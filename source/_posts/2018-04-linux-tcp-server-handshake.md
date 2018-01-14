---
title: linux tcp 服务端syn包接收
date: 2018-01-04 19:17:34
tags:
  - linux
  - tcp/ip

description: 本章主要说明tcp 服务端 syn/ack 的握手流程
---
# 主要函数调用栈
```cpp
tcp_v4_rcv
 ->tcp_v4_do_rcv
    ->tcp_rcv_state_process
       ->tcp_v4_conn_request
          ->tcp_v4_send_synack
```

本章只说明主要流程，具体的例如超时处理，time_wait等后面专门细化
收到syn包的处理流程大概是：
```
    1 检查包格式
    2 在hash表中查找listen sk
    3 创建连接请求块，链接到半连接队列
    4 构建syn/ack包，回包
    5 设置定时器，处理超时情况
```

# 详细流程
   
入口函数在之前协议簇初始化时，就已经注册了tcp协议对应的处理函数,
在ip层收到tcp包时，会调用tcp_v4_rcv处理

```cpp
static struct net_protocol tcp_protocol = {
  .handler =  tcp_v4_rcv,
  .err_handler =  tcp_v4_err,
  .gso_send_check = tcp_v4_gso_send_check,
  .gso_segment =  tcp_tso_segment,
  .no_policy =  1,
};

int tcp_v4_rcv(struct sk_buff *skb)
{
  struct tcphdr *th;
  struct sock *sk;
  int ret;

  //不是发往本地的包，丢弃
  if (skb->pkt_type != PACKET_HOST)
    goto discard_it;

  /* Count it even if it's bad */
  TCP_INC_STATS_BH(TCP_MIB_INSEGS);

  //拷贝标准tcp头部到线性缓冲区
  if (!pskb_may_pull(skb, sizeof(struct tcphdr)))
    goto discard_it;

  th = skb->h.th;

  //标准长度和doff字段比较
  if (th->doff < sizeof(struct tcphdr) / 4)
    goto bad_packet;

  //获取包括tcp选项的头部到线性缓冲区
  if (!pskb_may_pull(skb, th->doff * 4))
    goto discard_it;

  /* An explanation is required here, I think.
   * Packet length and doff are validated by header prediction,
   * provided case of th->doff==0 is eliminated.
   * So, we defer the checks. */

  //校验和相关
  if ((skb->ip_summed != CHECKSUM_UNNECESSARY &&
       tcp_v4_checksum_init(skb)))
    goto bad_packet;

  th = skb->h.th;
  TCP_SKB_CB(skb)->seq = ntohl(th->seq);
  //end_seq是首部的seq字段，加上数据长度
  TCP_SKB_CB(skb)->end_seq = (TCP_SKB_CB(skb)->seq + th->syn + th->fin +
            skb->len - th->doff * 4);

  //对端的确认号
  TCP_SKB_CB(skb)->ack_seq = ntohl(th->ack_seq);
  TCP_SKB_CB(skb)->when  = 0;
  TCP_SKB_CB(skb)->flags   = skb->nh.iph->tos;
  TCP_SKB_CB(skb)->sacked  = 0;

  //根据四元组到tcp_hashinfo中查找对应的sk
  //先在established中查找，然后到listener中查询
  sk = __inet_lookup(&tcp_hashinfo, skb->nh.iph->saddr, th->source,
         skb->nh.iph->daddr, th->dest,
         inet_iif(skb));

  if (!sk)
    goto no_tcp_socket;

process:
  if (sk->sk_state == TCP_TIME_WAIT)
    goto do_time_wait;

  if (!xfrm4_policy_check(sk, XFRM_POLICY_IN, skb))
    goto discard_and_relse;
  nf_reset(skb);

  if (sk_filter(sk, skb))
    goto discard_and_relse;

  skb->dev = NULL;

  bh_lock_sock_nested(sk);
  ret = 0;
  //判断有没有进程在处理当前sk，没有的话进入这个分支
  if (!sock_owned_by_user(sk)) {
  //dma没有了解
#ifdef CONFIG_NET_DMA
    struct tcp_sock *tp = tcp_sk(sk);
    if (!tp->ucopy.dma_chan && tp->ucopy.pinned_list)
      tp->ucopy.dma_chan = get_softnet_dma();
    if (tp->ucopy.dma_chan)
      ret = tcp_v4_do_rcv(sk, skb);
    else
#endif
    {
      //http://blog.csdn.net/dog250/article/details/5464513 讲prequeue存在的理由
      if (!tcp_prequeue(sk, skb))
      ret = tcp_v4_do_rcv(sk, skb);
    }
  } else
  //有进程在处理当前sk，插入报文到backlog
    sk_add_backlog(sk, skb);
  bh_unlock_sock(sk);

  sock_put(sk);

  return ret;

no_tcp_socket:
  if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb))
    goto discard_it;

  if (skb->len < (th->doff << 2) || tcp_checksum_complete(skb)) {
bad_packet:
    TCP_INC_STATS_BH(TCP_MIB_INERRS);
  } else {
    //发送reset包
    tcp_v4_send_reset(NULL, skb);
  }

discard_it:
  /* Discard frame. */
  kfree_skb(skb);
    return 0;

discard_and_relse:
  sock_put(sk);
  goto discard_it;

do_time_wait:
  if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
    inet_twsk_put(inet_twsk(sk));
    goto discard_it;
  }

  if (skb->len < (th->doff << 2) || tcp_checksum_complete(skb)) {
    TCP_INC_STATS_BH(TCP_MIB_INERRS);
    inet_twsk_put(inet_twsk(sk));
    goto discard_it;
  }
  switch (tcp_timewait_state_process(inet_twsk(sk), skb, th)) {
  case TCP_TW_SYN: {
    struct sock *sk2 = inet_lookup_listener(&tcp_hashinfo,
              skb->nh.iph->daddr,
              th->dest,
              inet_iif(skb));
    if (sk2) {
      inet_twsk_deschedule(inet_twsk(sk), &tcp_death_row);
      inet_twsk_put(inet_twsk(sk));
      sk = sk2;
      goto process;
    }
    /* Fall through to ACK */
  }
  case TCP_TW_ACK:
    tcp_v4_timewait_ack(sk, skb);
    break;
  case TCP_TW_RST:
    goto no_tcp_socket;
  case TCP_TW_SUCCESS:;
  }
  goto discard_it;
}

假如不是放到prequeue中， 回调用tcp_v4_do_rcv函数处理

int tcp_v4_do_rcv(struct sock *sk, struct sk_buff *skb)
{
  struct sock *rsk;
#ifdef CONFIG_TCP_MD5SIG
  /*
   * We really want to reject the packet as early as possible
   * if:
   *  o We're expecting an MD5'd packet and this is no MD5 tcp option
   *  o There is an MD5 option and we're not expecting one
   */
  if (tcp_v4_inbound_md5_hash(sk, skb))
    goto discard;
#endif

  if (sk->sk_state == TCP_ESTABLISHED) { /* Fast path */
    TCP_CHECK_TIMER(sk);
    if (tcp_rcv_established(sk, skb, skb->h.th, skb->len)) {
      rsk = sk;
      goto reset;
    }
    TCP_CHECK_TIMER(sk);
    return 0;
  }

  //计算检验和
  if (skb->len < (skb->h.th->doff << 2) || tcp_checksum_complete(skb))
    goto csum_err;

  //处于TCP_LISTEN状态的sk，进入这个分支
  if (sk->sk_state == TCP_LISTEN) {
    //第一次请求，在半连接队列中找不到对应的sock, 返回sk本身
    struct sock *nsk = tcp_v4_hnd_req(sk, skb);
    if (!nsk)
      goto discard;

    if (nsk != sk) {
      if (tcp_child_process(sk, nsk, skb)) {
        rsk = nsk;
        goto reset;
      }
      return 0;
    }
  }

  TCP_CHECK_TIMER(sk);
  //进去这个分支
  if (tcp_rcv_state_process(sk, skb, skb->h.th, skb->len)) {
    rsk = sk;
    goto reset;
  }
  TCP_CHECK_TIMER(sk);
  return 0;

reset:
  tcp_v4_send_reset(rsk, skb);
discard:
  kfree_skb(skb);
  /* Be careful here. If this function gets more complicated and
   * gcc suffers from register pressure on the x86, sk (in %ebx)
   * might be destroyed here. This current version compiles correctly,
   * but you have been warned.
   */
  return 0;

csum_err:
  TCP_INC_STATS_BH(TCP_MIB_INERRS);
  goto discard;
}


处理tcp半连接状态的请求
int tcp_rcv_state_process(struct sock *sk, struct sk_buff *skb,
        struct tcphdr *th, unsigned len)
{
  struct tcp_sock *tp = tcp_sk(sk);
  struct inet_connection_sock *icsk = inet_csk(sk);
  int queued = 0;

  tp->rx_opt.saw_tstamp = 0;

  switch (sk->sk_state) {
  case TCP_CLOSE:
    goto discard;

  case TCP_LISTEN:
    if(th->ack)
      return 1;

    if(th->rst)
      goto discard;

    if(th->syn) {
      if (icsk->icsk_af_ops->conn_request(sk, skb) < 0)
        return 1;

      return 0;
    }
    goto discard;

  ....
}

int tcp_v4_conn_request(struct sock *sk, struct sk_buff *skb)
{
  struct inet_request_sock *ireq;
  struct tcp_options_received tmp_opt;
  struct request_sock *req;
  __be32 saddr = skb->nh.iph->saddr;
  __be32 daddr = skb->nh.iph->daddr;
  __u32 isn = TCP_SKB_CB(skb)->when;
  struct dst_entry *dst = NULL;
#ifdef CONFIG_SYN_COOKIES
  int want_cookie = 0;
#else
#define want_cookie 0 /* Argh, why doesn't gcc optimize this :( */
#endif

  /* Never answer to SYNs send to broadcast or multicast */
  //丢弃广播，多播包
  if (((struct rtable *)skb->dst)->rt_flags &
      (RTCF_BROADCAST | RTCF_MULTICAST))
    goto drop;

  /* TW buckets are converted to open requests without
   * limitations, they conserve resources and peer is
   * evidently real one.
   */
  //半连接队列满了，丢弃
  if (inet_csk_reqsk_queue_is_full(sk) && !isn) {
    //除非使用syn cookies
#ifdef CONFIG_SYN_COOKIES
    if (sysctl_tcp_syncookies) {
      want_cookie = 1;
    } else
#endif
    goto drop;
  }

  //全连接队列已经满了， 并且半连接数量大于1, 丢弃报文
  if (sk_acceptq_is_full(sk) && inet_csk_reqsk_queue_young(sk) > 1)
    goto drop;

  //分配inet_request_sock数据结构
  req = reqsk_alloc(&tcp_request_sock_ops);
  if (!req)
    goto drop;

#ifdef CONFIG_TCP_MD5SIG
  tcp_rsk(req)->af_specific = &tcp_request_sock_ipv4_ops;
#endif

  tcp_clear_options(&tmp_opt);
  tmp_opt.mss_clamp = 536;
  tmp_opt.user_mss  = tcp_sk(sk)->rx_opt.user_mss;

  //tcp 选项处理
  tcp_parse_options(skb, &tmp_opt, 0);

  if (want_cookie) {
    tcp_clear_options(&tmp_opt);
    tmp_opt.saw_tstamp = 0;
  }

  if (tmp_opt.saw_tstamp && !tmp_opt.rcv_tsval) {
    /* Some OSes (unknown ones, but I see them on web server, which
     * contains information interesting only for windows'
     * users) do not send their stamp in SYN. It is easy case.
     * We simply do not advertise TS support.
     */
    tmp_opt.saw_tstamp = 0;
    tmp_opt.tstamp_ok  = 0;
  }
  tmp_opt.tstamp_ok = tmp_opt.saw_tstamp;

  tcp_openreq_init(req, &tmp_opt, skb);

  if (security_inet_conn_request(sk, skb, req))
    goto drop_and_free;

  ireq = inet_rsk(req);
  ireq->loc_addr = daddr;
  ireq->rmt_addr = saddr;
  ireq->opt = tcp_v4_save_options(sk, skb);
  if (!want_cookie)
    TCP_ECN_create_request(req, skb->h.th);

  if (want_cookie) {
#ifdef CONFIG_SYN_COOKIES
    syn_flood_warning(skb);
#endif
    isn = cookie_v4_init_sequence(sk, skb, &req->mss);
  } else if (!isn) {
    struct inet_peer *peer = NULL;

    /* VJ's idea. We save last timestamp seen
     * from the destination in peer table, when entering
     * state TIME-WAIT, and check against it before
     * accepting new connection request.
     *
     * If "isn" is not zero, this request hit alive
     * timewait bucket, so that all the necessary checks
     * are made in the function processing timewait state.
     */
    if (tmp_opt.saw_tstamp &&
        tcp_death_row.sysctl_tw_recycle &&
        (dst = inet_csk_route_req(sk, req)) != NULL &&
        (peer = rt_get_peer((struct rtable *)dst)) != NULL &&
        peer->v4daddr == saddr) {
      if (xtime.tv_sec < peer->tcp_ts_stamp + TCP_PAWS_MSL &&
          (s32)(peer->tcp_ts - req->ts_recent) >
              TCP_PAWS_WINDOW) {
        NET_INC_STATS_BH(LINUX_MIB_PAWSPASSIVEREJECTED);
        dst_release(dst);
        goto drop_and_free;
      }
    }
    /* Kill the following clause, if you dislike this way. */
    else if (!sysctl_tcp_syncookies &&
       (sysctl_max_syn_backlog - inet_csk_reqsk_queue_len(sk) <
        (sysctl_max_syn_backlog >> 2)) &&
       (!peer || !peer->tcp_ts_stamp) &&
       (!dst || !dst_metric(dst, RTAX_RTT))) {
      /* Without syncookies last quarter of
       * backlog is filled with destinations,
       * proven to be alive.
       * It means that we continue to communicate
       * to destinations, already remembered
       * to the moment of synflood.
       */
      LIMIT_NETDEBUG(KERN_DEBUG "TCP: drop open "
               "request from %u.%u.%u.%u/%u\n",
               NIPQUAD(saddr),
               ntohs(skb->h.th->source));
      dst_release(dst);
      goto drop_and_free;
    }

    isn = tcp_v4_init_sequence(skb);

  }
  
  //发送序号
  tcp_rsk(req)->snt_isn = isn;

  //发送syn ack包
  if (tcp_v4_send_synack(sk, req, dst))
    goto drop_and_free;

  if (want_cookie) {
      reqsk_free(req);
  } else {
    //非cookie模式，添加req 到半连接队列，并且设置超时时间, TCP_TIMEOUT_INIT是3s， 
    //3s重传一次，总共5次，这就是syn 攻击的一个原理
    inet_csk_reqsk_queue_hash_add(sk, req, TCP_TIMEOUT_INIT);
  }
  return 0;

drop_and_free:
  reqsk_free(req);
drop:
  return 0;
}

static int tcp_v4_send_synack(struct sock *sk, struct request_sock *req,
            struct dst_entry *dst)
{
  const struct inet_request_sock *ireq = inet_rsk(req);
  int err = -1;
  struct sk_buff * skb;

  /* First, grab a route. */
  if (!dst && (dst = inet_csk_route_req(sk, req)) == NULL)
    goto out;

  //创建synack包
  skb = tcp_make_synack(sk, dst, req);

  if (skb) {
    struct tcphdr *th = skb->h.th;

    th->check = tcp_v4_check(th, skb->len,
           ireq->loc_addr,
           ireq->rmt_addr,
           csum_partial((char *)th, skb->len,
                  skb->csum));

    err = ip_build_and_send_pkt(skb, sk, ireq->loc_addr,
              ireq->rmt_addr,
              ireq->opt);
    err = net_xmit_eval(err);
  }

out:
  dst_release(dst);
  return err;
}

struct sk_buff * tcp_make_synack(struct sock *sk, struct dst_entry *dst,
         struct request_sock *req) {
   //滑动窗口大小选择
   //http://blog.csdn.net/zhangskd/article/details/8588202
   tcp_select_initial_window(tcp_full_space(sk),
      dst_metric(dst, RTAX_ADVMSS) - (ireq->tstamp_ok ? TCPOLEN_TSTAMP_ALIGNED : 0),
      &req->rcv_wnd,
      &req->window_clamp,
      ireq->wscale_ok,
      &rcv_wscale);

}

```


