---
title: linux tcp 服务端ack接收 
date: 2018-01-10 20:10:30
tags:
  - linux
  - tcp/ip


description: 本章主要说明tcp 服务端接收最后一个ack的流程
---
# 整体流程
根据上一篇的描述，已经知道的是，接收一个syn，响应ack，并且发送syn包给client
这时候，会创建一个request_sock对象，保存在listen sock的半连接队列中，理所当然,
在收到最后一个ack时，大概流程如下：

```
1 查找半连接状态的request_sock对象
2 检查ack的有效性，包括时间戳，seq，确认seq等
3 分配sock对象，并且移到全连接队列，等待accept获取
```

至于函数的调用栈，基本和上一章差不多

# 代码说明
```cpp
struct sock *tcp_check_req(struct sock *sk,struct sk_buff *skb,
         struct request_sock *req,
         struct request_sock **prev)
{
  struct tcphdr *th = skb->h.th;
  __be32 flg = tcp_flag_word(th) & (TCP_FLAG_RST|TCP_FLAG_SYN|TCP_FLAG_ACK);
  int paws_reject = 0;
  struct tcp_options_received tmp_opt;
  struct sock *child;

  tmp_opt.saw_tstamp = 0;
  //解析tcp选项
  if (th->doff > (sizeof(struct tcphdr)>>2)) {
    tcp_parse_options(skb, &tmp_opt, 0);

    if (tmp_opt.saw_tstamp) {
      tmp_opt.ts_recent = req->ts_recent;
      tmp_opt.ts_recent_stamp = xtime.tv_sec - ((TCP_TIMEOUT_INIT/HZ)<<req->retrans);
      paws_reject = tcp_paws_check(&tmp_opt, th->rst);
    }
  }

  //序号相同，认为是重传的syn包，继续发送ack过去
  if (TCP_SKB_CB(skb)->seq == tcp_rsk(req)->rcv_isn &&
      flg == TCP_FLAG_SYN &&
      !paws_reject) {
    req->rsk_ops->rtx_syn_ack(sk, req, NULL);
    return NULL;
  }

  //假如有ack标志，但是确认序号不同，直接返回，到外面发送reset包
  if ((flg & TCP_FLAG_ACK) &&
      (TCP_SKB_CB(skb)->ack_seq != tcp_rsk(req)->snt_isn + 1))
    return sk;

  /* RFC793: "first check sequence number". */

  //时间戳回绕，或者序号不再接收窗口内，不是reset包的话，发送ack，并且删除当前sk
  if (paws_reject || !tcp_in_window(TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq,
            tcp_rsk(req)->rcv_isn + 1, tcp_rsk(req)->rcv_isn + 1 + req->rcv_wnd)) {
    /* Out of window: send ACK and drop. */
    if (!(flg & TCP_FLAG_RST))
      req->rsk_ops->send_ack(skb, req);
    if (paws_reject)
      NET_INC_STATS_BH(LINUX_MIB_PAWSESTABREJECTED);
    return NULL;
  }

  /* In sequence, PAWS is OK. */

  //假如包合法，记录接收包的对端时间
  if (tmp_opt.saw_tstamp && !after(TCP_SKB_CB(skb)->seq, tcp_rsk(req)->rcv_isn + 1))
      req->ts_recent = tmp_opt.rcv_tsval;

    if (TCP_SKB_CB(skb)->seq == tcp_rsk(req)->rcv_isn) {
      /* Truncate SYN, it is out of window starting
         at tcp_rsk(req)->rcv_isn + 1. */
      flg &= ~TCP_FLAG_SYN;
    }


    if (flg & (TCP_FLAG_RST|TCP_FLAG_SYN)) {
      TCP_INC_STATS_BH(TCP_MIB_ATTEMPTFAILS);
      goto embryonic_reset;
    }

    /* ACK sequence verified above, just make sure ACK is
     * set.  If ACK not set, just silently drop the packet.
     */
    if (!(flg & TCP_FLAG_ACK))
      return NULL;

    //设置了TCP_DEFER_ACCEPT, 并且里面没有数据的话，直接返回，不予理睬
    /* If TCP_DEFER_ACCEPT is set, drop bare ACK. */
    if (inet_csk(sk)->icsk_accept_queue.rskq_defer_accept &&
        TCP_SKB_CB(skb)->end_seq == tcp_rsk(req)->rcv_isn + 1) {
      inet_rsk(req)->acked = 1;
      return NULL;
    }

    //创建sock结构体，获取路由缓存，并且设置
    child = inet_csk(sk)->icsk_af_ops->syn_recv_sock(sk, skb,
                 req, NULL);
    if (child == NULL)
      goto listen_overflow;
#ifdef CONFIG_TCP_MD5SIG
    else {
      /* Copy over the MD5 key from the original socket */
      struct tcp_md5sig_key *key;
      struct tcp_sock *tp = tcp_sk(sk);
      key = tp->af_specific->md5_lookup(sk, child);
      if (key != NULL) {
        /*
         * We're using one, so create a matching key on the
         * newsk structure. If we fail to get memory then we
         * end up not copying the key across. Shucks.
         */
        char *newkey = kmemdup(key->key, key->keylen,
                   GFP_ATOMIC);
        if (newkey) {
          if (!tcp_alloc_md5sig_pool())
            BUG();
          tp->af_specific->md5_add(child, child,
                 newkey,
                 key->keylen);
        }
      }
   }
#endif

    inet_csk_reqsk_queue_unlink(sk, req, prev);
    inet_csk_reqsk_queue_removed(sk, req);

    //把request_sock链接到完全连接队列
    inet_csk_reqsk_queue_add(sk, req, child);
    return child;

  listen_overflow:
    if (!sysctl_tcp_abort_on_overflow) {
      inet_rsk(req)->acked = 1;
      return NULL;
    }

  embryonic_reset:
    NET_INC_STATS_BH(LINUX_MIB_EMBRYONICRSTS);
    if (!(flg & TCP_FLAG_RST))
      req->rsk_ops->send_reset(sk, skb);

    inet_csk_reqsk_queue_drop(sk, req, prev);
    return NULL;
}
```

# tcp 选项
1 窗口大小/窗口扩大因子
窗口大小就是众所周知的滑动窗口大小，与之相关的因素有用户设置接收缓存大小， 窗口16位表示的
限制上限，mss大小等，首先窗口大小必须能用16位大小表示(不考虑窗口扩大因子)，其次窗口大小要
小于用户设置的最大接收缓存大小；还有就是必须是mss的整数倍。
窗口扩大因子是指在需要指定的窗口大小大于2的16次方时，窗口大小的2的n次方倍，就是真正的窗口大小。这个参数用来扩大滑动窗口大小。

2 mss
mss是指tcp最大允许发送的数据包长度，这个是MTU-TCP首部-IP首部得到的结果，从路由中取得

3 时间戳
时间戳会在包发送时，指定一个时间戳，然后对端在回复这个包时候，带上这个时间戳，发送端根据系统现在时间，和接收包的时间戳，来做两件事情：
3.1 rtt计算，这样能够很精确的计算一个包的往返时间
3.2 paws机制，接收端在收到一个包时，会记录这个包的里面的时间戳，假如收到两个包，序列号一样，则会丢弃时间戳与最后时间戳相差距离比较大的那个包
