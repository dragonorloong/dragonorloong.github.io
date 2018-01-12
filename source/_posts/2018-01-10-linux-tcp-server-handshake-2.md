---
title: 2018-01-10-linux-tcp-server-handshake-2
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
2 检查ack的有效性，包括事件戳，seq，确认seq等
3 分配sock对象，并且移到全连接队列，等待accept获取
```

至于函数的调用栈，基本和上一章差不多

#代码说明
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
 if ((flg & TCP_FLAG_ACK) &&
      (TCP_SKB_CB(skb)->ack_seq != tcp_rsk(req)->snt_isn + 1))
    return sk;

  /* Also, it would be not so bad idea to check rcv_tsecr, which
   * is essentially ACK extension and too early or too late values
   * should cause reset in unsynchronized states.
   */

  /* RFC793: "first check sequence number". */

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

  if (tmp_opt.saw_tstamp && !after(TCP_SKB_CB(skb)->seq, tcp_rsk(req)->rcv_isn + 1))
      req->ts_recent = tmp_opt.rcv_tsval;

    if (TCP_SKB_CB(skb)->seq == tcp_rsk(req)->rcv_isn) {
      /* Truncate SYN, it is out of window starting
         at tcp_rsk(req)->rcv_isn + 1. */
      flg &= ~TCP_FLAG_SYN;
    }

    /* RFC793: "second check the RST bit" and
     *     "fourth, check the SYN bit"
     */
    if (flg & (TCP_FLAG_RST|TCP_FLAG_SYN)) {
      TCP_INC_STATS_BH(TCP_MIB_ATTEMPTFAILS);
      goto embryonic_reset;
    }

    /* ACK sequence verified above, just make sure ACK is
     * set.  If ACK not set, just silently drop the packet.
     */
    if (!(flg & TCP_FLAG_ACK))
      return NULL;

    /* If TCP_DEFER_ACCEPT is set, drop bare ACK. */
    if (inet_csk(sk)->icsk_accept_queue.rskq_defer_accept &&
        TCP_SKB_CB(skb)->end_seq == tcp_rsk(req)->rcv_isn + 1) {
      inet_rsk(req)->acked = 1;
      return NULL;
    }

    /* OK, ACK is valid, create big socket and
     * feed this segment to it. It will repeat all
     * the tests. THIS SEGMENT MUST MOVE SOCKET TO
     * ESTABLISHED STATE. If it will be dropped after
     * socket is created, wait for troubles.
     */
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
