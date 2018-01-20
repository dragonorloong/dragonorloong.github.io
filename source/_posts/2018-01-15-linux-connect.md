---
title: linux connect 过程
date: 2018-01-15 19:10:36
tags:
  - linux
  - tcp/ip

description: 本章主要说明connect函数的调用过程
---

# 函数调用栈
```cpp
sys_connect
    --> inet_stream_connect
        -->  inet_stream_connect
            --> tcp_v4_connect
                --> tcp_connect
                    --> tcp_transmit_skb
                        --> ip_queue_xmit

    --> inet_dgram_connect
        --> ip4_datagram_connect
```

# udp connect
udp connect在我看来最主要的作用是icmp可以报上来给应用层, 例如udp发包时，端口不可达，主机不可达，地址不可达等
当然，会在udp的hash中自动绑定五元组，后续可以直接调用send等函数发送
```cpp
int ip4_datagram_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
  struct inet_sock *inet = inet_sk(sk);
  struct sockaddr_in *usin = (struct sockaddr_in *) uaddr;
  struct rtable *rt;
  __be32 saddr;
  int oif;
  int err;


  if (addr_len < sizeof(*usin))
      return -EINVAL;

  if (usin->sin_family != AF_INET)
      return -EAFNOSUPPORT;

  sk_dst_reset(sk);

  oif = sk->sk_bound_dev_if;
  saddr = inet->saddr;
  if (MULTICAST(usin->sin_addr.s_addr)) {
    if (!oif)
      oif = inet->mc_index;
    if (!saddr)
      saddr = inet->mc_addr;
  }

  //查找路由
  err = ip_route_connect(&rt, usin->sin_addr.s_addr, saddr,
             RT_CONN_FLAGS(sk), oif,
             sk->sk_protocol,
             inet->sport, usin->sin_port, sk);
  if (err)
    return err;
  if ((rt->rt_flags & RTCF_BROADCAST) && !sock_flag(sk, SOCK_BROADCAST)) {
    ip_rt_put(rt);
    return -EACCES;
  }
    if (!inet->saddr)
      inet->saddr = rt->rt_src; /* Update source address */
  if (!inet->rcv_saddr)
    inet->rcv_saddr = rt->rt_src;
  inet->daddr = rt->rt_dst;
  inet->dport = usin->sin_port;

  //设置状态为连接状态
  sk->sk_state = TCP_ESTABLISHED;
  inet->id = jiffies;

  sk_dst_set(sk, &rt->u.dst);
  return(0);
}
```

udp 在收到icmp差错报文时，会调用udp_err函数处理, 整个流程如下所示：

```cpp
__inline__ void udp_err(struct sk_buff *skb, u32 info)
{
  return __udp4_lib_err(skb, info, udp_hash);
}

void __udp4_lib_err(struct sk_buff *skb, u32 info, struct hlist_head udptable[])
{
  //假如不处于连接状态，icmp不会上报到socket层
  if (!inet->recverr) {
    if (!harderr || sk->sk_state != TCP_ESTABLISHED)
      goto out;
  } else {
    ip_icmp_error(sk, skb, err, uh->dest, info, (u8*)(uh+1));
  }
  sk->sk_err = err;
  sk->sk_error_report(sk);
out:
  sock_put(sk);
}
```

# tcp connect

tcp的连接主要是tcp 属性的一些设定，包括窗口大小，窗口扩大因子，时间戳，序列号选取

```cpp
int inet_stream_connect(struct socket *sock, struct sockaddr *uaddr,
          int addr_len, int flags) {
  
  //发送syn包
  tcp_v4_connect()

  ...


  //假如是同步方式，会阻塞进程，等待发送超时时间
  timeo = sock_sndtimeo(sk, flags & O_NONBLOCK);

  if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) {
    /* Error code is set above */
    if (!timeo || !inet_wait_for_connect(sk, timeo))
      goto out;

    err = sock_intr_errno(timeo);
    if (signal_pending(current))
      goto out;
  }
}

int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len) {

  ...

  //查找路由
  tmp = ip_route_connect(&rt, nexthop, inet->saddr,
             RT_CONN_FLAGS(sk), sk->sk_bound_dev_if,
             IPPROTO_TCP,
             inet->sport, usin->sin_port, sk);

  ...

  //绑定本地端口，并且把sk链接到tcp_hashinfo的ESTABLISHED队列中
  tcp_set_state(sk, TCP_SYN_SENT);
  err = inet_hash_connect(&tcp_death_row, sk);

  ...

  //生成序号
  if (!tp->write_seq)
    tp->write_seq = secure_tcp_sequence_number(inet->saddr,
                 inet->daddr,
                 inet->sport,
                 usin->sin_port);

  inet->id = tp->write_seq ^ jiffies;

  err = tcp_connect(sk);
}

int tcp_connect(struct sock *sk) {
  //tcp 窗口大小，窗口扩大因子，mss， 初始序号设置
  tcp_connect_init(sk);

  //传输
  tcp_transmit_skb(sk, buff, 1, GFP_KERNEL);

  //syn包超时重传
  inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
          inet_csk(sk)->icsk_rto, TCP_RTO_MAX);
}
```

接收syn/ack， 并且发送ack, 函数调用栈
```cpp
tcp_v4_rcv
    --> tcp_v4_do_rcv
         --> tcp_rcv_state_process
              --> tcp_rcv_synsent_state_process
```

主要处理函数是tcp_rcv_synsent_state_process, 在其中保存对端的窗口大小mss等参数
```cpp
static int tcp_rcv_synsent_state_process(struct sock *sk, struct sk_buff *skb,
           struct tcphdr *th, unsigned len) {

  //解析选项
  tcp_parse_options(skb, &tp->rx_opt, 0);
   
  ......

  //设为连接状态
  tcp_set_state(sk, TCP_ESTABLISHED);

  //保活定时器
  //http://blog.csdn.net/zhangskd/article/details/44177475
  if (sock_flag(sk, SOCK_KEEPOPEN))
    inet_csk_reset_keepalive_timer(sk, keepalive_time_when(tp));

  if (!tp->rx_opt.snd_wscale)
    __tcp_fast_path_on(tp, tp->snd_wnd);
  else
    tp->pred_flags = 0;

  if (!sock_flag(sk, SOCK_DEAD)) {
    sk->sk_state_change(sk);
    sk_wake_async(sk, 0, POLL_OUT);
  }

  //假如有数据发送，设置了TCP_DEFER_ACCEPT标志，或者pingpong设置为1(延迟确认标志?)
  // 不会马上发送ack，使用延迟确认机制

  if (sk->sk_write_pending ||
      icsk->icsk_accept_queue.rskq_defer_accept ||
      icsk->icsk_ack.pingpong) {
    /* Save one ACK. Data will be ready after
     * several ticks, if write_pending is set.
     *
     * It may be deleted, but with this feature tcpdumps
     * look so _wonderfully_ clever, that I was not able
     * to stand against the temptation 8)     --ANK
     */
    inet_csk_schedule_ack(sk);
    icsk->icsk_ack.lrcvtime = tcp_time_stamp;
    icsk->icsk_ack.ato   = TCP_ATO_MIN;
    tcp_incr_quickack(sk);
    tcp_enter_quickack_mode(sk);
    inet_csk_reset_xmit_timer(sk, ICSK_TIME_DACK,
            TCP_DELACK_MAX, TCP_RTO_MAX);
  }

  ....

  tcp_send_ack(sk);

  ......

  //同时打开先不考虑
}
```

