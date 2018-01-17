---
title: linux udp 数据接收和发送过程 
date: 2018-01-02 19:22:51
tags:
  - linux
  - tcp/ip

description: 本章主要说明udp的数据发送和接收过程
---
# 数据发送
```cpp
//系统调用最后进入sys_sendto函数
asmlinkage long sys_sendto(int fd, void __user *buff, size_t len,
         unsigned flags, struct sockaddr __user *addr,
         int addr_len)
{
  struct socket *sock;
  char address[MAX_SOCK_ADDR];
  int err;
  struct msghdr msg;
  struct iovec iov;
  int fput_needed;
  struct file *sock_file;

  //增加socket引用计数
  sock_file = fget_light(fd, &fput_needed);
  if (!sock_file)
    return -EBADF;

  //根据fd获取sock结构体
  sock = sock_from_file(sock_file, &err);
  if (!sock)
    goto out_put;
  iov.iov_base = buff;
  iov.iov_len = len;
  msg.msg_name = NULL;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_namelen = 0;
  if (addr) {
    err = move_addr_to_kernel(addr, addr_len, address);
    if (err < 0)
      goto out_put;
    msg.msg_name = address;
    msg.msg_namelen = addr_len;
  }
  if (sock->file->f_flags & O_NONBLOCK)
    flags |= MSG_DONTWAIT;
  msg.msg_flags = flags;
  err = sock_sendmsg(sock, &msg, len);

out_put:
  fput_light(sock_file, fput_needed);
  return err;
}

int sock_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{
  struct kiocb iocb;
  struct sock_iocb siocb;
  int ret;

  init_sync_kiocb(&iocb, NULL);
  iocb.private = &siocb;
  ret = __sock_sendmsg(&iocb, sock, msg, size);
  if (-EIOCBQUEUED == ret)
    ret = wait_on_sync_kiocb(&iocb);
  return ret;
}

static inline int __sock_sendmsg(struct kiocb *iocb, struct socket *sock,
         struct msghdr *msg, size_t size)
{
  struct sock_iocb *si = kiocb_to_siocb(iocb);
  int err;

  si->sock = sock;
  si->scm = NULL;
  si->msg = msg;
  si->size = size;

  err = security_socket_sendmsg(sock, msg, size);
  if (err)
    return err;

  //调用inet_sendmsg
  return sock->ops->sendmsg(iocb, sock, msg, size);
}

int inet_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg,
     size_t size)
{
  struct sock *sk = sock->sk;

  //自动绑定端口
  /* We may need to bind the socket. */
  if (!inet_sk(sk)->num && inet_autobind(sk))
    return -EAGAIN;

  //调用udp_send_msg
  return sk->sk_prot->sendmsg(iocb, sk, msg, size);
}
```

注释1：
  该函数分为设置flag为MSG_MORE, 则只会把数据放到sock的write_queue中，假如是第一个数据包
  则会额外添加udp的长度，后续的收据包直接append到skb后面，假如没有设置MSG_MORE标识，则直接
  会调用udp_push_pending_frames函数，发送数据。这个函数会添加udp的头部
  在分配内存的时候，是由ip层回调传进去的getfrag, 最后会调用sock_alloc_send_pskb函数

注释2:
  udp 调用connect， 会在inet_sock的设置daddr和dport，并且把sk_state 设置为TCP_ESTABLISHED

```cpp
int udp_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
    size_t len) {
}

static struct sk_buff *sock_alloc_send_pskb(struct sock *sk,
              unsigned long header_len,
              unsigned long data_len,
              int noblock, int *errcode) {
  //判断已经分配的数据是否大于sndbuf
  if (atomic_read(&sk->sk_wmem_alloc) < sk->sk_sndbuf) {
    //假如内存足够，会分配下面这个函数，并且会增加sk_wmem_alloc的大小
    static inline void skb_set_owner_w(struct sk_buff *skb, struct sock *sk)                                                                                     
    {                                                                                                                                                            
      skb->sk = sk;                                                                                                                                              
      //sock_wfree函数，会减少sk_wmem_alloc的大小， 分配的skb最后要到被软中断来释放，所以，
      //udp的send buf表示在协议栈中的所有数据的总和，包括qos排队，网卡队列等
      skb->destructor = sock_rfree;
      atomic_add(skb->truesize, &sk->sk_wmem_alloc);
    }   
  }
}
```

# 数据接收
## 内核自动接收
```cpp
ip层接收完数据以后，根据四层协议类型，调用udp_rcv函数
__inline__ int udp_rcv(struct sk_buff *skb)
{
  return __udp4_lib_rcv(skb, udp_hash, 0);
}

int __udp4_lib_rcv(struct sk_buff *skb, struct hlist_head udptable[],
       int is_udplite)
{
  //从udptable中找出目的端口对应的sock
  sk = __udp4_lib_lookup(saddr, uh->source, daddr, uh->dest,
             skb->dev->ifindex, udptable        );

  if (sk != NULL) {
    int ret = udp_queue_rcv_skb(sk, skb);
    sock_put(sk);

    /* a return value > 0 means to resubmit the input, but
     * it wants the return to be -protocol, or 0
     */
    if (ret > 0)
      return -ret;
    return 0;
  }

  if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb))
    goto drop;
  nf_reset(skb);

  /* No socket. Drop packet silently, if checksum is wrong */
  if (udp_lib_checksum_complete(skb))
    goto csum_error;

  //假如sock不存在，则需要发送icmp
  UDP_INC_STATS_BH(UDP_MIB_NOPORTS, is_udplite);
  icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);

  /*
   * Hmm.  We got an UDP packet to a port to which we
   * don't wanna listen.  Ignore it.
   */
  kfree_skb(skb);
  return(0);
}

//校验和等检查通过以后，最后调用下面函数，把skb添加到skb_receive_queue队列中
int sock_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
  int err = 0;
  int skb_len;

  /* Cast skb->rcvbuf to unsigned... It's pointless, but reduces
     number of warnings when compiling with -W --ANK
   */

  //判断排队的数据有没有超过rcvbuf参数
  if (atomic_read(&sk->sk_rmem_alloc) + skb->truesize >=
      (unsigned)sk->sk_rcvbuf) {
    err = -ENOMEM;
    goto out;
  }

  err = sk_filter(sk, skb);
  if (err)
    goto out;

  skb->dev = NULL;
  skb_set_owner_r(skb, sk);

  /* Cache the SKB length before we tack it onto the receive
   * queue.  Once it is added it no longer belongs to us and
   * may be freed by other threads of control pulling packets
   * from the queue.
   */
  skb_len = skb->len;

  skb_queue_tail(&sk->sk_receive_queue, skb);

  if (!sock_flag(sk, SOCK_DEAD))
    sk->sk_data_ready(sk, skb_len);
out:
  return err;
}
```

## 用户调用recvfrom函数
```
调用sys_recvfrom函数->sock_common_recvmsg->udp_rcvmsg 然后从receive_queue队列中获取数据，
没有数据的话，会等待，直到超时或者非阻塞直接返回, 假如用户传进去的缓冲区过小，数据包会截断
```
