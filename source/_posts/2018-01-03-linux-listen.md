---
title: linux listen 过程
date: 2018-01-03 19:16:04
tags:
  - linux
  - tcp/ip

description: 本章主要说明listen系统调用过程
---
```
//系统调用入口
asmlinkage long sys_listen(int fd, int backlog)
{
  struct socket *sock;
  int err, fput_needed;

  sock = sockfd_lookup_light(fd, &err, &fput_needed);
  if (sock) {
    //全连接状态的长度，不能超过系统变量somaxconn
    if ((unsigned)backlog > sysctl_somaxconn)
      backlog = sysctl_somaxconn;

    err = security_socket_listen(sock, backlog);
    if (!err)
      //调用inet_listen
      err = sock->ops->listen(sock, backlog);

    fput_light(sock->file, fput_needed);
  }
  return err;
}

int inet_listen(struct socket *sock, int backlog)
{
  struct sock *sk = sock->sk;
  unsigned char old_state;
  int err;

  lock_sock(sk);

  err = -EINVAL;
  if (sock->state != SS_UNCONNECTED || sock->type != SOCK_STREAM)
    goto out;

  old_state = sk->sk_state;
  if (!((1 << old_state) & (TCPF_CLOSE | TCPF_LISTEN)))
    goto out;

  /* Really, if the socket is already in listen state
   * we can only allow the backlog to be adjusted.
   */
  if (old_state != TCP_LISTEN) {
    err = inet_csk_listen_start(sk, backlog);
    if (err)
      goto out;
  }

  //该参数后续验证, 全连接状态队列的长度
  sk->sk_max_ack_backlog = backlog;
  err = 0;

out:
  release_sock(sk);
  return err;
}

int inet_csk_listen_start(struct sock *sk, const int nr_table_entries)
{
  struct inet_sock *inet = inet_sk(sk);
  struct inet_connection_sock *icsk = inet_csk(sk);
  //创建半连接状态队列, 长度是backlog或者
  //系统参数tcp_max_syn_backlog长度的最接近2的倍数的数，最小值是8
  int rc = reqsk_queue_alloc(&icsk->icsk_accept_queue, nr_table_entries);

  if (rc != 0)
    return rc;

  sk->sk_max_ack_backlog = 0;
  sk->sk_ack_backlog = 0;
  inet_csk_delack_init(sk);

  /* There is race window here: we announce ourselves listening,
   * but this transition is still not validated by get_port().
   * It is OK, because this socket enters to hash table only
   * after validation is complete.
   */
  sk->sk_state = TCP_LISTEN;
  //检验port有没有用
  if (!sk->sk_prot->get_port(sk, inet->num)) {
    inet->sport = htons(inet->num);

    sk_dst_reset(sk);
    //调用tcp_v4_hash函数
    sk->sk_prot->hash(sk);

    return 0;
  }

  sk->sk_state = TCP_CLOSE;
  __reqsk_queue_destroy(&icsk->icsk_accept_queue);
  return -EADDRINUSE;
}

tcp_v4_hash
   inet_hash
    static inline void __inet_hash(struct inet_hashinfo *hashinfo,
                 struct sock *sk, const int listen_possible)
    {
      struct hlist_head *list;
      rwlock_t *lock;

      BUG_TRAP(sk_unhashed(sk));
      //对于监听状态的sk，绑定到tcp_hashinfo的listening_hash队列中
      if (listen_possible && sk->sk_state == TCP_LISTEN) {
        list = &hashinfo->listening_hash[inet_sk_listen_hashfn(sk)];
        lock = &hashinfo->lhash_lock;
        inet_listen_wlock(hashinfo);
      } else {
        struct inet_ehash_bucket *head;
        sk->sk_hash = inet_sk_ehashfn(sk);
        head = inet_ehash_bucket(hashinfo, sk->sk_hash);
        list = &head->chain;
        lock = &head->lock;
        write_lock(lock);
      }
      __sk_add_node(sk, list);
      sock_prot_inc_use(sk->sk_prot);
      write_unlock(lock);
      if (listen_possible && sk->sk_state == TCP_LISTEN)
        wake_up(&hashinfo->lhash_wait);
    }

```
