---
title: socket bind过程
date: 2017-12-24 20:20:33
tags:
    - linux
    - tcp/ip

description: 本章主要说明bind系统调用的流程
---

```cpp
asmlinkage long sys_bind(int fd, struct sockaddr __user *umyaddr, int addrlen)
{
    struct socket *sock;
    char address[MAX_SOCK_ADDR];
    int err, fput_needed;

    //根据fd取出file，然后从file中取出privatedata,对应socket
    if((sock = sockfd_lookup_light(fd, &err, &fput_needed))!=NULL)
    {    
        //把参数从用户态拷贝到内核态
        if((err=move_addr_to_kernel(umyaddr,addrlen,address))>=0) {
            err = security_socket_bind(sock, (struct sockaddr *)address, addrlen);
            if (!err)
                //调用协议相关的bind函数
                //对于tcp和udp来说都是调用inet_bind
                err = sock->ops->bind(sock,
                    (struct sockaddr *)address, addrlen);
        }
        fput_light(sock->file, fput_needed);
    }                
    return err; 
}

//socket状态

typedef enum {  
    SS_FREE = 0,            //该socket还未分配  
    SS_UNCONNECTED,         //未连向任何socket  
    SS_CONNECTING,          //正在连接过程中  
    SS_CONNECTED,           //已连向一个socket  
    SS_DISCONNECTING        //正在断开连接的过程中  
}socket_state;  

//sock状态
enum {  
   TCP_ESTABLISHED = 1,  
   TCP_SYN_SENT,  
   TCP_SYN_RECV,  
   TCP_FIN_WAIT1,  
   TCP_FIN_WAIT2,  
   TCP_TIME_WAIT,  
   TCP_CLOSE,  
   TCP_CLOSE_WAIT,  
   TCP_LAST_ACK,  
   TCP_LISTEN,  
   TCP_CLOSING，  
  
   TCP_MAX_STATES  
}


int inet_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len) {
 //sysctl_ip_nonlocal_bind, 系统级别设置，这个套接字是否支持绑定非本地ip地址
 //freebind socket级别设置，套接字是否支持绑定非本地ip地址

 if (!sysctl_ip_nonlocal_bind &&
      !inet->freebind &&
      addr->sin_addr.s_addr != INADDR_ANY &&
      chk_addr_ret != RTN_MULTICAST &&
      chk_addr_ret != RTN_BROADCAST)
    goto out; 


  //对于tcp，会调用inet_csk_get_port
  //对于每一个bind的端口，会存储在tcp_hashinfo中
  //新版本的内核支持S_REUSEPORT接口
  //对于udp来说，调用__udp_lib_get_port函数
  if (sk->sk_prot->get_port(sk, snum)) {
  inet_csk_get_port(struct inet_hashinfo *hashinfo,
          struct sock *sk, unsigned short snum,
          int (*bind_conflict)(const struct sock *sk,
             const struct inet_bind_bucket *tb))

}
```

accept 系统调用被阻塞时，会调用
```
inet_csk_wait_for_connect
  // 设置这个标志
  --> prepare_to_wait_exclusive
    --> wait->flags |= WQ_FLAG_EXCLUSIVE;  

//唤醒操作:
__wake_up_common
    if (curr->func(curr, mode, wake_flags, key) &&
        (flags & WQ_FLAG_EXCLUSIVE) && !--nr_exclusive)
      //只调用一次就break
      break;

epoll 惊群已经全部解决
fork之前的epoll_create默认解决, 边缘触发扩展解决, 水平触发没有解决
fork之后的epoll_create 通过设置标志解决,EPOLLEXCLUSIVE
```
