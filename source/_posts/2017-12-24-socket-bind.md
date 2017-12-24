---
title: 2017-12-24-socket-bind
date: 2017-12-24 20:20:33
tags:
    - linux
    - tcp/ip

description: 本章主要说明bind系统调用的流程
---

```
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
```
