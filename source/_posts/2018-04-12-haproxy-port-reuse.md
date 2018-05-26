---
type: "tags"
layout: "tags"
title: Haproxy 端口复用
date: 2018-04-12 15:45:20
category: Haprxoy
tags:
    - Haproxy
    - 负载均衡

description: 本章主要说明haproxy的惊群和socket的REUSEPORT和REUSEADDR选项
---
# 端口地址复用

最近使用haproxy的时候，发现一个问题，当连接后端的socket内核自动绑定使用了一个端口，
然后再使用这个端口去监听时，会报错。跟踪代码发现，连接，连接后端的socket没有使用SO_REUSEPORT.
因此，特别记录以下这两个选项的区别, 使用。

```
linux 3.10：
SO_REUSEADDR：
两个同时监听端口,无论是不是通配地址，都不行
一个监听端口，一个不是监听，先客户端bind，然后监听通配地址/或者普通地址都可以

SO_REUSEPORT:
一个绑定通配地址，一个绑定固定地址，永远只会进行优先匹配固定地址, 不能匹配再分配给通配地址
```

# 惊群效应
先说结论，accept的惊群效应已经被解决, epoll的惊群同一个epoll fd等待同一个socket fd，内核默认解决惊群效应
不同epoll fd等待同一个socket fd, 通过设置EPOLLEXCLUSIVE标识解决，不过这个标识只能在linux 4.5以后的版本使用，
并且只能在EPLL_CTL_ADD中使用，并且只能和EPOLLEXCLUSIVE_OK_BITS一起使用, 例如EPOLLRDHUP一起使用就会报错

```
#define EP_PRIVATE_BITS (EPOLLWAKEUP | EPOLLONESHOT | EPOLLET | EPOLLEXCLUSIVE)

#define EPOLLINOUT_BITS (POLLIN | POLLOUT)

#define EPOLLEXCLUSIVE_OK_BITS (EPOLLINOUT_BITS | POLLERR | POLLHUP | \
            EPOLLWAKEUP | EPOLLET | EPOLLEXCLUSIVE)

```

accept解决惊群效应关键代码
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
```

# haproxy 惊群效应解决
haproxy 多进程模式下，默认是有惊群效应的，尝试给haproxy提个patch，但是被拒了，作者的解释如下:

 ![email](2018-04-12-haproxy-port-reuse/mail)


可以使用在不同进程上绑定同一个端口，然后通过reuseport解决这个问题:
```
bind :8443 process 1
bind :8443 process 2
bind :8443 process 3
bind :8443 process 4
```

