---
type: "tags"
layout: "tags"
title: Haproxy 启动流程
date: 2017-10-05 15:45:20
category: Haprxoy
toc: true
tags:
    - Haproxy
    - 负载均衡

description: 本章主要说明haproxy的启动流程，以及reload机制
comments: true
---

# Haproxy 启动流程
## 初始化流程
```
整个初始化流程为：
    1 解析命令行参数，获取oldpid，-sf pid1 pid2
    2 读取配置文件，解析配置文件，检查配置文件是否有效 -f /etc/haproxy/haproxy.cfg
    3 全局参数的初始化，例如使用io复用方式，进程个数，最大套接字个数，内存池等
    4 注册和忽略相关信号处理
    5 调用setrlimit设置资源使用限制
    6 尝试监听所有bind端口，监听失败时，暂停老进程的监听端口, 后面新进程再遇到情况，
    会恢复老进程的监听
    7 chroot，改变进程的根目录
    8 关闭老进程，根据命令行参数决定是软中止，还是强关
    9 根据配置文件中nbproc个数，fork子进程
    10 设置子进程的cpu亲缘性
    11 在代码层面启动监听，开始accept连接
```

## 相关信号
```
SIGUSR1： 软重启，等所有连接断掉以后再退出进程，监听一般都是立即关闭，不会接收新连接， 
          有个配置grace，表示多久以后再关闭监听
SIGTERM： 马上关闭，强关
SIGQUIT:  dump出内存使用情况, 顺便gc内存，高于低水位的未使用的内存回收掉
SIGHUP: 打印出后端的server的连接情况
SIGTTOU: 关闭监听, 之前bind的端口全部close
SIGTTIN: 重新打开监听
```

## 监听设置
```
    作为一个异步服务器，监听套接字需要设置很多选项, haproxy 主要设置以下几个选项：
    1 设置listen为非阻塞, 防止阻塞在accept 
        fcntl(fd, F_SETFL, O_NONBLOCK)
        
    2 设置SO_REUSEADDR和SO_REUSEPORT, 主要是端口和地址重用的问题, 
        SO_REUSEADDR在Linux系统上的作用是，tcp服务器重启阶段，即使存在time_wait socket，
        也可以绑定成功。
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one))；
        
        SO_REUSEPORT的作用是能够同时绑定监听多个相同的ip:port，并且内核会分发任务，
        使每个socket的accept平衡处理，3.9以后才有的特性，假如系统不支持这个选项，
        haproxy在reload时，会关闭老进程的监听
        http://blog.chinaunix.net/uid-28587158-id-4006500.html
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
        
    3  根据配置文件中的配置，假如设置了option nolinger， 在调用close(fd)时，会丢弃
       tcp发送缓存的数据，并且发送rst给对方
        const struct linger nolinger = { .l_onoff = 1, .l_linger = 0 };
        setsockopt(fd, SOL_SOCKET, SO_LINGER, &nolinger, sizeof(struct linger));
        
    4 还有透明代理相关的配置 //待深入了解
        setsockopt(fd, SOL_IP, IP_TRANSPARENT, &one, sizeof(one))
        setsockopt(fd, SOL_IP, IP_FREEBIND, &one, sizeof(one))
        setsockopt(fd, IPPROTO_IP, IP_BINDANY, &one, sizeof(one))
        setsockopt(fd, SOL_SOCKET, SO_BINDANY, &one, sizeof(one))
```
