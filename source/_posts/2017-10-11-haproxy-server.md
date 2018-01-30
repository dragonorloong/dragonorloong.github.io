---
type: "tags"
layout: "tags"
title: Haproxy 后端server/健康检查
date: 2017-10-11 15:45:20
category: Haprxoy
toc: true
tags:
    - Haproxy
    - 负载均衡

description: 本章主要说明haproxy 后端server和健康检查相关的实现
comments: true
---


# Haproxy Server管理

## 概述
```
server配置如下：
    server <name> <address>[:[port]] [param*]

name: 必须保证在同一个backend中唯一

address: 可以加个前缀，指定后端地址的类型，
   支持ipv4,ipv6, unix domain, namespace

port: 假如不指定时，使用客户端连过来的端口，
    也可以使用-1,+2,这样表示在客户端的端口上减去1，
    例如客户端连接127.0.0.1:83，配置-1以后，
    后端的端口为83-1=82

param: 包括健康检查check，代理agent，cookie等
```
## 连接数
```
关于连接限制，maxconn可以定义在global，default，listener，frontend, server这几个地方，
另外还有minconn, maxconn， fullconn等，比较混乱，下面分析下各个参数的具体意思，从一个配置入手：

global
    maxconn 81920 //整个进程所有前端加起来最多accept 81920个连接

default
    maxconn 10240  //单个frontend最多accept 10240个连接

backend be
    //当server的minconn和maxconn设置了以后， fullconn才有意义
    //fullconn默认值是引用它的frontend的maxconn累加 除以10，(1024+1000+9)/10, 加9是为了向下取整
    //fullconn的意义是，当backend的所有server的连接数加起来超过了fullconn 1024,认为这个backend已经处于
    //高负载情况，这时候，server-1的最大连接数为maxconn 100，否则server-1的最大连接数为minconn 10
    fullconn 1024 
    //作者的解释：http://thread.gmane.org/gmane.comp.web.haproxy/5357
    //  - minconn defines the limit when load is low
    //  - maxconn defines the limit when load is high
    //  - fullconn defines what a high load is

    server server-1 192.168.0.5:8080 minconn 10 maxconn 100
    server server-2 192.168.0.6:8080 minconn 1000 maxconn 10000
    
frontend fe1
    bind :8080
    maxconn 1024 //fronend fe1 最大accept个数为1024
    use-backend be
    
frontend fe2
    bind :8081
    maxconn 1000
    use-backend be
```

## http相关

### keep-alive
```
    option http-keepalive //默认选项，对于client带有conntion: keep-alive的选项，保持连接
    option http-server-close //客户端保持连接，服务端关闭连接
    option forceclose //完成整个响应以后，关闭两端连接
    option http-tunnel //只有第一个请求被解析，后面的内容只是透明转发, 当在头部中发现upgrade字段时，也会转变成这种模式，所以haproxy天生支持websocket
    option httpclose //在请求和响应两端分别加上connection: close字段
```

### 连接复用
```
    //对于默认情况下，client带了keep-alive header时，后端连接会保留，这时候
    //连接可以下次的重复使用，即多个客户端先后使用同一个服务端
    http-reuse never //永远不重复利用，默认选项
    http-reuse safe //client的第一个请求新建后端连接，后续请求可以复用之前别的client遗留下来的连接
    http-reuse aggressive //client的第一个请求只会复用之前已经复用过一次及以上的遗留连接
    http-reuse always //总是重复利用之前遗留的连接
```

## 健康检查

```
健康检查涉及到的配置参数：
    global
        //程序启动开始计时，到第一次健康检查执行的最大间隔时间
        //为了防止多个健康检查同时运行，第一次健康检查的时间为:
        //min(inter, max-spread-checks)*index/total，其中index是server的位置，
        //total是整个进程中，server的个数
        //后面的每次健康检查间隔时间也会减去一个随机时间，随机因子中有max-spread-checks
        max-spread-checks 
        
    backend be
        //健康检查方法1
            //http健康检查，后面可以指定方法
            option httpchk GET /
            //返回码只有2/3开头才会认为检查是成功的
            http-check expect rstatus ^[23]
            //发送服务器的健康检查状态给后端
            http-check send-state
            //返回404时，进入维修模式，请求不会转发到这个后端，可以作为http服务器升级使用
            http-check disable-on-404
        
        //健康检查方法2
            //tcp健康检查
            //可能在一个ip上面绑定多个端口，这样健康检查可以像下面这样做，
            //haproxy先连110端口，检查返回值，再连143端口，发送test字符串，
            //再检查返回值，整个过程是一个事务，都成功，才认为
            //这次检查的结果是健康的
            option tcp-checkoption tcp-check
            tcp-check connect port 110
            tcp-check expect string +OK\ POP3\ ready
            tcp-check connect port 143
            tcp-check send test
            tcp-check expect string *\ OK\ IMAP4\ ready
            server mail 10.0.0.1 check
        
        //健康检查方法3
            //外部健康检查，调用外部进程来完成健康检查，健康检查的结果通过捕获子进程退出的
            //信号，waitpid 获取子进程退出码，退出状态为0代表健康
            //传给子进程的参数通过注入环境变量完成
            option external-check
            //外部进程
            external-check command /bin/true
            //外部进程的PATH环境变量
            external-check path "/usr/bin:/bin"
            
        //另外还支持多种健康检查方式，例如redis，mysql，smtp等
        
        
        //代理健康检查，agent，主要用于后端服务的升级
        //当后端服务要升级时，先后端服务商listen 18080端口，然后haproxy会检测这个端口打开
        //会连接上去，这时候返回maint字符串，haproxy收到这个字符串以后，会把后端设置为维修模式，
        //这样，就不会有新的连接过来了，等老的连接断掉以后，把服务器升级重启，
        //然后再发送ready给haproxy，haproxy把server放到正常的队列里面，开始提供服务
        
        //除了一开始发送maint，也可以发送up，down来设置server的状态
        server server1 192.168.1.3:8080 check inter 5s agent-check agent-inter 10s age
nt-port 18080

        //因为haproxy的server启动时，默认server是可用的，
        //配置slowstart以后，会在启动的时候，每次增加权重的5%，在配置的时间内(10s)内完成整个启动
        server slowstart-server 192.168.1.3:8081 slowstart 10s
```
