---
type: "tags"
layout: "tags"
title: Haproxy 半连接状态的bug 解决
date: 2017-10-14 20:11:23
category: Haprxoy
toc: true
tags:
    - Haproxy
    - 负载均衡

description: 本章主要说明Haproxy tcp处于半连接状态, 触发cpu死循环的bug
comments: true
---
# 问题描述

&#160; &#160; &#160; &#160;前段时间的一天，吃完晚饭，正在和同事各种吹牛的时候，突然收到报警，线上有个用户的haproxy cpu 100%。负载均衡nlb这边的规格是按带宽来标识的，用户的带宽限制是5Mb，理论上很难跑满cpu的，持续报警肯定是有问题的。登陆上去，用我们这边标准组合拳看了一下，包括:
```
1 dmesg -T 查看系统日志
2 ss -t 查看tcp连接情况
3 top查看系统负载
4 strace查看haproxy的系统调用
5 sar -n ETCP 1查看tcp重传，连接重置信息
6 sar -n DEV 1网卡流量
7 unix域套接字连接到haproxy查看统计信息
```
得到的信息是：

```
1 haproxy cpu 100%，use 80%，sys 20%
2 tcp连接不多，200多连接
3 strace查看信息一切正常，全部是epoll_wait和sendto，recvfrom等系统调用
4 tcp 外网网卡重传很高
```
&#160; &#160; &#160; &#160;暂时就只能看到这些信息，看起来一切正常，cpu持续一段时间以后就降下来了。但是从以前压测的情况来看，5Mb带宽，连接数不多的情况是肯定跑不满cpu的，暂时看不出什么问题来了，只能tcpdump保存流量，然后慢慢分析，尝试复现来定位。
 
# 问题解决
##  尝试复现

&#160; &#160; &#160; &#160;查看tcpdump保存下来的流量，发现用户的上传流量很少，但是下行流量都很大，一个请求上行几百个字节，下行都达到了十几兆。根据这种场景，尝试线下复现，压了很久，终于复现一次cpu 100%的情况。从系统日志里面看到tcp out of memory，很明显与线上问题不一致。出现这个问题是因为连接数太多了，tcp内存使用太多，超过了系统设置的阈值以后，内存池用完了，cpu不断的分配和释放内存导致cpu使用过高。调整一下/proc/sys/net/ipv4/tcp_mem参数以后，cpu就降下来了。
 
##  分析现场信息
&#160; &#160; &#160; &#160;接着定位，仔细查看strace信息，显示epoll_wait的超时时间总是设置为0，一直在空转。
```
20:02:10.425653 epoll_wait(3, {}, 200, 0) = 0 <0.000008>
20:02:10.425692 epoll_wait(3, {}, 200, 0) = 0 <0.000008>
20:02:10.425730 epoll_wait(3, {}, 200, 0) = 0 <0.000006>
20:02:10.425767 epoll_wait(3, {}, 200, 0) = 0 <0.000004>
20:02:10.425792 epoll_wait(3, {}, 200, 0) = 0 <0.000004>
20:02:10.425813 epoll_wait(3, {}, 200, 0) = 0 <0.000005>
20:02:10.425838 epoll_wait(3, {}, 200, 0) = 0 <0.000003>
```
&#160; &#160; &#160; &#160;man epoll_wait可以看到，第三个参数是timeout
```
int epoll_wait(int epfd, struct epoll_event *events,int maxevents, int timeout);
```
&#160; &#160; &#160; &#160;haproxy总是把这个超时时间设置为0，看来可以确定是haproxy的一个bug了，线上的时候流量比较大，中间会夹杂很多recvfrom和sendto系统调用，所以没看出来。是什么原因导致epoll_wait的时间设置为0 呢？到社区搜索发现，这个bug最早三四年前就有人报出来了，但是一直没有稳定复现的方式，所以没找到。

## 代码分析
&#160; &#160; &#160; &#160;不能复现，线上不能抓到产生现场，只能看代码来解决了，haproxy的整个进程初始化配置以后，会进入一个大循环，这个大循环分为这么几步：
```
1 处理task, task包括一些acl规则，增删http头部，黑白名单，超时处理等，一个转发session对应一个task。
2 处理信号，haproxy通过自己的队列来管理信号。
3 epoll_wait等待网络事件。
4 处理网络事件。
```
代码如下所示：
```
/* Runs the polling loop */
void run_poll_loop()
{
  int next;

  tv_update_date(0,1);
  while (1) {
    /* Process a few tasks */
    process_runnable_tasks();

    /* check if we caught some signals and process them */
    signal_process_queue();

    /* Check if we can expire some tasks */
    next = wake_expired_tasks();

    /* stop when there's nothing left to do */
    if (jobs == 0)
      break;

    /* expire immediately if events are pending */
    if (fd_cache_num || run_queue || signal_queue_len || !LIST_ISEMPTY(&applet_active_queue))
      next = now_ms;

    /* The poller will ensure it returns around <next> */
    cur_poller.poll(&cur_poller, next);
    fd_process_cached_events();
    applet_run_active();
  }
}
```
&#160; &#160; &#160; &#160;在epoll_wait之前，它要设置epoll_wait的等待时间，上面代码的next就是epoll_wait最大等待时间。首先查看最先超时的task，理论上每次epoll_wait的等待时间都是这个值。但是haproxy为了更加均衡的处理task, fd读写，signal等任务，限制了每次循环处理的个数，例如每次处理task最大不超过200个，所以，当任务过多的时候，每次也会引起epoll_wait的超时时间设置为0：
```
void process_runnable_tasks()
{
  struct task *t;
  unsigned int max_processed;

  run_queue_cur = run_queue; /* keep a copy for reporting */
  nb_tasks_cur = nb_tasks;
  max_processed = run_queue;

  if (!run_queue)
    return;

  if (max_processed > 200)
    max_processed = 200;

  if (likely(niced_tasks))
    max_processed = (max_processed + 3) / 4;

  while (max_processed--) {
    ...
  }
}
```
&#160; &#160; &#160; &#160;想到这里，用haproxy的提供的统计接口查看一下当时的task数量：
```
echo "show info"|socat stdio /run/haproxy/admin.sock
…
Tasks: 226
Run_queue: 2
…
```
&#160; &#160; &#160; &#160;当时task有226个，但是能运行的是两个。能不能看到这两个处于run状态的task是什么呢，当时就感觉有道光打在我前方，对，就这么干。再仔细查看一下session的信息：
```
0xd77590: proto=tcpv4 src=42.86.68.234:43273 fe=80_efbc3d46-6522-4557-ad07-e9b709d3aefa 
be=80_d5937fca-d8b0-4b00-9613-211bb0288a64 srv=default-packteam1:cdn-3:80:80:10.173.32.165:2
ts=04 age=14m52s calls=116063184
rq[f=84a020h,i=0,an=00h,rx=,wx=,ax=] rp[f=8004c020h,i=0,an=00h,rx=?,wx=14s,ax=]
s0=[7,0h,fd=134,ex=] s1=[9,10h,fd=140,ex=] exp=? run(nice=0)
```
&#160; &#160; &#160; &#160;发现某一个session的信息尤其怪异，其中的calls字段表示task调用了多少次。一般只有连接刚创建的时候进行acl规则判断，后端服务器选择时会执行task的逻辑，也就调用3次左右就ok了，其余的就是单纯的数据透明转发，不会唤醒task,不至于调用一亿多次，看来就是这个怪异的连接引起的。rex代表读取超时时间，rex=?,感觉像c语言里面的“烫烫”，应该是哪里乱码了。到这里可以确定，这个bug只会引起cpu空转，但不会影响正常的业务，这样还放心一些。但是这个bug在我们的场景这么容易复现，不解决的话问题很严重。恩，继续看代码。
```
 if (unlikely(t < 0 || hz_div <= 0)) {
    snprintf(p, end - p, "?");
    return rv;
  }
```
&#160; &#160; &#160; &#160;"?"就是这里打出来，hz_div是一个常量1000，不可能小于0，查看代码发现，haproxy内部时间用的是无符号整形，但是他要转换成毫秒来使用，很明显已经溢出了。
```
src/time.c：
unsigned int   now_ms;  
now_ms = now.tv_sec * 1000 + curr_sec_ms;

include/types/channel.h:
struct channel {
    int rex;  /* expiration date for a read, in ticks */
}
```
&#160; &#160; &#160; &#160;更加刺激的是，无符号now_ms最终会赋值给有符号的rex，然后就成了负数，代码这么写确实很心累。虽然不能复现，但也觉得找到问题了，和老大汇报了一下，感觉自己马上就要走到人生巅峰了，后来发现脸好痛，打得啪啪啪的响。对于溢出的情况，在linux内核也是很常见的，为了节省内存而已，就相当于把最高位去掉再比较，所以只要设置的超时时间不是特别大，肯定是没问题的。对于无符号，有符号之间的比较，最后也会类型提升。那天我都和祥玲嫂一样，一直念叨“我真傻, 真的，没有复现，就说自己找到了问题”。
 
&#160; &#160; &#160; &#160;看来rex不可能是负值了，肯定是rex已经超时了，但是每次都没有重置它，导致不断循环。
因为要根据rq,rp,s0,s1来分析问题，他们的含义如下图所示：
  ![](memory-frame-work.jpeg) 
&#160; &#160; &#160; &#160;简单点说，那堆数据代表的意思就是haproxy与后端服务器的连接已经完全关闭了，客户端已经发送了tcp fin包给haproxy，但是后端还有数据没有转发给前端，所以，前端连接处于close_wait状态。初步怀疑和半连接状态有关。因为猜测是已经超时，但是没有重置超时的情况下导致task不断回调，所以查看超时重置的代码，如下所示：
```
if (unlikely((res->flags & (CF_SHUTR|CF_READ_TIMEOUT)) == CF_READ_TIMEOUT)) {
    if (si_b->flags & SI_FL_NOHALF)
        si_b->flags |= SI_FL_NOLINGER;
    si_shutr(si_b);
}
```
&#160; &#160; &#160; &#160;假如设置了CF_SHUTR状态，就永远不会进去这个分支，超时状态就会一直保持，就会不断的回调task。恩，感觉马上就找到问题了，然后再尝试查找设置后端读取超时的地方，也就是设置res的地方，如下所示：
```
if (unlikely((req->flags & (CF_SHUTW|CF_SHUTW_NOW)) == CF_SHUTW_NOW &&
         channel_is_empty(req))) {
    if (req->flags & CF_READ_ERROR)
        si_b->flags |= SI_FL_NOLINGER;
    si_shutw(si_b);
    if (tick_isset(s->be->timeout.serverfin)) {
        res->rto = s->be->timeout.serverfin;
        res->rex = tick_add(now_ms, res->rto);
    }
}
```
&#160; &#160; &#160; &#160;假如设置rex读超时之前，已经收到了后端服务器的tcp fin包，设置了res的状态为CF_SHUTR状态，然后客户端再发送tcp fin包给haproxy，进入这个分支，就会触发这个bug了。根据这个假设去复现，发现和线上现象是完全吻合的。在这里判断一下res的状态，在已经关闭读端的时候，不去设置半连接超时，这样就能修复这个bug了。如下所示：
```
if (tick_isset(s->be->timeout.serverfin) && !(res->flag & CF_SHUR)) {
    ...
}
```
## 反馈
&#160; &#160; &#160; &#160; 总结一下这个bug触发的场景，其实也是很巧合，
```
1 nlb这边haproxy的半连接超时是90s,正常连接超时是900s，这里有个时间差；
2 用户后端服务器与haproxy之间的网络流量很流畅，没有阻塞;
3 客户端与haproxy之间因为经过公网，网络丢包很严重，网络拥塞，数据一致阻塞在haproxy的缓存中，
  这时候设置写超时wex=900s。
4 后端服务器发送完数据主动关闭写，发送fin包，haproxy接收这个fin包，haproxy设置res->flag |= CF_SHUTR。
5 客户端主动关闭写，发送fin包给haproxy，haproxy设置res->rex = 90s。90s后，task被超时唤醒，
```
&#160; &#160; &#160; &#160;没有重置rex的值，导致一直超时，不断回调。直到wex=900超时以后两端都关闭释放整个session和task为止。
总之上面的条件每一个都要满足才会触发这个bug。

&#160; &#160; &#160; &#160;能稳定复现，也已经找到修复的方法，给官方提个patch，也好确认一下问题，
当然我看问题没有作者那么全面，他提出了比较全面的修复方法，截取部分邮件内容：

  ![](patch-email.png) 

 &#160; &#160; &#160; &#160;git提交信息如下：
 
![](commit-message.png) 


# 总结
&#160; &#160; &#160; &#160;下面分享一下我个人在解决这种问题时的思路：
```
1 首先肯定是现场分析，查看应用层软件的日志信息，对于开源软件，一般会提供统计工具，
例如haproxy就会有专门的统计接口。 应用层软件没有明显问题时，分析操作系统级别的问题，
借助tcpdump，top，strace，ss，sar，dmesg等。比较难的问题现场很难定位到，
这时候，很重要的一点，保存刚刚抓到的信息。

2 线上一般流量比较大，很多干扰信息。这时候，可以根据线上现象，猜测原因，并且尝试复现。
假如能肯定复现，那这个问解决起来就比较简单了，线下能单步调试，查看相关模块的代码等方式来解决。

3 对于比较著名的开源软件，也许你遇到的bug，大部分人都已经遇到过，可以去社区查询，或者与作者邮件沟通。
像本文遇到的这个bug，社区有人报这个bug，因为不能复现，所以一直没有解决。
但是也可以为解决问题增加一点猜测的方向，别人的场景和我的场景有什么重叠和不同之处。

4 向团队专家，大神求助，他们经验丰富，能够及时纠正你一些错误的想法，特别是操作系统层面的问题，
可能他们曾经就遇到过。 解决这个bug的时候，我多次骚扰我们团队的大神。
```
