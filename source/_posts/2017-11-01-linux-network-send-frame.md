---
title: linux 驱动层数据发送
date: 2017-11-01 20:54:26
tags:
    - linux 
    - tcp/ip
description: 网卡驱动层发送流程, 占坑，以后再总结
---

l3调用

dev_hard_start_xmit

内核与驱动的衔接函数
dev_queue_xmit

netif_start_queue 重启出口队列

netif_wake_queue 重启网卡并且检查有没有数据需要发送

linux 网卡驱动队列是一个简单的环形队列，和qdisc提供的队列完全是两码事，下面的图可以说明：

使用ip a或者 ifconfig显示的qlen或者txqueuelen 表示的是qdisc队列的长度,单位是包数, 有可能存在一种情况，就是流量大的tcp 流，直接把qdisc队列打满了，为了公平，推出了tsq机制， 单个tcp流最多存在的排队字节数， tcp_limit_output_bytes参数用来调整
而网卡队列的长度可以通过ethtool -g eth0 查看，单位是字节数, ethtool命令用来查看修改网卡的物理信息
tso 表示tcp 延迟分段，所有的分段度交给网卡来处理
gso 通用延迟分段，在发送给网卡之前再分段，只需内核支持，不需要网卡支持
lro/gro 通过把小包汇聚成大包交给上层协议，对于负载均衡等中间设备，应该关掉这个特性

netfilter 原理：
http://www.cnblogs.com/liushaodong/archive/2013/02/26/2933593.html

TC(Traffic Control)框架原理解析
http://blog.csdn.net/dog250/article/details/40483627

