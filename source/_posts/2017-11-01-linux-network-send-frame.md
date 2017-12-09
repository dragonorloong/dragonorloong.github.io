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

linux 出口队列就是qdisc排队，多队列支持就是多个qdisc队列
