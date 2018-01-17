---
title: linux 软中断处理
date: 2017-10-26 21:01:25
category: tcp/ip
toc: true
tags:
    - linux 
    - tcp/ip

description: 本章简要说明软中断的数据结构，以及网卡软中断的处理流程
comments: true
---
# 数据结构及初始化
每个cpu都会有一个softnet_data数据结构，cpu的softnet_data是由net_dev_init在引导期间执行初始化的，在初始化期间，还会注册网卡软中断对应的处理程序
```cpp
subsys_initcall(net_dev_init);

static int __init net_dev_init(void)
{
  int i, rc = -ENOMEM;

  BUG_ON(!dev_boot_phase);

  if (dev_proc_init())
    goto out;

  if (netdev_sysfs_init())
    goto out;

  INIT_LIST_HEAD(&ptype_all);
  for (i = 0; i < 16; i++)
    INIT_LIST_HEAD(&ptype_base[i]);

  for (i = 0; i < ARRAY_SIZE(dev_name_head); i++)
    INIT_HLIST_HEAD(&dev_name_head[i]);

  for (i = 0; i < ARRAY_SIZE(dev_index_head); i++)
    INIT_HLIST_HEAD(&dev_index_head[i]);

  /*
   *  Initialise the packet receive queues.
   */

  for_each_possible_cpu(i) {
    struct softnet_data *queue;

    queue = &per_cpu(softnet_data, i);
    skb_queue_head_init(&queue->input_pkt_queue);
    queue->completion_queue = NULL;
    INIT_LIST_HEAD(&queue->poll_list);
    set_bit(__LINK_STATE_START, &queue->backlog_dev.state);
    queue->backlog_dev.weight = weight_p;
    queue->backlog_dev.poll = process_backlog;
    atomic_set(&queue->backlog_dev.refcnt, 1);
  }

  netdev_dma_register();

  dev_boot_phase = 0;

  open_softirq(NET_TX_SOFTIRQ, net_tx_action, NULL);
  open_softirq(NET_RX_SOFTIRQ, net_rx_action, NULL);

  hotcpu_notifier(dev_cpu_callback, 0);
  dst_init();
  dev_mcast_init();
  rc = 0;
out:
  return rc;
}

struct softnet_data {
  //拥塞管理算法使用
  //bool值，true代表cpu超负荷，所有输入帧都会被丢弃
  int throttle;

  //代表拥塞等级
  int cng_level;

  //input_pkt_queue 队列长度加权后的平均值
  int avg_blog;

  //保存进来的帧 netdev_max_backlog参数相关，现在都是napi，可能不会使用, 
  //backlog 更老版本会用这个值，所有设备共享一个输入队列， 
  //netdev_max_backlog一个cpu的队列长度
  //napi情况下，是一次软中断能处理的最大帧数
  struct sk_buff_head input_pkt_queue;

  //设备列表，标识其中的设备有数据传输
  struct net_device *output_queue;

  //缓冲区列表，标识其可以释放掉
  struct sk_buff *completion_queue;

  //表示一个网卡已经准备执行，关联到这个cpu上, 非napi使用
  struct net_device backlog_dev;

  //双向链表，其中的设备表示有数据可以读取
  struct list_head poll_list;
};
```

# 中断处理
硬中断:
napi 中断发生时，调用netif_rx_schedule函数，先调用netif_rx_schedule_prep确保设备处于运行状态，并且没有添加到poll_list列表中, 然后调用__netif_rx_schedule函数把设备加入到cpu的softdata的poll_list，并且开启软中断
在这个时候，可能并没有关闭硬件驱动，这个完全由驱动程序决定，处理完以后，调用netif_rx_complete函数把设备从poll_list中删除，并且开启硬件中断

软中断:
从cpu的softdata中，轮寻poll_list中的每个设备，调用设备驱动的poll函数，poll函数负责从设备映射的内存中拷贝数据包，封装成skb，然后调用netif_receive_skb传到协议栈处理
在驱动层的的后面，会调用eth_type_trans设置l3的protocol字段和pkt_type，protocol我所知道的有arp，ip， pkt_type主要是指PACKET_OTHERHOST/PACKET_HOST/PACKET_BROADCAST/PACKET_MULTICAST等

```cpp
int netif_receive_skb(struct sk_buff *skb)
  //假如是bond网卡，把skb->dev 设置为原始网卡的master网卡
  orig_dev = skb_bond(skb);

  //对于数据的分发，假如数据帧感兴趣，就调用dev_add_pack注册到ptype_all或者ptype_base，
  //假如对所有协议都感兴趣，例如tcpdump， 原始套接字等,就把回调函数注册到ptype_all，
  //这是一个双向链表，假如只对某种协议感兴趣，l3的ip，arp等，就调用ptype_base注册，
  //ptype_bash是一个hash+链表的数据结构
  list_for_each_entry_rcu(ptype, &ptype_all, list) {
    if (!ptype->dev || ptype->dev == skb->dev) {
      if (pt_prev)
        ret = deliver_skb(skb, pt_prev, orig_dev);
      pt_prev = ptype;
    }
  }

  //处理桥接逻辑，假如一个包被发往网桥上，就不会再发给协议栈了
  if (handle_bridge(&skb, &pt_prev, &ret, orig_dev))
    goto out;

  //对于l3协议，调用其回调函数处理
  //对于arp, dev_add_pack(&arp_packet_type) 最终处理函数是：arp_rcv
  //对于ip, dev_add_pack(&ip_packet_type) 最终处理函数是: ip_rcv

  type = skb->protocol;
  list_for_each_entry_rcu(ptype, &ptype_base[ntohs(type)&15], list) {
    if (ptype->type == type &&
        (!ptype->dev || ptype->dev == skb->dev)) {
      if (pt_prev)
        ret = deliver_skb(skb, pt_prev, orig_dev);
      pt_prev = ptype;
    }
  }
```
