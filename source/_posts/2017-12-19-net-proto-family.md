---
title: internet 协议簇
date: 2017-12-19 20:08:41
tags:
  - linux
  - tcp/ip
---
   linux 目前最多支持种协议簇, 此外，还有一个地址簇的概念，目前来说，他们是一一对应的，如下图所示：
   ![net_protocol_family](2017-12-19-net-protocol-family/protocol_family.png)

   每个协议簇都用一个net_proto_family结构实例表示, 对于PF_INET来说定义如下:

   static struct net_proto_family inet_family_ops = {
        .family = PF_INET,
        .create = inet_create,
        .owner  = THIS_MODULE,
   };

  后续socket相关的操作都会使用inetsw_array中的数据结构，根据socket类型，组成一个hash表，通过链式解决冲突问题, 数据结构如下图所示：
   ![inetssw](2017-12-19-net-protocol-family/inetsw.png)
    
  static struct inet_protosw inetsw_array[] =
  {
          {
                  .type =       SOCK_STREAM,
                  .protocol =   IPPROTO_TCP,
                  .prot =       &tcp_prot,
                  .ops =        &inet_stream_ops,
                  .capability = -1,
                  .no_check =   0,
                  .flags =      INET_PROTOSW_PERMANENT |
                                INET_PROTOSW_ICSK,
          },

          {
                  .type =       SOCK_DGRAM,
                  .protocol =   IPPROTO_UDP,
                  .prot =       &udp_prot,
                  .ops =        &inet_dgram_ops,
                  .capability = -1,
                  .no_check =   UDP_CSUM_DEFAULT,
                  .flags =      INET_PROTOSW_PERMANENT,
         },


         {
                 .type =       SOCK_RAW,
                 .protocol =   IPPROTO_IP,        /* wild card */
                 .prot =       &raw_prot,
                 .ops =        &inet_sockraw_ops,
                 .capability = CAP_NET_RAW,
                 .no_check =   UDP_CSUM_DEFAULT,
                 .flags =      INET_PROTOSW_REUSE,
         }
  }; 

  当ip层收到数据以后，需要根据四层协议的类型，转发给相关函数处理，该函数也是在数组中，数组下表是四层协议类型, 单个结构类型为net_protocol数据结构如下图所示：
   ![inet_protos](2017-12-19-net-protocol-family/inet_protos.png)

  internet 协议簇的初始化：
    1 初始化tcp_prot, udp_prot, raw_prto的slab, 并且把它们加到proto_list链表中，以便支持/proc/net文件系统, 其中tcp有三个slab存池，另外两个是request, time_wait结构
    2 在套接口层支持internet协议簇
    3 将所有的传输层协议注册到net_protos中
    4 初始化inetsw hash表，将inetsw_array中的协议注册到inetsw中
    5 初始化arp模块
    6 初始化ip模块
    7 创建内部tcp套接口， 主要用来发送RST和ACK
    8 初始化UDP-Lite协议
    9 初始化ICMP模块
    10 初始化/proc/net 文件系统

    ......

