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

    static int __init inet_init(void)
    {
          struct sk_buff *dummy_skb;
          struct inet_protosw *q;
          struct list_head *r;
          int rc = -EINVAL;

          BUILD_BUG_ON(sizeof(struct inet_skb_parm) > sizeof(dummy_skb->cb));

          //主要是创建各种sock的内存池, 然后把协议添加到全局链表proto_list中
          rc = proto_register(&tcp_prot, 1);
          if (rc)
                  goto out;

          rc = proto_register(&udp_prot, 1);
          if (rc)
                  goto out_unregister_tcp_proto;

          rc = proto_register(&raw_prot, 1);
          if (rc)
                  goto out_unregister_udp_proto;

          /*
           *      Tell SOCKET that we are alive...
           */

          //把PF_INET协议簇添加到sock_register, 对应的操作函数是inet_family_ops, 创建套接字是的创建函数
          (void)sock_register(&inet_family_ops);

          /*
           *      Add all the base protocols.
           */

          //把四层协议添加爱到全局变量inet_proto中，注册三层向四层传递时的接收函数
          if (inet_add_protocol(&icmp_protocol, IPPROTO_ICMP) < 0)
                  printk(KERN_CRIT "inet_init: Cannot add ICMP protocol\n");
          if (inet_add_protocol(&udp_protocol, IPPROTO_UDP) < 0)
                  printk(KERN_CRIT "inet_init: Cannot add UDP protocol\n");
          if (inet_add_protocol(&tcp_protocol, IPPROTO_TCP) < 0)
                  printk(KERN_CRIT "inet_init: Cannot add TCP protocol\n");
#ifdef CONFIG_IP_MULTICAST
          if (inet_add_protocol(&igmp_protocol, IPPROTO_IGMP) < 0)
                  printk(KERN_CRIT "inet_init: Cannot add IGMP protocol\n");
#endif

          /* Register the socket-side information for inet_create. */
          for (r = &inetsw[0]; r < &inetsw[SOCK_MAX]; ++r)
                  INIT_LIST_HEAD(r);

          //把四层协议的inet_protosw结构注册到inetsw中, 用于暂时未知
          for (q = inetsw_array; q < &inetsw_array[INETSW_ARRAY_LEN]; ++q)
                  inet_register_protosw(q);

          /*
           *      Set the ARP module up
           */

          //注册二层向三层投递时，arp类型的处理函数, 
          //以及neight模块的初始化, /proc参数读取，设置初始化
          arp_init();

          /*
           *      Set the IP module up
           */

          //路由子系统的初始化， ip_peer初始化，主要对每一个地址，保持一个连接信息，生成ip包的id
          ip_init();

          //创建内核tcp_socket来发送reset包
          tcp_v4_init(&inet_family_ops);

          /* Setup TCP slab cache for open requests. */
          tcp_init();

          /* Add UDP-Lite (RFC 3828) */
          udplite4_register();

          /*
           *      Set the ICMP layer up
           */

          //每个cpu创建一个内核icmp套接字，用于处理ip请求的响应, 错误报告
          icmp_init(&inet_family_ops);

          /*
           *      Initialise the multicast router
           */
#if defined(CONFIG_IP_MROUTE)
          ip_mr_init();
#endif
   /*
           *      Initialise per-cpu ipv4 mibs
           */

          if(init_ipv4_mibs())
                  printk(KERN_CRIT "inet_init: Cannot init ipv4 mibs\n"); ;

          ipv4_proc_init();

          ipfrag_init();

          //二层向三层投递是，ip协议的接收函数注册
          dev_add_pack(&ip_packet_type);

          rc = 0;
  out:
          return rc;
  out_unregister_udp_proto:
          proto_unregister(&udp_prot);
  out_unregister_tcp_proto:
          proto_unregister(&tcp_prot);
          goto out;
    }
