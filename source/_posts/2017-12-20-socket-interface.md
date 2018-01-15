---
title: linux 套接口层
date: 2017-12-20 19:42:55
tags:
  - linux
  - tcp/ip

description: 本章主要说明socket 接口层的初始化过程
---

# 套接口层的系统初始化
  socket_init在系统启动时在初始化列表中被调用，通过core_initcall宏加入到内核的初始化列表中

```cpp
  static int __init sock_init(void)
  {
          /*
           *      Initialize sock SLAB cache.
           */

          sk_init();

          /*
           *      Initialize skbuff SLAB cache
           */
          skb_init();

          /*
           *      Initialize the protocols module.
           */

          init_inodecache();
          //注册文件系统，数据结构中包含了分配i节点，和销毁i节点的函数
          //分配的i节点完整结构如下，能够通过i节点或者是socket推导出另外一个，从而建立其关系
          /*struct socket_alloc {
              struct socket socket;
              struct inode vfs_inode;
            };
          */
          register_filesystem(&sock_fs_type);
          sock_mnt = kern_mount(&sock_fs_type);

          /* The real protocol initialization is performed in later initcalls.
           */

    #ifdef CONFIG_NETFILTER
          netfilter_init();
    #endif

          return 0;
  }

  //设置内存限制, 根据物理内存来限制
  void __init sk_init(void)
  {
    if (num_physpages <= 4096) {
      sysctl_wmem_max = 32767;
      sysctl_rmem_max = 32767;
      sysctl_wmem_default = 32767;
      sysctl_rmem_default = 32767;
    } else if (num_physpages >= 131072) {
      sysctl_wmem_max = 131071;
      sysctl_rmem_max = 131071;
    }
  }

  //初始化skb内存池
  void __init skb_init(void)
  {
          skbuff_head_cache = kmem_cache_create("skbuff_head_cache",
                                                sizeof(struct sk_buff),
                                                0,
                                                SLAB_HWCACHE_ALIGN|SLAB_PANIC,
                                                NULL, NULL);
          skbuff_fclone_cache = kmem_cache_create("skbuff_fclone_cache",
                                                  (2*sizeof(struct sk_buff)) +
                                                  sizeof(atomic_t),
                                                  0,
                                                  SLAB_HWCACHE_ALIGN|SLAB_PANIC,
                                                  NULL, NULL);
  }

  //初始化套接字虚拟文件系统的i节点缓存
  static int init_inodecache(void)
  {
          sock_inode_cachep = kmem_cache_create("sock_inode_cache",
                                                sizeof(struct socket_alloc),
                                                0,
                                                (SLAB_HWCACHE_ALIGN |
                                                 SLAB_RECLAIM_ACCOUNT |
                                                 SLAB_MEM_SPREAD),
                                                init_once,
                                                NULL);
          if (sock_inode_cachep == NULL)
                  return -ENOMEM;
          return 0;
  }
```




socket 套接字数据结构，大部分字段都可以从名字看出来含义，其中ops就是上一章中写的存在inetsw中的类型
该结构完成从协议无关的套接口层到协议相关的传输层的连接，而proto结构(tcp_prot)等又将传输层映射到网络层
```cpp
/**
 *  struct socket - general BSD socket
 *  @state: socket state (%SS_CONNECTED, etc)
 *  @flags: socket flags (%SOCK_ASYNC_NOSPACE, etc)
 *  @ops: protocol specific socket operations
 *  @fasync_list: Asynchronous wake up list
 *  @file: File back pointer for gc
 *  @sk: internal networking protocol agnostic socket representation
 *  @wait: wait queue for several uses
 *  @type: socket type (%SOCK_STREAM, etc)
 */
struct socket {
        socket_state            state;
        unsigned long           flags;
        const struct proto_ops  *ops;
        struct fasync_struct    *fasync_list;
        struct file             *file;
        struct sock             *sk;
        wait_queue_head_t       wait;
        short                   type;
};
```


