---
type: "tags"
layout: "tags"
title: Haproxy 信号处理
date: 2017-10-08 15:45:20
category: Haprxoy
toc: true
tags:
    - Haproxy
    - 负载均衡

description: 本章主要说明haproxy的信号处理机制
comments: true
---

# Haproxy 信号处理
## linux 信号机制
```
在早期的UNIX中信号是不可靠的，不可靠在这里指的是：
信号可能丢失，一个信号发生了，
但进程却可能一直不知道这一点。
现在Linux 在SIGRTMIN实时信号之前的都叫不可靠信号，
这里的不可靠主要是不支持信号队列，
就是当多个信号发生在进程中的时候
（收到信号的速度超过进程处理的速度的时候），
这些没来的及处理的信号就会被丢掉，仅仅留下一个信号。
可靠信号是多个信号发送到进程的时候
（收到信号的速度超过进程处理信号的速度的时候），
这些没来的及处理的信号就会排入进程的队列。
等进程有机会来处理的时候，依次再处理，信号不丢失。
在signal函数处理信号时，产生信号，
不会打断当前函数，会排队，但是可靠信号会多次排队，
不可靠信号只能残留一个，也就是只能保留两个信号，
signal函数不需要多次安装
```
## 数据结构
```
    //一个信号可能由多个函数处理，轮流处理，通过sig_handler描述
    struct sig_handler {
        struct list list;
        void *handler;
        int arg;
        int flags;
    }
    
    //单个信号处理，处理函数链表通过handlers链接起来
    struct signal_descriptor {
        int coutn;
        struct list handlers;
    }
    
    int signal_queue[MAX_SIGNAL]; //本轮循环中，产生的信号
    struct signal_descriptor signal_state[MAX_SIGNAL]; //所有信号的处理方法
    struct pool_head *pool2_sig_handlers = NULL;  //信号处理相关的内存分配
    sigset_t blocked_sig; //阻塞信号集
```
## signal_init()
信号处理初始化函数
```

int signal_init() {
    int sig;

    signal_queue_len = 0;
    memset(signal_queue, 0, sizeof(signal_queue));
    memset(signal_state, 0, sizeof(signal_state));

    /* Ensure signals are not blocked. Some shells or service managers may
    * accidently block all of our signals unfortunately, causing lots of
    * zombie processes to remain in the background during reloads.
    */
    //清空信号阻塞集
    sigemptyset(&blocked_sig);
    //不阻塞任何信号
    sigprocmask(SIG_SETMASK, &blocked_sig, NULL);

    //初始化非阻塞信号集，在__signal_process_queue调用
    //sigprocmask接触阻塞，阻塞所有信号，然后进行信号处理
    sigfillset(&blocked_sig);
    sigdelset(&blocked_sig, SIGPROF);
    
    //初始化每个信号的处理链表
    for (sig = 0; sig < MAX_SIGNAL; sig++)
        LIST_INIT(&signal_state[sig].handlers);

    pool2_sig_handlers = create_pool("sig_handlers", sizeof(struct sig_handler),    MEM_F_SHARED);
    return pool2_sig_handlers != NULL;
}
```

## signal_register_fct()

信号注册函数，回调函数类型，对于task为signal_register_task函数

```
struct sig_handler *signal_register_fct(int sig, void (*fct)(struct sig_handler *), int arg)
{
    struct sig_handler *sh;

    if (sig < 0 || sig >= MAX_SIGNAL)
        return NULL;
    
    //默认函数为signal_handler
    if (sig)
        signal(sig, fct ? signal_handler : SIG_IGN);
    
    if (!fct)
        return NULL;
    
    //在内存池中分配sig_handler结构，然后加入到signal_state的list中
    sh = pool_alloc2(pool2_sig_handlers);
    if (!sh)
        return NULL;
    
    sh->handler = fct;
    sh->arg = arg;
    sh->flags = SIG_F_TYPE_FCT;                                                                                                         
    LIST_ADDQ(&signal_state[sig].handlers, &sh->list);                                                                                  
    return sh;                                     
}

```

## signal_handler
默认处理函数

```
void signal_handler(int sig)
{
    if (sig < 0 || sig >= MAX_SIGNAL) {
        /* unhandled signal */
        signal(sig, SIG_IGN);
        qfprintf(stderr, "Received unhandled signal %d. Signal has been disabled.\n", sig);
        return;
    }

    if (!signal_state[sig].count) {
        /* signal was not queued yet */
        if (signal_queue_len < MAX_SIGNAL)
            //在signal_queue中标记信号已经产生，防止盲目轮询
            signal_queue[signal_queue_len++] = sig;
        else
            qfprintf(stderr, "Signal %d : signal queue is unexpectedly full.\n", sig);
    }

    //记录信号产生的次数，再次安装信号处理函数
    signal_state[sig].count++;
    if (sig)
        signal(sig, signal_handler); /* re-arm signal */
}

```

## signal_process_queue()
真正的信号处理函数，每次循环调用一次

```
static inline void signal_process_queue() {
    if (unlikely(signal_queue_len > 0))
        __signal_process_queue()
}

void __signal_process_queue() {
    int sig, cur_pos = 0;
    struct signal_descriptor *desc;
    sigset_t old_sig;
              
    /* block signal delivery during processing */
    //阻塞所有信号                                                    
    sigprocmask(SIG_SETMASK, &blocked_sig, &old_sig);  
    
    /* It is important that we scan the queue forwards so that we can 
    * catch any signal that would have been queued by another signal
    * handler. That allows real signal handlers to redistribute signals
    * to tasks subscribed to signal zero.
    */
    //轮询signal_queue，在signal_handler中，已经记录了此次信号产生
    for (cur_pos = 0; cur_pos < signal_queue_len; cur_pos++) {
        sig  = signal_queue[cur_pos];
        desc = &signal_state[sig];     
        
        //回调所有信号处理函数，产生多次只会调用一次
        if (desc->count) { 
            struct sig_handler *sh, *shb;
            list_for_each_entry_safe(sh, shb, &desc->handlers, list) {
                if ((sh->flags & SIG_F_TYPE_FCT) && sh->handler)
                    ((void (*)(struct sig_handler *))sh->handler)(sh);
                else if ((sh->flags & SIG_F_TYPE_TASK) && sh->handler)
                    task_wakeup(sh->handler, sh->arg | TASK_WOKEN_SIGNAL);
            }
            desc->count = 0;
        }
    }
    signal_queue_len = 0;

    //重置信号屏蔽字
    /* restore signal delivery */
    sigprocmask(SIG_SETMASK, &old_sig, NULL);
}

```
