---
type: "tags"
layout: "tags"
title: Haproxy stick table
date: 2017-10-07 15:45:20
category: Haprxoy
toc: true
tags:
    - Haproxy
    - 负载均衡

description: 本章主要说明haproxy stick table使用和原理实现
comments: true
---


# Haproxy Stick Table 原理
## 概述
```
   stick-table 中文翻译"粘表"，最开始设计初衷是对于有相同标志的多个请求，请求转发到同一个后端。
    后面扩大了一些功能，可以用来做数据统计，限速攻击拦截等，所以在使用中，第一反应是很乱，本文从配置
    入手，分析一个比较典型的例子，再说明其源码的实现。
    
    stick-table type {ip | integer | string [len <length>] | binary [len <length>]}
            size <size> [expire <expire>] [nopurge] [peers <peersect>]
            [store <data_type>]
            
    这是一个stick-table的定义，每个frontend，backend，listen都可以定义一个stick-table，名字是frontend
    等的名字，type是stick-table存储的key的类型，store是额外存储的字段，其中server_id也就是后端服务器
    的id是默认存储的。额外存储的字段例如conn_cnt，连接总数，单调递增；http_req_rate(10s) 10s内http
    请求的速度。
    
    stick on <pattern> [table <table>] [{if | unless} <condition>]    
    匹配和保存，根据pattern提取出来的值作为key，去table查找后端，如果查找到就使用
    请求完成以后，把后端，以及额外要保存的值保存到table中
    pattern： 是样本提取函数，参考前面acl一节
    table： table名字，可以在一个后端中引用另外一个后端的table
    condition： 满足这个条件才会进行匹配和保存
    
    stick match <pattern> [table <table>] [{if | unless} <cond>]
    单纯匹配后端，不保存本次的结果
    
    stick store-request <pattern> [table <table>] [{if | unless} <condition>]
    stick store-response <pattern> [table <table>] [{if | unless} <condition>]
    单纯保存，不进行匹配
    
    
    http-request { track-sc0 | track-sc1 | track-sc2 } <key> [table <table>] |
              sc-inc-gpc0(<sc-id>) |
              sc-set-gpt0(<sc-id>) <int> 
    tcp-request content  track-sc0 | track-sc1 | track-sc2 } <key> [table <table>] |
              sc-inc-gpc0(<sc-id>) |
              sc-set-gpt0(<sc-id>) <int> 
              
    在http-request和tcp-request中，也会有stick-table的使用，主要用于跟踪值，增加gpc值等，
    其中key表示样本提取方法，用来从请求当中提取主键，可以这么使用：
    http-request track-sc2 hdr(host)
    
```

## 示例
```
google haproxy stick-table的使用，总是会遇到一篇文章，说实话，这个示例很乱，没有说清楚，反而带来很多困扰
http://blog.serverfault.com/2010/08/26/1016491873/（英文）
http://blog.sina.com.cn/s/blog_704836f40101f6qz.html (中文翻译)
本文也以这个为示例:
    
global
   log 127.0.0.1   local0
   log 127.0.0.1   local1 notice
   stats socket /var/run/haproxy.stat mode 600 level operator
   maxconn 4096
   user haproxy
   group haproxy
#   daemon

defaults
   log global
   mode http
   option httplog
   option dontlognull
   retries 3
   option redispatch
   maxconn 2000

backend test1
   stick-table type ip size 200k expire 10m store conn_rate(100s),bytes_out_rate(60s),gpc0
     # values below are specific to the backend
     tcp-request content track-sc2 src 
     acl conn_rate_abuse sc2_conn_rate gt 3

     # abuse is marked in the frontend so that it's shared between all sites
     acl mark_as_abuser sc1_inc_gpc0 gt 0
     tcp-request content reject if conn_rate_abuse mark_as_abuser
     server local_apache localhost:80

  backend ease-up-y0
      mode http
      errorfile 503 /etc/haproxy/errors/503.http

frontend http
   bind *:2550
   stick-table type ip size 200k expire 10m store gpc0
   # check the source before tracking counters, that will allow it to
   # expire the entry even if there is still activity.
   acl source_is_abuser src_get_gpc0 gt 0
   acl is_test1 hdr_sub(host) -i test1.com
   tcp-request connection track-sc1 src if !source_is_abuser

   use_backend ease-up-y0 if source_is_abuser
   use_backend test1 if is_test1
   
   这个实例我精简了一下，现在主要作用是是：
   1 host=test1.com 的使用backend test1后端
   2 对于gpc0 大于 0的，使用ease-up-y0后端，返回503
   3 100s内，连接速度超过3个，拒绝连接，并且标记增加gpc0的值
```
## 数据结构
```
//每个key的数据结构， 所有的值都存储在后面
struct stksess {
  unsigned int expire;      /* session expiration date */
  unsigned int ref_cnt;     /* reference count, can only purge when zero */
  struct eb32_node exp;     /* ebtree node used to hold the session in expiration tree */
  struct eb32_node upd;     /* ebtree node used to hold the update sequence tree */
  //连接到stktable的keys中
  struct ebmb_node key;     /* ebtree node used to hold the session in table */
  /* WARNING! do not put anything after <keys>, it's used by the key */
  //例如：gpc0，server_id等值都是存储在最后面的这块内存里面，Linux常见手法
};

//单个stick-table的数据结构，这里省略了很多字段
struct stktable {
  //使用eb_root存储key
  struct eb_root keys;      /* head of sticky session tree */
  struct eb_root exps;      /* head of sticky session expiration tree */
  //存储额外字段的总大小，也就是在分配上面的stksess的时候，需要多分配data_size大小的内存
  int data_size; /* the size of the data that is prepended *before* stksess */
  //每种存储类型与stkses的距离offset，为0代表不需要存储这种类型，类型包括server_id,gpt0，gpc0,conn_cnt等
  int data_ofs[STKTABLE_DATA_TYPES]; /* negative offsets of present data types, or 0 if absent */
  //每种类型的参数，例如速率相关的都有个时间，conn_rate(100s)，这个100s就保存在这里
  union {
    int i;
    unsigned int u;
    void *p;
  } data_arg[STKTABLE_DATA_TYPES]; /* optional argument of each data type */
}

//当前strem正在跟踪的条目，entry是stksess的地址强转为unsigned long类型
struct stkctr {
  unsigned long entry;  /* entry containing counters currently being tracked by this stream  */
  struct stktable *table; /* table the counters above belong to (undefined if counters are null) */
}

//stream 与本节相关的内容
struct stream {
  ...
  
  //需要保存的数据，一开始先标记，等后面例如server_id等赋值以后，再从这里取出来保存，顺便增加conn_cnt等值
  struct {
    struct stksess *ts;
    struct stktable *table;
  } store[8];                     /* tracked stickiness values to store */
  int store_count;
  
  //这里困扰了我很久的一个问题，上面示例中的src_get_gpc0在frontend中声明，
  //默认使用的是http表，在backend中sc1_inc_gpc0 默认使用的是test1表，
  //两个表都可以独立的统计gpc0，一点关联都没有，不可能达到配置的目的，后来
  //通过查看代码发现，在一个stream中，针对sc0 sc1 sc2这三个标记，会在stkctr数组中保存
  //因为一个frontend和一个backend属于同一个stream，又在http中，track-sc1的时候，已经
  //初始化了stkctr[1]->table = http，所以在backend test1中，会从这数组中取出http table来
  //使用，增加gpc0的值
  struct stkctr stkctr[MAX_SESS_STKCTR];
  
  ...
}

//与本节内容弄有关的还有tcp-request http-request等，这些保存在proxy中
struct proxy {
  //"http_request"
  struct list http_req_rules;   /* HTTP request rules: allow/deny/... */
  //"http_response"
  struct list http_res_rules;   /* HTTP response rules: allow/deny/... */
  //"stick match" "stick store" "stick on"
  struct list sticking_rules;             /* content sticking rules (chained) */
  struct list storersp_rules;             /* content store response rules (chained) */
  
  // "tcp_request"
  struct tcp_req {};
  
  //"tcp_response"
  struct tcp_rep {};
}
```

## 代码跟踪
```
//tcp-request connection 是在session处理阶段，accept中处理的，stream中的strctr会从session中继承下来
//tcp-request content 是在已经分配了stream，在stream中处理的

tcp-request connection track-sc1 src if !source_is_abuser

首先在frontend的http表中，gpc0初始值为0，所以会进入track-sc1流程，tcp-request属于上面的tcp_req
规则的一部分，所以会在tcp_exec_req_rules函数中处理
  tcp_exec_req_rules：
    ......
    //首先执行acl的conditon，条件满足以后，会判断rule的action
    if (rule->action >= ACT_ACTION_TRK_SC0 && rule->action <= ACT_ACTION_TRK_SCMAX) {
      /* Note: only the first valid tracking parameter of each
      * applies.
      */
      struct stktable_key *key;
      
      //判断是不是第一次进去，不是的话，返回非空，直接返回
      if (stkctr_entry(&sess->stkctr[tcp_trk_idx(rule->action)]))
        continue;

      //rule的table会在配置解析的时候，设置为http
      t = rule->arg.trk_ctr.table.t;
      //到table中查找key，假如不存在会创建新的
      key = stktable_fetch_key(t, sess->fe, sess, NULL, SMP_OPT_DIR_REQ|SMP_OPT_FINAL, rule->arg.trk_ctr.expr, NULL);

      //根据key获取stksess，然后初始化
      if (key && (ts = stktable_get_entry(t, key)))
        //这里用的是sess->stkctr的指针，相当于初始化了stkctr[1]
        stream_track_stkctr(&sess->stkctr[tcp_trk_idx(rule->action)], t, ts);
           //把需要保存的值累加
           steam_start_counters:
    }


acl source_is_abuser src_get_gpc0 gt 0:
  src_get_gpc0对应的样本提取函数是：
    smp_fetch_sc_get_gpc0：
      //从stream->strctr中取stkptr
      //这里在配置文件中，因为src_get_gpc0没有指定table，会默认使用http表，但是因为key是src，所以
      //使用的和上面track-sc1一样的表
      smp_fetch_sc_stkctr：
        if (strm)
          stkptr = &strm->stkctr[num];
        if (!strm || !stkctr_entry(stkptr)) {
          stkptr = &sess->stkctr[num];
          if (!stkctr_entry(stkptr))
            return NULL;
        }
        
        return stkptr;
      //从对应的stksess中，取出对应字段gpc0的值
      if (stkctr_entry(stkctr) != NULL) {
        void *ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC0);
        if (!ptr)
          return 0; /* parameter not stored */
        smp->data.u.sint = stktable_data_cast(ptr, gpc0);
      }

tcp-request content track-sc2 src 
因为上面都没有使用sc2这个变量，所以初始化为strem->stkctr[2].table = test1


acl conn_rate_abuse sc2_conn_rate gt 3
从stream->stkctr[2].table 也就是test1表中取出 conn_rate字段，判断当前值是否大于3

acl mark_as_abuser sc1_inc_gpc0 gt 0
从stream->stkctr[1].table 也就是http中取出gpc0的值，然后加1，这个acl始终会返回true

tcp-request content reject if conn_rate_abuse mark_as_abuser
对于速度大于3的情况，累加http表中gpc0的值，然后拒绝这个连接

然后这个ip的下一个连接过来时：
acl source_is_abuser src_get_gpc0 gt 0
use_backend ease-up-y0 if source_is_abuser

从http表中取出gpc0的值，大于1，使用ease-up-y0后端，返回503，直到10m分钟过期以后解除这限制
```
