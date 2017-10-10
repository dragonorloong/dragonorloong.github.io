---
type: "tags"
layout: "tags"
title: Haproxy 时间管理
date: 2017-10-09 15:45:20
category: Haprxoy
toc: true
tags:
    - Haproxy
    - 负载均衡

description: 本章主要说明Haproxy的时间管理
comments: true
---

# Haproxy 时间管理
## 概述
```
    程序会有很多定时器，超时判断等，强依赖时间。假如直接依赖系统时间，
    系统时间调整就会导致紊乱， 所以对于基础软件，都会自己管理时间，
    这个时间是单调递增的，不受系统时间的变化影响。例如libevent和haproxy都有这么做。
```

haproxy在系统初始化期间，会顺便初始化内部时间管理：

```
    tv_update_date(-1,-1);
    
``` 

每次epoll_wait返回以后，会更新和校准时间：
```
    tv_update_date(wait_time, status);    
```

```
//全局变量
unsigned int   curr_sec_ms;     /* millisecond of current second (0..999) */
unsigned int   ms_left_scaled;  /* milliseconds left for current second (0..2^32-1) */
unsigned int   now_ms;          /* internal date in milliseconds (may wrap) */
unsigned int   samp_time;       /* total elapsed time over current sample */
unsigned int   idle_time;       /* total idle time over current sample */
unsigned int   idle_pct;        /* idle to total ratio over last sample (percent) */
struct timeval now;             /* internal date is a monotonic function of real clock */
struct timeval date;            /* the real current date */
struct timeval start_date;      /* the process's start date */
struct timeval before_poll;     /* system date before calling poll() */
struct timeval after_poll;      /* system date after leaving poll() */

REGPRM2 void tv_update_date(int max_wait, int interrupted) {
{
    //记录时间差，操作系统时间调整的跨度
    static struct timeval tv_offset; /* warning: signed offset! */
    
    //adjust 校准以后的时间，deadline一次循环允许的最长时刻
    struct timeval adjusted, deadline;

    //获取当前系统时间
    gettimeofday(&date, NULL);
    
    //max_wait小于0， 表示系统初始化
    if (unlikely(max_wait < 0)) {
        tv_zero(&tv_offset);
        adjusted = date;
        after_poll = date;
        samp_time = idle_time = 0;
        idle_pct = 100;
        goto to_ms;
    }
    
    //当前时间+上次系统调整的时间跨度 = adjusted
    __tv_add(&adjusted, &date, &tv_offset);
    
    //小于now代表操作系统往回调了时间，例如当前标准时间是12点，
    //但是用shell命令调整为11点，这种情况需要重新计算offset，校准时间
    if (unlikely(__tv_islt(&adjusted, &now))) {
        goto fixup; /* jump in the past */
    }

    //一个循环运行时间大于max_wait + MAX_DELAY_MS时，认为操作系统时间往后调了，例如从12点调到13点
    /* OK we did not jump backwards, let's see if we have jumped too far
    * forwards. The poll value was in <max_wait>, we accept that plus
    * MAX_DELAY_MS to cover additional time.
    */
    _tv_ms_add(&deadline, &now, max_wait + MAX_DELAY_MS);
    if (likely(__tv_islt(&adjusted, &deadline)))
        goto to_ms; /* OK time is within expected range */
    
    fixup:
        /* Large jump. If the poll was interrupted, we consider that the date
        * has not changed (immediate wake-up), otherwise we add the poll
        * time-out to the previous date. The new offset is recomputed.
        */
        //上次时间now + max_wait当做adjusted，重新计算offset
        _tv_ms_add(&adjusted, &now, interrupted ? 0 : max_wait);

        tv_offset.tv_sec  = adjusted.tv_sec  - date.tv_sec;
        tv_offset.tv_usec = adjusted.tv_usec - date.tv_usec;
    
        if (tv_offset.tv_usec < 0) {
            tv_offset.tv_usec += 1000000;
            tv_offset.tv_sec--;
        }
    
    to_ms:
        //内部时间永远是单调递增的
        now = adjusted;
        curr_sec_ms = now.tv_usec / 1000;            /* ms of current second */

        /* For frequency counters, we'll need to know the ratio of the previous
        * value to add to current value depending on the current millisecond.
        * The principle is that during the first millisecond, we use 999/1000
        * of the past value and that during the last millisecond we use 0/1000
        * of the past value. In summary, we only use the past value during the
        * first 999 ms of a second, and the last ms is used to complete the
        * current measure. The value is scaled to (2^32-1) so that a simple
        * multiply followed by a shift gives us the final value.
        */
        ms_left_scaled = (999U - curr_sec_ms) * 4294967U;
        now_ms = now.tv_sec * 1000 + curr_sec_ms;
        return;
}

