---
type: "tags"
layout: "tags"
title: Haproxy cookie
date: 2017-10-12 15:45:20
category: Haprxoy
toc: true
tags:
    - Haproxy
    - 负载均衡

description: 本章主要说明haproxy cookie的实现和使用
comments: true
---

# Haproxy cookie 配置

## 配置
```
cookie <name> [ rewrite | insert | prefix ] [ indirect ] [ nocache ]
              [ postonly ] [ preserve ] [ httponly ] [ secure ]
              [ domain <domain> ]* [ maxidle <idle> ] [ maxlife <life> ]
              
    rewrite: 改写cookie，后端没带这个cookie名字时，直接跳过，会把cookie转发给后端
    
    insert: 插入cookie, 假如设置了maxlife或者maxidle，后面用|分隔，分别设置last_date，first_date,
    第一个日期是last_date刷新时间: now - last_date > maxidle  过期
    第二个日期是first_date生成时间: now - first_date > maxlife 过期 
    对于服务端返回的同名cookie，直接删除
    
    prefix: 在服务端返回的cookie value前面加入一个前缀，客户端带过来请求时，会删掉，不会传给服务端。
    使用~作为分隔符, 与indirect不生效
    
    indirect： 与insert模式一起时，会删除整个cookie，不会转发给服务端
    
    preserve: 服务器已经有这个cookie时，不会改变它
    
    nocache: inesrt时有用，设置Cache-control: private头部，告诉中间代理服务器，不要缓存这个响应 //http规定
    
    domain: 只有访问这个域名才会带上cookie，主要是子域名的包含问题 //http规定
    
    httponly: 防止js里面获取cookie，防止xss攻击 //http规定 ？
    
    secure: 只要在使用https等安全协议时，才会发送cookie //http规定
    
    postonly: 只在insert模式下有用，只有在post模式下才插入cookie

option persist    
    配置以后，无论server健康检查是否down，都会使用匹配的server，不会redispatch
force-persist { if | unless } <condition>
    满足acl条件的情况下，cookie匹配到某个后端server时，不管后端server的健康检查状态，都强制使用这个server
    
ignore-persist { if | unless } <condition>
    满足acl条件的情况下，忽略cookie等匹配，http-response中，不会插入cookie
```

## 性能
```
/*
 * Manage client-side cookie. It can impact performance by about 2% so it is
 * desirable to call it only when needed. This code is quite complex because
 * of the multiple very crappy and ambiguous syntaxes we have to support. it
 * highly recommended not to touch this part without a good reason !
 */
 
 代码实现很复杂，会影响2%的性能
```
