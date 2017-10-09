---
type: "tags"
layout: "tags"
title: Haproxy acl
date: 2017-10-06 15:45:20
category: Haprxoy
toc: true
tags:
    - Haproxy
    - 负载均衡

description: 本章主要说明haproxy acl 的使用以及实现原理
comments: true
---

# Haproxy Acl
##概述
```
acl:Access Control Lists 访问控制列表

acl格式如下所示：
    acl <aclname> <criterion> [flags] [operator] [<value>]
    aclname: acl名字，在后面的条件表达式中引用
    criterion: 样本提取方法，从请求或者响应内容中提取值，如hdr(host)，从http头部提取host字段的值
    flags: 匹配标志，-i 忽略大小写，-m str匹配字符串，-f从文件读取值等
    operator: 方法，匹配整形时，eq方法表示等于
    value: 具体匹配的值，可以是多个，匹配整形时 “1 2 3”，匹配字符串时“netease.com baidu.com”
```
## 示例配置
```
//以下所有的解释都基于下面的acl规则

    //定义三个acl
    //1 http host为netease.com，baidu.com，ali.com，转换成小写匹配
    acl host_acl hdr(host),lower  -m str netease.com baidu.com ali.com
    
    //2 http path 是以 /index.html 开头
    acl path_acl path_beg /index.html
    
    //3 http version为 1.1
    acl head_acl hdr(version) -m str 1.1
    
    //条件 (host_acl && (!head_acl))  || path_acl满足时，使用test1后端
    use_backend test1 if host_acl !head_acl or path_acl
```
## 数据结构
```
//acl关键字解析，例如hdr，path等
struct acl_keyword {
  const char *kw; //关键字名称，hdr
  char *fetch_kw; //提取关键字名字，多个acl关键字对应的提取关键字一样，例如hdr，hdr_beg, hdr_dir都对应req.hdr
  int match_type; /* Contain PAT_MATCH_* */ //匹配类型，可以是int，bool，str，ip等
  int (*parse)(const char *text, struct pattern *pattern, int flags, char **err); //解析字段，例如hdr(host)，调用pat_parse_str把host字段保存起来
  int (*index)(struct pattern_expr *expr, struct pattern *pattern, char **err); //把需要匹配的值保存链接起来，baidu.com，netease.com ali.com
  void (*delete)(struct pattern_expr *expr, struct pat_ref_elt *);
  void (*prune)(struct pattern_expr *expr);
  struct pattern *(*match)(struct sample *smp, struct pattern_expr *expr, int fill); //acl执行时的匹配函数
  /* must be after the config params */
  struct sample_fetch *smp; /* the sample fetch we depend on */ //样本提取结构体
};

struct acl {
    struct list list;  //假如多个acl组成一个逻辑且的表达式，通过这个list链接起来
    char *name; //acl名字
    struct list expr; //acl表达式
    int cache_idx;
    unsigned int use;
    unsigned int val;
}

//acl表达式
struct acl_expr {
    struct sample_expr *smp; //样本提取结构，例如从http头部数据的提起，获得host字段的值等
    struct pattern_head pat; //样本提取以后，具体的匹配函数，对应acl_keyword中的函数指针
    struct list list; //名字相同的acl可以包含多个acl_expr，通过链表连接起来
    const char *kw; //acl名字
}

//acl_keyword中的匹配函数
struct pattern_head {
  int (*parse)(const char *text, struct pattern *pattern, int flags, char **err);
  int (*parse_smp)(const char *text, struct sample_data *data);
  int (*index)(struct pattern_expr *, struct pattern *, char **);
  void (*delete)(struct pattern_expr *, struct pat_ref_elt *);
  void (*prune)(struct pattern_expr *);
  struct pattern *(*match)(struct sample *, struct pattern_expr *, int);
  int expect_type; /* type of the expected sample (SMP_T_*) */ //样本提取出来的类型

  struct list head; /* This is a list of struct pattern_expr_list. */
};

//主要是与pat_ref的一些结合
struct pattern_expr {
  struct list list; /* Used for chaining pattern_expr in pat_ref. */
  unsigned long long revision; /* updated for each update */
  struct pat_ref *ref; /* The pattern reference if exists. */
  struct pattern_head *pat_head; /* Point to the pattern_head that contain manipulation functions.
                                  * Note that this link point on compatible head but not on the real
                                  * head. You can use only the function, and you must not use the
                                  * "head". Dont write "(struct pattern_expr *)any->pat_head->expr".
                                  */
  struct list patterns;         /* list of acl_patterns */ //这个就是配置文件中的值，在示例中为netease.com ,baidu.com这几个值的一个链表
  struct eb_root pattern_tree;  /* may be used for lookup in large datasets */
  struct eb_root pattern_tree_2;  /* may be used for different types */
  int mflags;                     /* flags relative to the parsing or matching method. */
};

//一个acl项，其中neg为表示在使用acl时，前面是否带了逻辑非“！”
struct acl_term {
  struct list list;           /* chaining */ //所有逻辑与的acl通过这个链接起来
  struct acl *acl;            /* acl pointed to by this term */
  int neg;                    /* 1 if the ACL result must be negated */
};

//一个条件中，逻辑与的表达式通过这个结构体表示，示例中host_acl !head_acl 和 path_acl通过两个结构体表示
struct acl_term_suite {
  struct list list;           /* chaining of term suites */
  struct list terms;          /* list of acl_terms */
};


//条件，多个acl组成，use_backend if host_acl，通过一个acl_cond组成
struct acl_cond {
  struct list list;           /* Some specific tests may use multiple conditions */
  struct list suites;         /* list of acl_term_suites */
  enum acl_cond_pol pol;      /* polarity: ACL_COND_IF / ACL_COND_UNLESS */
  unsigned int use;           /* or'ed bit mask of all suites's SMP_USE_* */
  unsigned int val;           /* or'ed bit mask of all suites's SMP_VAL_* */
  const char *file;           /* config file where the condition is declared */
  int line;                   /* line in the config file where the condition is declared */
};

```

## 代码跟踪
### acl
```
//acl表达式，hdr为于proto_http.c中定义，会在程序初始化时注册到全局变量中
static struct acl_kw_list acl_kws = {ILH, {
    //hdr没有声明pattern_head中的函数，会直接调用req.hdr 样本提取结构中的匹配，检验等函数
    "hdr",             "req.hdr",  PAT_MATCH_STR }, 
}
}

//smp_fetch_hdr用于从http从提取头部的函数，ARG2(0,STR,SINT)表示最少0个参数，最多两个参数，并且参数类型分别是长度，和整形，所以可以这么声明hdr(host, 10)，提取host前10个字符串
//一个参数的mask由一个32位的整形表示，其中第三位代表参数的最少个数个数，后面的25位每5位代表一个参数，5位最大代表31中类型，所以现在的内置函数最多支持5个参数，31中内置类型，可以参考include/types/arg.h 和include/proto/arg.h src/arg.c的实现
static struct sample_fetch_kw_list sample_fetch_keywords = {ILH, {
{ "req.hdr",         smp_fetch_hdr,            ARG2(0,STR,SINT), val_hdr, SMP_T_STR,  SMP_USE_HRQHV }
}

int cfg_parse_listen(const char *file, int linenum, char **args, int kwm):cfgparse.c:3193
    //遇到acl关键字，进入acl分支中
    parse_acl：acl.c:712
        parse_acl_expr: acl.c:134
            aclkw = find_acl_kw(args[0]); //查找acl关键字，示例中是"hdr"
            smp = calloc(1, sizeof(struct sample_expr)); //创建样本提取表达式
            LIST_INIT(&(smp->conv_exprs)); //样本提取可以有转换表达式，示例中的lower
            smp->fetch = aclkw->smp; //保存样本提取的表达式
            smp->arg_p = empty_arg_list; //参数列表
            for (arg = args[0]; *arg && *arg != '(' && *arg != ','; arg++); //参数列表是以“(”和“,”为分隔符
            
            endt = arg; 
            //找到参数列表的结束符)"
            if (*endt == '(') {
              /* look for the end of this term and skip the opening parenthesis */
              endt = ++arg;
              while (*endt && *endt != ')') 
                endt++;
              if (*endt != ')') {
                memprintf(err, "missing closing ')' after arguments to ACL keyword '%s'", aclkw->kw);
                goto out_free_smp;
              }    
            }
            
            //创建参数列表，这里很很有技巧，所有的参数都会存入arg_p中，列表类型，arg_mask就是上面说的那个32位的整数
            nbargs = make_arg_list(arg, endt - arg, smp->fetch->arg_mask, &smp->arg_p,
                           err, NULL, NULL, al); 
                
            //省略转换部分参数解析，例如language(es;fr;en)这个参数转换函数的参数解析
            ....
            
            //创建acl_expr
            expr = (struct acl_expr *)calloc(1, sizeof(*expr));
            //根据参数类型，设置匹配，解析，函数，上面的hdr没有定义自己的函数
            //所以用match_type在全局变量pat_pars_fcts中找
            expr->pat.parse  = aclkw->parse  ? aclkw->parse  : pat_parse_fcts[aclkw->match_type]; 
            ...
            
            //接下来解析-m str baidu.com netease.com等部分，把baidu.com存入arg中
            ...
            
            //会调用index函数，把baidu.com存入pat_expr的pattern_list，
            //这几个值是逻辑或的关系，后续判断acl是否匹配是，只要匹配一个值即可
            if (!pat_ref_add(ref, arg, NULL, err))
        
        //回到parse_acl函数，根据acl名字在这个proxy中查找已经存在的acl，
        //如果存在，直接通过链表连接起来即可，后续判断所有acl是逻辑与的关系
        if (*args[0])
          cur_acl = find_acl_by_name(args[0], known_acl);                                                                                   
        else
          cur_acl = NULL;
```

### use_backend 后端选择
```
    //配置解析
    cfg_parse_listen(const char *file, int linenum, char **args, int kwm):cfgparse.c:3803
        //先判断是 逻辑 “是” 或者 “非”
        if (strcmp(args[2], "if") == 0 || strcmp(args[2], "unless") == 0)
            //构建acl_cond
            build_acl_cond：acl.c:1056
              parse_acl_cond：acl.c:900
                //函数比较简单，创建acl_cond，指定pol字段到底是if还是unless
                //对于or字段前面的所有acl，每个acl创建一个acl_term来保存，acl_term的neg表示前面是否有!
                //对于or字段前面的所有acl，创建acl_term_suit连接起来
                //对于所有or作为分隔符的acl，判断时是逻辑与的关系，每个or就是一个acl_term_suit，通过acl_cond的suitel字段连接
                
        //每个use_backend通过一个switching_rule表示，通过proxy的switching_rules连接起来
        rule = (struct switching_rule *)calloc(1, sizeof(*rule));
        rule->cond = cond;
        rule->be.name = strdup(args[1]);
        LIST_INIT(&rule->list);
        LIST_ADDQ(&curproxy->switching_rules, &rule->list);
    
    //后端选择
    static int process_switching_rules(struct stream *s, struct channel *req, int an_bit):stream.c:1112
        //对于每个use_backend轮询处理，如果遇到合适的，直接匹配，
        //所以haproxy就是简单的根据声明顺序，优先匹配
        list_for_each_entry(rule, &fe->switching_rules, list) {
            acl_exec_cond：acl.c:1102
                //遍历acl_cond的每个suites，suites只要匹配一个即可
                list_for_each_entry(suite, &cond->suites, list) {
                    //遍历suites中所有的acl，需要所有的acl都满足
                    list_for_each_entry(term, &suite->terms, list) {
                        //每个acl都由多个acl_expr组成，遍历，需要全部满足
                        list_for_each_entry(expr, &acl->expr, list) {
                            //提取请求中需要做判断的字段
                            sample_process(px, sess, strm, opt, expr->smp, &smp)
                            //调用pattern_exec_match判断
                            acl_res |= pat2acl(pattern_exec_match(&expr->pat, &smp, 0));
    
    struct pattern *pattern_exec_match(struct pattern_head *head, struct sample *smp, int fill)
        //先进行转换，例如lower函数执行等
        if (!sample_convert(smp, head->expect_type))
        
        //对每组进行匹配？这个链表暂时没看出来什么意思
        list_for_each_entry(list, &head->head, list) {
            pat = head->match(smp, list->expr, fill);
            //对于PAT_MATCH_STR类型，调用
                pat_match_str：
                    //遍历每个参数，baidu.com，netease.com等，只要满足一个即可
                    list_for_each_entry(lst, &expr->patterns, list) {
            if (pat)
              return pat;
```

### map的使用
```
    acl 使用-f选项时，从指定文件中加载， -M选项时，从文件中读取key/value，没有指定时，单纯加载一个值
    
    acl 的convert部分可以使用map，例如：
    把host当做key，到文件/etc/test取值出来 去匹配
    文件内容：
    netease.com 100
    baidu.com 20
    
    acl格式如下：
    acl test hdr(host),map(/etc/test) gt 10
    
    http-request中也可以使用map
    del-map(<file name>) <key fmt> |
    set-map(<file name>) <key fmt> <value fmt>
    
    key fmt和 value fmt可以使用日志中的变量，例如%[src] 也可以是提取函数，%[res.hdr(X-Value)]等
    
    所有map文件都使用pat_ref结构保存起来，并且链接到一个全局变量中，例如在文件名字相同的情况下
    http-request使用set-map，会更新到acl中的map中
```

