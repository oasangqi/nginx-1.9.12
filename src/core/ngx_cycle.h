
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CYCLE_H_INCLUDED_
#define _NGX_CYCLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef NGX_CYCLE_POOL_SIZE
#define NGX_CYCLE_POOL_SIZE     NGX_DEFAULT_POOL_SIZE
#endif


#define NGX_DEBUG_POINTS_STOP   1
#define NGX_DEBUG_POINTS_ABORT  2


typedef struct ngx_shm_zone_s  ngx_shm_zone_t;

typedef ngx_int_t (*ngx_shm_zone_init_pt) (ngx_shm_zone_t *zone, void *data);

struct ngx_shm_zone_s {
    void                     *data;
    ngx_shm_t                 shm;
    ngx_shm_zone_init_pt      init;
    void                     *tag;
    ngx_uint_t                noreuse;  /* unsigned  noreuse:1; */
};


/*
 *  对应nginx进程的一次启动过程。不论是新的nginx、reload还是热替换，nginx都会创建一个新的cycle
 *  */
struct ngx_cycle_s {
	/* 各模块的配置项，void*数组，ngx_max_module个元素，事件模块成员为void***  */
    void                  ****conf_ctx;
    ngx_pool_t               *pool;

    ngx_log_t                *log; /* 未执行ngx_init_cycle前使用的日志对象 */
    ngx_log_t                 new_log;

    ngx_uint_t                log_use_stderr;  /* unsigned  log_use_stderr:1; */

    ngx_connection_t        **files;
    ngx_connection_t         *free_connections; /* 空闲连接池 */
    ngx_uint_t                free_connection_n;/* 空闲连接池大小 */

    ngx_module_t            **modules; /* 模块(内存池中分配ngx_max_module个元素) */
    ngx_uint_t                modules_n; /* 模块个数 */
    ngx_uint_t                modules_used;    /* unsigned  modules_used:1; */

    ngx_queue_t               reusable_connections_queue; /* 双向链表容器，元素类型是ngx_connection_t结构体，表示可重复使用的连接队列，连接不够用时强制断开该队列中的一些连接 */

    ngx_array_t               listening; /* 数组成员为ngx_listening_t类型 */
    ngx_array_t               paths; /* 数组成员为ngx_path_t类型，代表nginx所有要操作的目录。如果有目录不存在，就会试图创建，而创建目录失败就会导致nginx启动失败 */
    ngx_array_t               config_dump; /* 数组成员为ngx_conf_dump_t类型，,ngx_init_cycle中初始1个成员 */
    ngx_list_t                open_files; /* 链表成员为ngx_open_file_t类型 */
    ngx_list_t                shared_memory; /* 链表成员为ngx_shm_zone_t类型 */

    ngx_uint_t                connection_n; /* 当前进程所有连接对象、读事件、写事件的个数 */
    ngx_uint_t                files_n;

    ngx_connection_t         *connections; /* 当前进程所有连接对象，初始化参照ngx_event_process_init */
    ngx_event_t              *read_events; /* 当前进程所有读事件 */
    ngx_event_t              *write_events; /* 当前进程所有写事件 */

    ngx_cycle_t              *old_cycle; /* ngx_init_cycle之前的cycle */

    ngx_str_t                 conf_file; /*配置文件相对安装目录路径 */
    ngx_str_t                 conf_param; /* 处理配置文件时，需要进行特殊处理的参数，-g指定 */
    ngx_str_t                 conf_prefix; /* 配置文件所在目录路径 */
    ngx_str_t                 prefix; /* 安装目录路径 */
    ngx_str_t                 lock_file;
    ngx_str_t                 hostname;
};


typedef struct {
     ngx_flag_t               daemon;
     ngx_flag_t               master;

     ngx_msec_t               timer_resolution;

     ngx_int_t                worker_processes; /* worker进程个数 */
     ngx_int_t                debug_points;

     ngx_int_t                rlimit_nofile; /* 可打开fd个数 */
     off_t                    rlimit_core; /* core文件大小 */

     int                      priority; /* 进程优先级 */

     ngx_uint_t               cpu_affinity_auto; /* 是否自动绑定CPU */
     ngx_uint_t               cpu_affinity_n; /* 设置亲缘性的CPU个数 */
     ngx_cpuset_t            *cpu_affinity; /* 绑定的CPU集合 */

     char                    *username;
     ngx_uid_t                user; /* worker进程uid */
     ngx_gid_t                group;/* worker进程gid */

     ngx_str_t                working_directory; /* 工作目录 */
     ngx_str_t                lock_file;

     ngx_str_t                pid;
     ngx_str_t                oldpid;

     ngx_array_t              env;
     char                   **environment;
} ngx_core_conf_t; /* worker进程的配置 */


#define ngx_is_init_cycle(cycle)  (cycle->conf_ctx == NULL)


ngx_cycle_t *ngx_init_cycle(ngx_cycle_t *old_cycle);
ngx_int_t ngx_create_pidfile(ngx_str_t *name, ngx_log_t *log);
void ngx_delete_pidfile(ngx_cycle_t *cycle);
ngx_int_t ngx_signal_process(ngx_cycle_t *cycle, char *sig);
void ngx_reopen_files(ngx_cycle_t *cycle, ngx_uid_t user);
char **ngx_set_environment(ngx_cycle_t *cycle, ngx_uint_t *last);
ngx_pid_t ngx_exec_new_binary(ngx_cycle_t *cycle, char *const *argv);
ngx_cpuset_t *ngx_get_cpu_affinity(ngx_uint_t n);
ngx_shm_zone_t *ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name,
    size_t size, void *tag);


extern volatile ngx_cycle_t  *ngx_cycle;
extern ngx_array_t            ngx_old_cycles;
extern ngx_module_t           ngx_core_module;
extern ngx_uint_t             ngx_test_config;
extern ngx_uint_t             ngx_dump_config;
extern ngx_uint_t             ngx_quiet_mode;


#endif /* _NGX_CYCLE_H_INCLUDED_ */
