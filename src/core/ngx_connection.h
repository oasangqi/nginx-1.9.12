
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CONNECTION_H_INCLUDED_
#define _NGX_CONNECTION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_listening_s  ngx_listening_t;

/* 对应侦听的端口 */
struct ngx_listening_s {
    ngx_socket_t        fd;

    struct sockaddr    *sockaddr; /* fd绑定的地址 */
    socklen_t           socklen;    /* size of sockaddr */
    size_t              addr_text_max_len; /* addr_text的最大长度 */
    ngx_str_t           addr_text; /* IP地址字符串 */

    int                 type; /* 套接字类型，例如SOCK_STREAM */

    int                 backlog; /* listen的队列大小 */
    int                 rcvbuf; /*内核中对应该fd的接收缓冲区大小 */
    int                 sndbuf; /*内核中对应该fd的发送缓冲区大小 */
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                 keepidle; /* 开始首次KeepAlive探测前的TCP空闭时间 */
    int                 keepintvl; /* 两次KeepAlive探测间的时间间隔 */
    int                 keepcnt; /* 判定断开前的KeepAlive探测次数 */
#endif

    /* handler of accepted connection */
    ngx_connection_handler_pt   handler; /* 新的TCP连接建立成功后的回调方法 */

	/* 实际上框架并不适用servers 指针，它更多是作为一个保留指针，目前主要用于HTTP或者mail等模块，用户保存当前监听端口对应着的所有主机名 */
    void               *servers;  /* array of ngx_http_in_addr_t, for example */

    ngx_log_t           log;
    ngx_log_t          *logp;

    size_t              pool_size; /* 如果为新的TCP连接创建内存池，则内存池的初始大小应该是pool_size */
    /* should be here because of the AcceptEx() preread */
    size_t              post_accept_buffer_size;
    /* should be here because of the deferred accept */
    ngx_msec_t          post_accept_timeout; /* 超过该时间没有收到数据，则内核丢弃连接??? */

	/* 前一个ngx_listening_t结构，多个ngx_listening_t结构体之间由previous指针组成单链表 */
    ngx_listening_t    *previous;
    ngx_connection_t   *connection; /* 当前fd对应的ngx_connection_t结构 */

    ngx_uint_t          worker;

	/* 为1表示在当前监听句柄有效，且执行ngx_init_cycle时不关闭监听端口，
	 * 为0正常关闭。该标志位框架代码会自动设置 */
    unsigned            open:1;
	/* 为1表示使用已经有的ngx_cycle_t来初始化新的ngx_cycle_t结构体时，不关闭原先打开的监听端口，这对运行中升级程序很有用，
	 * 为0表示正常关闭曾经打开的监听端口。该标志位框架代码会自动设置，参见ngx_init_cycle方法 */
    unsigned            remain:1;
	/* 为1表示跳过设置当前ngx_listening_t结构体中的套接字，
	 * 为0正常初始化套接字，参照ngx_open_listening_sockets */
    unsigned            ignore:1;

	/* 目前保留 */
    unsigned            bound:1;       /* already bound */
	/* 为1表示来自前一个进程，一般会保留之前已经设置好的套接字，不做改变 */
    unsigned            inherited:1;   /* inherited from previous process */
	/* 目前保留 */
    unsigned            nonblocking_accept:1;
	/* 为1表示当前结构体中的套接字已经监听 */
    unsigned            listen:1;
	/* 目前保留 */
    unsigned            nonblocking:1;
    unsigned            shared:1;    /* shared between threads or processes */
	/* 为1表示nginx会将网络地址转变为字符串形式的地址，参照ngx_event_accept */
    unsigned            addr_ntop:1;

#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned            ipv6only:1;
#endif
#if (NGX_HAVE_REUSEPORT)
    unsigned            reuseport:1;
    unsigned            add_reuseport:1;
#endif
    unsigned            keepalive:2; /* 是否使用TCP的keepalive探测对端是否断开??? */

#if (NGX_HAVE_DEFERRED_ACCEPT)
	/* 延迟accept，收到数据时才accept，减少一个epoll_ctl、epoll_wait开销 */
    unsigned            deferred_accept:1;
    unsigned            delete_deferred:1;
    unsigned            add_deferred:1;
#ifdef SO_ACCEPTFILTER
    char               *accept_filter;
#endif
#endif
#if (NGX_HAVE_SETFIB)
    int                 setfib;
#endif

#if (NGX_HAVE_TCP_FASTOPEN)
    int                 fastopen;
#endif

};


typedef enum {
     NGX_ERROR_ALERT = 0,
     NGX_ERROR_ERR,
     NGX_ERROR_INFO,
     NGX_ERROR_IGNORE_ECONNRESET,
     NGX_ERROR_IGNORE_EINVAL
} ngx_connection_log_error_e;


typedef enum {
     NGX_TCP_NODELAY_UNSET = 0,
     NGX_TCP_NODELAY_SET,
     NGX_TCP_NODELAY_DISABLED
} ngx_connection_tcp_nodelay_e;


typedef enum {
     NGX_TCP_NOPUSH_UNSET = 0,
     NGX_TCP_NOPUSH_SET,
     NGX_TCP_NOPUSH_DISABLED
} ngx_connection_tcp_nopush_e;


#define NGX_LOWLEVEL_BUFFERED  0x0f
#define NGX_SSL_BUFFERED       0x01
#define NGX_HTTP_V2_BUFFERED   0x02


struct ngx_connection_s {
    void               *data;
    ngx_event_t        *read;
    ngx_event_t        *write;

    ngx_socket_t        fd;

    ngx_recv_pt         recv;
    ngx_send_pt         send;
    ngx_recv_chain_pt   recv_chain;
    ngx_send_chain_pt   send_chain;

    ngx_listening_t    *listening;

    off_t               sent;

    ngx_log_t          *log;

    ngx_pool_t         *pool;

    struct sockaddr    *sockaddr;
    socklen_t           socklen;
    ngx_str_t           addr_text;

    ngx_str_t           proxy_protocol_addr;

#if (NGX_SSL)
    ngx_ssl_connection_t  *ssl;
#endif

    struct sockaddr    *local_sockaddr;
    socklen_t           local_socklen;

    ngx_buf_t          *buffer;

    ngx_queue_t         queue;

    ngx_atomic_uint_t   number;

    ngx_uint_t          requests;

    unsigned            buffered:8;

    unsigned            log_error:3;     /* ngx_connection_log_error_e */

    unsigned            unexpected_eof:1;
    unsigned            timedout:1;
    unsigned            error:1;
    unsigned            destroyed:1;

    unsigned            idle:1;
    unsigned            reusable:1; /* 连接可重用 */
    unsigned            close:1; /* 连接已断开，强制断开连接时先标记再调用handler进行处理 */

    unsigned            sendfile:1;
    unsigned            sndlowat:1;
    unsigned            tcp_nodelay:2;   /* ngx_connection_tcp_nodelay_e */
    unsigned            tcp_nopush:2;    /* ngx_connection_tcp_nopush_e */

    unsigned            need_last_buf:1;

#if (NGX_HAVE_IOCP)
    unsigned            accept_context_updated:1;
#endif

#if (NGX_HAVE_AIO_SENDFILE)
    unsigned            busy_count:2;
#endif

#if (NGX_THREADS)
    ngx_thread_task_t  *sendfile_task;
#endif
};


#define ngx_set_connection_log(c, l)                                         \
                                                                             \
    c->log->file = l->file;                                                  \
    c->log->next = l->next;                                                  \
    c->log->writer = l->writer;                                              \
    c->log->wdata = l->wdata;                                                \
    if (!(c->log->log_level & NGX_LOG_DEBUG_CONNECTION)) {                   \
        c->log->log_level = l->log_level;                                    \
    }


ngx_listening_t *ngx_create_listening(ngx_conf_t *cf, void *sockaddr,
    socklen_t socklen);
ngx_int_t ngx_clone_listening(ngx_conf_t *cf, ngx_listening_t *ls);
ngx_int_t ngx_set_inherited_sockets(ngx_cycle_t *cycle);
ngx_int_t ngx_open_listening_sockets(ngx_cycle_t *cycle);
void ngx_configure_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_connection(ngx_connection_t *c);
void ngx_close_idle_connections(ngx_cycle_t *cycle);
ngx_int_t ngx_connection_local_sockaddr(ngx_connection_t *c, ngx_str_t *s,
    ngx_uint_t port);
ngx_int_t ngx_connection_error(ngx_connection_t *c, ngx_err_t err, char *text);

ngx_connection_t *ngx_get_connection(ngx_socket_t s, ngx_log_t *log);
void ngx_free_connection(ngx_connection_t *c);

void ngx_reusable_connection(ngx_connection_t *c, ngx_uint_t reusable);

#endif /* _NGX_CONNECTION_H_INCLUDED_ */
