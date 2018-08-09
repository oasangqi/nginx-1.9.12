
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


ngx_queue_t  ngx_posted_accept_events; /* 延后处理的新事件队列 */
ngx_queue_t  ngx_posted_events; /* 延后处理的普通事件队列 */


void
ngx_event_process_posted(ngx_cycle_t *cycle, ngx_queue_t *posted)
{
    ngx_queue_t  *q;
    ngx_event_t  *ev;

	/* 遍历队列 */
    while (!ngx_queue_empty(posted)) {

		/* 从队列头取出事件 */
        q = ngx_queue_head(posted);
        ev = ngx_queue_data(q, ngx_event_t, queue);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                      "posted event %p", ev);

		/* 移除该事件 */
        ngx_delete_posted_event(ev);

		/* 执行事件对应的回调 */
        ev->handler(ev);
    }
}
