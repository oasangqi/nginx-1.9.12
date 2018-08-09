
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


/* 创建一个链表，成员大小为size，数据节点成员个数为n */
ngx_list_t *
ngx_list_create(ngx_pool_t *pool, ngx_uint_t n, size_t size)
{
    ngx_list_t  *list;

    list = ngx_palloc(pool, sizeof(ngx_list_t));
    if (list == NULL) {
        return NULL;
    }

    if (ngx_list_init(list, pool, n, size) != NGX_OK) {
        return NULL;
    }

    return list;
}


/* 向链表中压入一个成员 */
void *
ngx_list_push(ngx_list_t *l)
{
    void             *elt;
    ngx_list_part_t  *last;

    last = l->last;

	/* 节点没有空间 */
    if (last->nelts == l->nalloc) {

        /* the last part is full, allocate a new list part */
		/* 新建一个数据节点 */
        last = ngx_palloc(l->pool, sizeof(ngx_list_part_t));
        if (last == NULL) {
            return NULL;
        }

        last->elts = ngx_palloc(l->pool, l->nalloc * l->size);
        if (last->elts == NULL) {
            return NULL;
        }

        last->nelts = 0;
        last->next = NULL;

		/* 数据节点加入链表 */
        l->last->next = last;
        l->last = last;
    }

	/* 为新成员分配空间 */
    elt = (char *) last->elts + l->size * last->nelts;
    last->nelts++;

    return elt;
}
