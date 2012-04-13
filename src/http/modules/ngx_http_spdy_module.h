/*
 * Copyright (c) Eugene Pimenov
 */

#ifndef _NGX_HTTP_SPDY_H_INCLUDED_
#define _NGX_HTTP_SPDY_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <zlib.h>

#define NGX_SPDY_MODULE 0x59445053

#define NGX_SPDY_PROTOCOL_ERROR         1
#define NGX_SPDY_INVALID_STREAM         1
#define NGX_SPDY_REFUSED_STREAM         1
#define NGX_SPDY_UNSUPPORTED_VERSION    1
#define NGX_SPDY_CANCEL                 1
#define NGX_SPDY_INTERNAL_ERROR         1
#define NGX_SPDY_FLOW_CONTROL_ERROR     1
#define NGX_SPDY_FLAGS_FIN              1


typedef struct {
    union {
        struct {
            unsigned  control:1;
            unsigned  version:15;
            unsigned  type:16;
        } control_frame;
        struct {
            unsigned control:1;
            unsigned stream_id:31;
        } data_frame;
    };
    unsigned  flags:8;
    unsigned  length:24;
} ngx_http_spdy_frame_header_t;

typedef struct {
    ngx_flag_t                      enable;
    u_char                         *file;
    ngx_uint_t                      line;
} ngx_http_spdy_srv_conf_t;

typedef struct {
    ngx_queue_t         queue;
    ngx_http_request_t *request;
    uint32_t            stream_id;
    uint8_t             priority;
} ngx_http_spdy_stream_t;

typedef struct ngx_http_spdy_request_s {
    uint32_t                      signature;         /* "SPDY" */
    ngx_connection_t             *connection;

    ngx_http_spdy_frame_header_t  current_frame;
    ngx_buf_t                    *buffer_r;
    ngx_buf_t                    *buffer_w;

    /* This is the original request. We do not use it as HTTP request
       just stash it here, so the pool won't be deallocated and SSL closed */
    ngx_http_request_t           *fake_request;

    z_stream                      zstream_in;
    z_stream                      zstream_out;

    ngx_queue_t                  *streams;

    int32_t                       ping_id;
    int32_t                       last_stream_id;

} ngx_http_spdy_request_t;

extern ngx_module_t ngx_http_spdy_module;

void ngx_http_spdy_init_connection(ngx_connection_t *connection);
void ngx_http_spdy_process_frame(ngx_event_t *rev);
ngx_int_t ngx_http_spy_send_syn_reply(ngx_http_request_t *hr, ngx_buf_t *b);

typedef void (*ngx_http_spdy_control_frame_handler_t)(ngx_http_spdy_request_t *r);

#endif
