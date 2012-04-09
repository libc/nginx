#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_spdy_module.h>

#define BE_LOAD_16(data) ((data)[1] | ((data)[0] << 8))
#define BE_LOAD_32(data) ((data)[3] | ((data)[2] << 8) | ((data)[1] << 16) | ((data)[0] << 24))
#define BE_STORE_16(target, source) do {  \
    (target)[1] = (source) & 0xFF;        \
    (target)[0] = ((source) >> 8) & 0xFF; \
} while(0);
#define BE_STORE_32(target, source) do {   \
    (target)[3] = (source) & 0xFF;         \
    (target)[2] = ((source) >> 8) & 0xFF;  \
    (target)[1] = ((source) >> 16) & 0xFF; \
    (target)[0] = ((source) >> 24) & 0xFF; \
} while(0);
#define NGX_SPDY_DATA_FRAME_SIZE 16384

static void *ngx_http_spdy_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_spdy_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);
static int ngx_ssl_next_protos_advertised_callback(ngx_ssl_conn_t *ssl_conn,
    const unsigned char **data, unsigned int *len, void *arg);
static char *ngx_http_spdy_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void ngx_http_spdy_request_handler(ngx_event_t *ev);

static void ngx_http_spdy_control_frame_noop(ngx_http_spdy_request_t *r);
static void ngx_http_spdy_control_frame_syn_stream(ngx_http_spdy_request_t *r);

static ngx_command_t  ngx_http_spdy_commands[] = {
    { ngx_string("spdy"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_http_spdy_enable,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_spdy_srv_conf_t, enable),
      NULL },
    ngx_null_command
};

static ngx_http_module_t ngx_http_spdy_module_ctx = {
    NULL,                                 /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_spdy_create_srv_conf,         /* create server configuration */
    ngx_http_spdy_merge_srv_conf,          /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};

ngx_module_t  ngx_http_spdy_module = {
    NGX_MODULE_V1,
    &ngx_http_spdy_module_ctx,             /* module context */
    ngx_http_spdy_commands,                /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_http_spdy_control_frame_handler_t ngx_http_spdy_control_frame_handlers[] = {
    ngx_http_spdy_control_frame_noop,           /* nothing */
    ngx_http_spdy_control_frame_syn_stream,     /* SYN_STREAM */
    ngx_http_spdy_control_frame_noop,           /* SYN_REPLY */
    ngx_http_spdy_control_frame_noop,           /* RST_STREAM */
    ngx_http_spdy_control_frame_noop,           /* SETTINGS */
    ngx_http_spdy_control_frame_noop,           /* NOOP */
    ngx_http_spdy_control_frame_noop,           /* PING */
    ngx_http_spdy_control_frame_noop,           /* GOAWAY */
    ngx_http_spdy_control_frame_noop,           /* HEADERS */
};

static const char * ngx_http_sdpy_zlib_dictionary =
    "optionsgetheadpostputdeletetraceacceptaccept-charsetaccept-encodingaccept-"
    "languageauthorizationexpectfromhostif-modified-sinceif-matchif-none-matchi"
    "f-rangeif-unmodifiedsincemax-forwardsproxy-authorizationrangerefererteuser"
    "-agent10010120020120220320420520630030130230330430530630740040140240340440"
    "5406407408409410411412413414415416417500501502503504505accept-rangesageeta"
    "glocationproxy-authenticatepublicretry-afterservervarywarningwww-authentic"
    "ateallowcontent-basecontent-encodingcache-controlconnectiondatetrailertran"
    "sfer-encodingupgradeviawarningcontent-languagecontent-lengthcontent-locati"
    "oncontent-md5content-rangecontent-typeetagexpireslast-modifiedset-cookieMo"
    "ndayTuesdayWednesdayThursdayFridaySaturdaySundayJanFebMarAprMayJunJulAugSe"
    "pOctNovDecchunkedtext/htmlimage/pngimage/jpgimage/gifapplication/xmlapplic"
    "ation/xhtmltext/plainpublicmax-agecharset=iso-8859-1utf-8gzipdeflateHTTP/1"
    ".1statusversionurl";

static void *
ngx_http_spdy_create_srv_conf(ngx_conf_t *cf)
{
  ngx_http_spdy_srv_conf_t *sscf;

  sscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_spdy_srv_conf_t));
  if (sscf == NULL) {
    return NULL;
  }

  sscf->enable = NGX_CONF_UNSET;

  return sscf;
}

static char *
ngx_http_spdy_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_spdy_srv_conf_t *prev = parent;
    ngx_http_spdy_srv_conf_t *conf = child;
    ngx_http_ssl_srv_conf_t  *ssl_conf;

    if (conf->enable == NGX_CONF_UNSET) {
        if (prev->enable == NGX_CONF_UNSET) {
            conf->enable = 0;
        } else {
            conf->enable = prev->enable;
            conf->file = prev->file;
            conf->line = prev->line;
        }
    }

    ssl_conf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);
    if (ssl_conf == NULL || ssl_conf->enable == NGX_CONF_UNSET) {
        ngx_log_error(NGX_LOG_WARN, cf->log, 0,
            "trying to enable SPDY with disabled SSL, the universe is not"
            "happy.");
        return NGX_CONF_ERROR;
    } else if (conf->enable) {
        SSL_CTX_set_next_protos_advertised_cb(ssl_conf->ssl.ctx, ngx_ssl_next_protos_advertised_callback, NULL);
    }
    return NGX_CONF_OK;
}

static char *
ngx_http_spdy_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_spdy_srv_conf_t *sscf = conf;

    char  *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    sscf->file = cf->conf_file->file.name.data;
    sscf->line = cf->conf_file->line;

    return NGX_CONF_OK;
}

#define NPN_SUPPORTED_PROTOCOLS "\6spdy/2\x8http/1.1\x8http/1.0"


static int
ngx_ssl_next_protos_advertised_callback(ngx_ssl_conn_t *ssl_conn, const unsigned char **data, unsigned int *len, void *arg)
{
    *data = (const unsigned char*)NPN_SUPPORTED_PROTOCOLS;
    *len  = sizeof(NPN_SUPPORTED_PROTOCOLS)-1;
    return SSL_TLSEXT_ERR_OK;
}

void
ngx_http_spdy_init_connection(ngx_connection_t *connection)
{
    ngx_http_spdy_request_t *r;

    r = ngx_pcalloc(connection->pool, sizeof(ngx_http_spdy_request_t));
    r->signature = NGX_SPDY_MODULE; /* SPDY */

    r->connection = connection;
    r->fake_request = connection->data;
    r->buffer_r = ngx_create_temp_buf(connection->pool, 4096);
    r->buffer_w = ngx_create_temp_buf(connection->pool, 256);
    r->streams = ngx_radix_tree_create(connection->pool, -1);

    inflateInit(&r->zstream_in);
    deflateInit(&r->zstream_out, 9);

    connection->data = r;

    connection->write->handler = ngx_http_spdy_request_handler;
}

static void
ngx_prepare_next_frame(ngx_http_spdy_request_t *r)
{
    r->buffer_r->last = r->buffer_r->start;
    r->buffer_r->pos = r->buffer_r->start;
    r->connection->read->handler = ngx_http_spdy_process_frame;
}

static ngx_int_t
ngx_http_spdy_send_rst_stream(ngx_http_spdy_request_t *r, uint32_t stream_id, uint32_t error)
{
    printf("stream_id: %d, error: %d\n", stream_id, error);
    BE_STORE_16(r->buffer_w->start, 2);     /* Version */
    r->buffer_w->start[0] |= 0x80;          /* Control flag */
    BE_STORE_16(&r->buffer_w->start[2], 3); /* RST */
    BE_STORE_32(&r->buffer_w->start[4], 8); /* Flags and length */

    BE_STORE_32(&r->buffer_w->start[8], stream_id);
    BE_STORE_32(&r->buffer_w->start[12], error);
    return r->connection->send(r->connection, r->buffer_w->start, 16);
}

ngx_int_t
ngx_http_spy_send_syn_reply(ngx_http_request_t *hr, ngx_buf_t *b)
{
    ngx_buf_t               *b_w;
    ngx_int_t                result;
    ngx_http_spdy_request_t *r;
    int                      zlib_result;

    b_w = ngx_create_temp_buf(hr->pool, b->last - b->pos + 14);

    if (b_w == NULL) {
        return NGX_ERROR;
    }

    BE_STORE_16(b_w->start, 2);     /* Version */
    b_w->start[0] |= 0x80;          /* Control flag */
    BE_STORE_16(&b_w->start[2], 2); /* SYN_REPLY */
    BE_STORE_32(&b_w->start[8], hr->stream_id);

    r = hr->spdy_request;

    r->zstream_out.next_in = b->pos;
    r->zstream_out.avail_in = b->last - b->pos;
    r->zstream_out.next_out = b_w->start + 14;
    r->zstream_out.avail_out = b_w->end - b_w->start - 14;

    zlib_result = deflate(&r->zstream_out, Z_SYNC_FLUSH);
    if (zlib_result != Z_OK) {
        ngx_http_spdy_send_rst_stream(r, hr->stream_id, NGX_SPDY_INTERNAL_ERROR);
        return NGX_ERROR;
    }

    BE_STORE_32(&b_w->start[4], r->zstream_out.next_out - b_w->start - 8);
    result = r->connection->send(r->connection, b_w->start, r->zstream_out.next_out - b_w->start);

    ngx_pfree(hr->pool, b_w);

    if (result == NGX_AGAIN || result == NGX_ERROR) {
        return result;
    }

    return NGX_OK;
}

static void
ngx_http_spdy_control_frame_noop(ngx_http_spdy_request_t *r)
{
}

static ssize_t
ngx_http_spdy_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    printf("spdy recv\n");
    return NGX_AGAIN;
}

static ssize_t
ngx_http_spdy_recv_chain(ngx_connection_t *c, ngx_chain_t *cl)
{
    printf("spdy recv chain\n");
    return NGX_AGAIN;
}

static ssize_t
ngx_http_spdy_send_with_flags(ngx_connection_t *c, u_char *data, size_t size, uint8_t flags)
{
    ngx_http_request_t      *hr;
    ngx_http_spdy_request_t *r;
    ngx_int_t                result;

    hr = c->data;
    r = hr->spdy_request;

    BE_STORE_32(r->buffer_w->start, hr->stream_id);
    BE_STORE_32(&r->buffer_w->start[4], size);
    r->buffer_w->start[4] = flags;

    result = r->connection->send(r->connection, r->buffer_w->start, 8);

    if (result == NGX_ERROR || result == NGX_AGAIN) {
        return result;
    }

    return r->connection->send(r->connection, data, size);
}

static ssize_t
ngx_http_spdy_send(ngx_connection_t *c, u_char *data, size_t size)
{
    printf("send\n");
    return ngx_http_spdy_send_with_flags(c, data, size, 0);
}

static ngx_chain_t *
ngx_http_spdy_send_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    off_t sent, len, n;

    sent = 0;
    if (limit == 0) {
        limit = NGX_SPDY_DATA_FRAME_SIZE;
    }

    for (;sent < limit;) {
        if (in == NULL) {
            break;
        }

        if (ngx_buf_special(in->buf)) {
            in = in->next;
            continue;
        }

        len = in->buf->last - in->buf->pos;

        if (len > limit) {
            len = limit;
        }
        n = ngx_http_spdy_send_with_flags(c, in->buf->pos, len, in->buf->last_buf ? NGX_SPDY_FLAGS_FIN : 0);

        if (n == NGX_ERROR) {
            return NGX_CHAIN_ERROR;
        }

        if (n == NGX_AGAIN) {
            return in;
        }

        if (n != len) {
            printf("PANIC!!!!");
            return in;
        }

        in->buf->pos += n;
        sent += n;
        limit -= n;

        if (in->buf->pos == in->buf->last) {
            in = in->next;
        }
    }

    return in;
}

static void
ngx_close_accepted_connection(ngx_connection_t *c)
{
    ngx_socket_t  fd;

    ngx_free_connection(c);

    fd = c->fd;
    c->fd = (ngx_socket_t) -1;

    if (fd != -1 && ngx_close_socket(fd) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
                      ngx_close_socket_n " failed");
    }

    if (c->pool) {
        ngx_destroy_pool(c->pool);
    }
}

static ngx_connection_t *
ngx_http_spdy_create_connection(ngx_http_spdy_request_t *r)
{
    ngx_connection_t          *c;
    ngx_http_core_srv_conf_t  *cscf;
    socklen_t                  socklen;
    ngx_log_t                 *log;

    c = ngx_get_connection(-1, r->connection->log);
    cscf = r->fake_request->srv_conf[0];

    c->pool = ngx_create_pool(cscf->connection_pool_size, r->connection->log);
    if (c->pool == NULL) {
        ngx_close_accepted_connection(c);
        return NULL;
    }

    socklen = NGX_SOCKADDRLEN;

    c->sockaddr = ngx_palloc(c->pool, socklen);
    if (c->sockaddr == NULL) {
        ngx_close_accepted_connection(c);
        return NULL;
    }
    c->socklen = socklen;

    ngx_memcpy(c->sockaddr, r->connection->sockaddr, socklen);

    log = ngx_palloc(c->pool, sizeof(ngx_log_t));
    if (log == NULL) {
        ngx_close_accepted_connection(c);
        return NULL;
    }

    *log = *r->connection->log;

    c->recv = ngx_http_spdy_recv;
    c->recv_chain = ngx_http_spdy_recv_chain;
    c->send = ngx_http_spdy_send;
    c->send_chain = ngx_http_spdy_send_chain;

    c->listening = r->connection->listening;
    c->local_sockaddr = r->connection->local_sockaddr;
    c->read->log = log;
    c->write->log = log;
    /* Don't let upstream mess with our fd */
    c->tcp_nodelay = NGX_TCP_NODELAY_DISABLED;
    c->unclosable = 1;

    return c;
}

static ngx_http_spdy_stream_t *
ngx_http_spdy_create_stream(ngx_http_spdy_request_t *r, uint32_t stream_id, uint8_t priority)
{
    ngx_http_request_t     *hr;
    ngx_http_spdy_stream_t *s;
    ngx_connection_t       *c;
    uintptr_t               ptr;

    ptr = ngx_radix32tree_find(r->streams, stream_id);
    if (ptr != NGX_RADIX_NO_VALUE) {
        ngx_http_spdy_send_rst_stream(r, stream_id, NGX_SPDY_PROTOCOL_ERROR);
        return NULL;
    }
    s = (ngx_http_spdy_stream_t*)ptr;

    c = ngx_http_spdy_create_connection(r);

    hr = ngx_http_init_request_non_destructive(c->read);
    if (hr == NULL) {
        ngx_http_spdy_send_rst_stream(r, stream_id, NGX_SPDY_INTERNAL_ERROR);
        return NULL;
    }
    hr->spdy = 1;
    hr->stream_id = stream_id;
    hr->spdy_request = r;
    c->data = hr;

    s = ngx_pcalloc(r->connection->pool, sizeof(ngx_http_spdy_stream_t));
    s->stream_id = stream_id;
    s->request = hr;
    s->priority = priority;

    ngx_radix32tree_insert(r->streams, stream_id, (uint32_t)(-1), (uintptr_t)s);

    return s;
}

static int
ngx_http_spdy_unpack_headers(ngx_http_spdy_stream_t *s, ngx_http_spdy_request_t *r)
{
    ngx_http_request_t *hr;
    ngx_buf_t          *headers;
    int                 rv;
    int                 zlib_result;

    hr = s->request;
    headers = hr->header_in;

    r->zstream_in.next_in = r->buffer_r->pos;
    r->zstream_in.avail_in = r->buffer_r->last - r->buffer_r->pos;
    r->zstream_in.next_out = headers->start;
    r->zstream_in.avail_out = headers->end - headers->start;

    zlib_result = inflate(&r->zstream_in, Z_SYNC_FLUSH);
    if (zlib_result == Z_NEED_DICT) {
        inflateSetDictionary(&r->zstream_in, (const u_char*)ngx_http_sdpy_zlib_dictionary, strlen(ngx_http_sdpy_zlib_dictionary)+1);
        zlib_result = inflate(&r->zstream_in, Z_SYNC_FLUSH);
    }

    if (zlib_result != Z_OK) {
        return NGX_ERROR;
    }

    if (r->zstream_in.avail_in > 0) {
        headers->last = r->zstream_in.next_out;

        rv = ngx_http_alloc_large_header_buffer(hr, 0);
        if (rv != NGX_OK) {
            return NGX_ERROR;
        }

        headers = hr->header_in;
        r->zstream_in.next_out = headers->last;
        r->zstream_in.avail_out = headers->last - headers->end;

        zlib_result = inflate(&r->zstream_in, Z_SYNC_FLUSH);
        if (zlib_result != Z_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static void
ngx_http_spdy_parse_headers(ngx_http_spdy_stream_t *s, ngx_http_spdy_request_t *r)
{
    ngx_http_request_t         *hr;
    ngx_buf_t                  *headers;
    ngx_table_elt_t            *h;
    ngx_http_header_t          *hh;
    uint16_t                    n, k, i;
    ngx_http_core_main_conf_t  *cmcf;

    if (ngx_http_spdy_unpack_headers(s, r) != NGX_OK) {
        ngx_http_spdy_send_rst_stream(r, s->stream_id, NGX_SPDY_PROTOCOL_ERROR);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                       "error unpacking headers for stream %d", s->stream_id);
        return;
    }

    hr = s->request;
    headers = hr->header_in;

    if (ngx_list_init(&hr->headers_in.headers, hr->pool, 20,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        ngx_http_spdy_send_rst_stream(r, s->stream_id, NGX_SPDY_INTERNAL_ERROR);
        return;
    }


    if (ngx_array_init(&hr->headers_in.cookies, hr->pool, 2,
                       sizeof(ngx_table_elt_t *))
        != NGX_OK)
    {
        ngx_http_spdy_send_rst_stream(r, s->stream_id, NGX_SPDY_INTERNAL_ERROR);
        return;
    }

    /* Phew, the headers are unpacked now! */
    n = BE_LOAD_16(headers->pos);
    headers->pos += 2;

    if (n > 0 && headers->last - headers->end == 0) {
        /* We don't have a byte at the end of the buffer, so we
            cannot sneak \0 in. This is very sad. */
        ngx_http_spdy_send_rst_stream(r, s->stream_id, NGX_SPDY_INTERNAL_ERROR);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                       "headers are too large for stream %d", s->stream_id);
        return;
    }

    cmcf = ngx_http_get_module_main_conf(hr, ngx_http_core_module);

    k = BE_LOAD_16(headers->pos);
    for(i = 0; i < n; ++i) {
        h = ngx_list_push(&hr->headers_in.headers);

        h->key.len = k;
        headers->pos += 2;
        h->key.data = headers->pos;
        headers->pos += k;

        k = BE_LOAD_16(headers->pos);
        headers->pos[0] = 0;
        headers->pos += 2;

        h->value.len = k;
        h->value.data = headers->pos;
        headers->pos += k;
        k = BE_LOAD_16(headers->pos);
        headers->pos[0] = 0;

        h->lowcase_key = ngx_pnalloc(hr->pool, h->key.len);
        if (h->lowcase_key == NULL) {
            ngx_http_spdy_send_rst_stream(r, s->stream_id, NGX_SPDY_INTERNAL_ERROR);
            return;
        }

        /* header name in SPDY must be lower case */
        ngx_memcpy(h->lowcase_key, h->key.data, h->key.len);

        h->hash = ngx_hash_key(h->lowcase_key, h->key.len);

        hh = ngx_hash_find(&cmcf->headers_in_hash, h->hash,
                           h->lowcase_key, h->key.len);

        if (hh && hh->handler(hr, h, hh->offset) != NGX_OK) {
            ngx_http_spdy_send_rst_stream(r, s->stream_id, NGX_SPDY_INTERNAL_ERROR);
            return;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "spdy header: \"%V: %V\"",
                       &h->key, &h->value);
    }
}

static int
ngx_http_spdy_validate_headers(ngx_http_request_t *r)
{
    if (r->uri.data == NULL) {
        return NGX_ERROR;
    }

    r->headers_in.connection_type = NGX_HTTP_CONNECTION_CLOSE;
    return NGX_OK;
}

static void
ngx_http_spdy_control_frame_syn_stream(ngx_http_spdy_request_t *r)
{
    uint32_t stream_id, associated_stream_id;
    u_char priority;
    ngx_http_spdy_stream_t *s;

    stream_id = BE_LOAD_32(r->buffer_r->pos);
    r->buffer_r->pos += 4;
    associated_stream_id = BE_LOAD_32(r->buffer_r->pos);
    r->buffer_r->pos += 4;
    priority = *r->buffer_r->pos >> 6;
    r->buffer_r->pos += 2;

    s = ngx_http_spdy_create_stream(r, stream_id, priority);
    if (s == NULL) {
        ngx_http_spdy_send_rst_stream(r, stream_id, NGX_SPDY_INTERNAL_ERROR);
        return;
    }

    ngx_http_spdy_parse_headers(s, r);

    if (ngx_http_spdy_validate_headers(s->request) != NGX_OK) {
        ngx_http_spdy_send_rst_stream(r, stream_id, NGX_SPDY_INTERNAL_ERROR);
        return;
    }

    if (ngx_http_process_request_header(s->request) != NGX_OK) {
        ngx_http_spdy_send_rst_stream(r, stream_id, NGX_SPDY_INTERNAL_ERROR);
        return;
    }

    s->request->http_state = NGX_HTTP_PROCESS_REQUEST_STATE;

    ngx_http_process_request(s->request);
}


static void
ngx_http_spdy_process_control_frame(ngx_http_spdy_request_t *r)
{
    if (r->current_frame.control_frame.version != 2) {
        return;
    }

    if (r->current_frame.control_frame.type < sizeof(ngx_http_spdy_control_frame_handlers)/sizeof(ngx_http_spdy_control_frame_handlers[0])) {
        ngx_http_spdy_control_frame_handlers[r->current_frame.control_frame.type](r);
    }
}

static void
ngx_http_spdy_read_control_frame(ngx_event_t *rev)
{
    ssize_t                 left_to_read;
    ssize_t                 n;
    ngx_connection_t        *c;
    ngx_http_spdy_request_t *r;

    c = rev->data;
    r = c->data;
    left_to_read = r->current_frame.length - (r->buffer_r->last - r->buffer_r->start) + sizeof(ngx_http_spdy_frame_header_t);

    n = c->recv(c, r->buffer_r->last, left_to_read);
    if (n == NGX_AGAIN) {
        return;
    }
    if (n == NGX_ERROR) {
        /* TODO: close the connection */
        return;
    }
    r->buffer_r->last += n;
    if (n == left_to_read) {
        ngx_http_spdy_process_control_frame(r);
        ngx_prepare_next_frame(r);

        rev->handler(rev);
    }
}

static void
ngx_http_spdy_read_data_frame(ngx_event_t *rev)
{
    printf("data frame!\n");
}

static void
ngx_http_sdpy_resize_buffer(ngx_http_spdy_request_t *r)
{
    ngx_buf_t *nb, *ob;
    ob = r->buffer_r;

    /* This function assumes the new size should be larger than the "current" size */
    nb = ngx_create_temp_buf(r->connection->pool, r->current_frame.length + sizeof(ngx_http_spdy_frame_header_t));
    ngx_memcpy(nb->start, ob->start, ob->last - ob->start);

    nb->pos += ob->pos - ob->start;
    nb->last += nb->last - ob->start;

    ngx_pfree(r->connection->pool, ob);

    r->buffer_r = nb;
}

static void
ngx_http_sdpy_process_frame_header(ngx_http_spdy_request_t *r)
{
    u_char                       *b;
    ngx_http_spdy_frame_header_t *frame;

    b = r->buffer_r->start;
    frame = &r->current_frame;

    frame->control_frame.control = b[0] >> 7;

    frame->flags = b[4];
    frame->length = BE_LOAD_32(b + 4) & 0xffffff;

    if (frame->control_frame.control) {
        frame->control_frame.version = BE_LOAD_16(b) & 0x7fff;
        frame->control_frame.type = BE_LOAD_16(&b[2]);
        r->connection->read->handler = ngx_http_spdy_read_control_frame;
        if ((ssize_t)(r->buffer_r->end - r->buffer_r->start) < (ssize_t)(frame->length + sizeof(ngx_http_spdy_frame_header_t))) {
            ngx_http_sdpy_resize_buffer(r);
        }
    } else {
        frame->data_frame.stream_id = BE_LOAD_32(b);
        r->connection->read->handler = ngx_http_spdy_read_data_frame;
    }
    r->buffer_r->pos += sizeof(ngx_http_spdy_frame_header_t);

    r->connection->read->handler(r->connection->read);
}

void ngx_http_spdy_process_frame(ngx_event_t *rev)
{
    ssize_t                  n;
    ngx_connection_t        *c;
    ngx_http_spdy_request_t *r;

    c  = rev->data;
    rev = c->read;
    r = c->data;

    if (!rev->ready) {
        return;
    }

    n = c->recv(c, r->buffer_r->last,
                    sizeof(ngx_http_spdy_frame_header_t) - (r->buffer_r->last - r->buffer_r->start));

    if (n == NGX_AGAIN) {
        return;
    }
    if (n == NGX_ERROR) {
        /* TODO: close connection */
        return;
    }

    r->buffer_r->last += n;

    if (r->buffer_r->last - r->buffer_r->start == sizeof(ngx_http_spdy_frame_header_t)) {
        ngx_http_sdpy_process_frame_header(r);
    }
}

static void
ngx_http_spdy_request_handler(ngx_event_t *ev)
{
    printf("write handler!\n");
    // ngx_connection_t    *c;
    // ngx_http_request_t  *r;
    // ngx_http_log_ctx_t  *ctx;

    // c = ev->data;
    // r = c->data;

    // ctx = c->log->data;
    // ctx->current_request = r;

    // ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
    //                "http run request: \"%V?%V\"", &r->uri, &r->args);

    // if (ev->write) {
    //     r->write_event_handler(r);

    // } else {
    //     r->read_event_handler(r);
    // }

    // ngx_http_run_posted_requests(c);
}

