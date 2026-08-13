/*
 * nginx-compression — phase-0 prototype core (RFC: nginx-zstd-module
 * #109). One filter module, N backends, election by compression_order,
 * gzip by defer/veto. Throwaway by charter: the deliverable is the
 * backend interface and the seams, not production polish — the known
 * shortcuts are marked "PHASE0:" and collected in WRINKLES.md.
 */

#include "ngx_http_compression.h"
#include "ngx_http_compression_ae.h"


extern ngx_http_compression_backend_t  *ngx_http_compression_backend_zstd;
extern ngx_http_compression_backend_t  *ngx_http_compression_backend_brotli;

ngx_http_compression_backend_t  *ngx_http_compression_backends[] = {
    NULL,   /* set in preconfiguration: zstd */
    NULL,   /* brotli */
    NULL
};


/*
 * One election-order entry. backend == NULL is the gzip token: gzip is
 * never implemented here (RFC: defer or veto, never implement), it
 * only occupies a position in the order.
 */
typedef struct {
    ngx_http_compression_backend_t  *backend;
} ngx_http_compression_token_t;


typedef struct {
    ngx_flag_t     enable;
    ssize_t        min_length;
    ngx_hash_t     types;
    ngx_array_t   *types_keys;
    ngx_array_t   *order;          /* of ngx_http_compression_token_t */
} ngx_http_compression_conf_t;


typedef struct {
    ngx_http_compression_backend_t  *backend;
    void                            *bctx;
    ngx_chain_t                     *in;
    ngx_buf_t                       *ob;        /* current output buf */
    size_t                           out_size;
    unsigned                         done:1;
} ngx_http_compression_ctx_t;


static ngx_int_t ngx_http_compression_add_backends(ngx_conf_t *cf);
static void *ngx_http_compression_create_conf(ngx_conf_t *cf);
static char *ngx_http_compression_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_compression_order(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_compression_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_compression_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_compression_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);


static ngx_command_t  ngx_http_compression_commands[] = {

    { ngx_string("compression"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_compression_conf_t, enable),
      NULL },

    { ngx_string("compression_order"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_compression_order,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("compression_min_length"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_compression_conf_t, min_length),
      NULL },

    { ngx_string("compression_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_types_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_compression_conf_t, types_keys),
      &ngx_http_html_default_types[0] },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_compression_module_ctx = {
    ngx_http_compression_add_backends,     /* preconfiguration */
    ngx_http_compression_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_compression_create_conf,      /* create location configuration */
    ngx_http_compression_merge_conf,       /* merge location configuration */
};


ngx_module_t  ngx_http_compression_module = {
    NGX_MODULE_V1,
    &ngx_http_compression_module_ctx,      /* module context */
    ngx_http_compression_commands,         /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

static ngx_str_t  ngx_http_compression_gzip_token = ngx_string("gzip");


#if !(NGX_HTTP_GZIP)
/*
 * Without the gzip module there is no r->headers_in.accept_encoding —
 * that field, like r->gzip_vary/gzip_tested/gzip_ok, lives inside
 * #if (NGX_HTTP_GZIP) in ngx_http_request.h (review round 1; the
 * sneaky part being that --with-compat forces NGX_HTTP_GZIP=1, so
 * compat CI builds can never catch a gzip-less break). Find the
 * header ourselves; FIRST match only, same parity as the gzip-built
 * path (see ngx_http_compression_ae.h on why).
 */
static ngx_table_elt_t *
ngx_http_compression_accept_encoding(ngx_http_request_t *r)
{
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;

    part = &r->headers_in.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].key.len == sizeof("Accept-Encoding") - 1
            && ngx_strncasecmp(h[i].key.data, (u_char *) "Accept-Encoding",
                               sizeof("Accept-Encoding") - 1) == 0)
        {
            return &h[i];
        }
    }

    return NULL;
}
#endif


static ngx_int_t
ngx_http_compression_add_backends(ngx_conf_t *cf)
{
    (void) cf;

    /*
     * Filled here rather than by static initializer only because the
     * backends live in separate TUs exporting pointers; a real module
     * can use a designated static array.
     */
    ngx_http_compression_backends[0] = ngx_http_compression_backend_zstd;
    ngx_http_compression_backends[1] = ngx_http_compression_backend_brotli;

    return NGX_OK;
}


/*
 * PHASE0: per-backend tuning directives (levels, windows) are out of
 * scope; a unified "compression_level" was considered and REJECTED —
 * level scales are not comparable across codecs (zstd 3 and brotli 5
 * are both "the sane default" yet share no axis), so the real module
 * keeps per-coding directives. Wrinkle #8.
 */
static ngx_int_t
ngx_http_compression_default_level(ngx_http_compression_backend_t *b)
{
    if (b->coding.len == 4
        && ngx_strncmp(b->coding.data, "zstd", 4) == 0)
    {
        return 3;
    }
    return 5;   /* brotli quality */
}


static void *
ngx_http_compression_create_conf(ngx_conf_t *cf)
{
    ngx_http_compression_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_compression_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->min_length = NGX_CONF_UNSET;
    conf->order = NULL;     /* NULL = inherit / shipped default */

    return conf;
}


static char *
ngx_http_compression_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_compression_conf_t *prev = parent;
    ngx_http_compression_conf_t *conf = child;

    ngx_http_compression_token_t  *t;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->min_length, prev->min_length, 20);

    if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             ngx_http_html_default_types)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (conf->order == NULL) {
        conf->order = prev->order;
    }

    if (conf->order == NULL) {
        /* shipped default: zstd br gzip (RFC: dynamic prefers the
         * cheap coding; gzip last makes deferral risk-free) */
        conf->order = ngx_array_create(cf->pool, 3,
                                    sizeof(ngx_http_compression_token_t));
        if (conf->order == NULL) {
            return NGX_CONF_ERROR;
        }

        t = ngx_array_push(conf->order);
        if (t == NULL) {
            return NGX_CONF_ERROR;
        }
        t->backend = ngx_http_compression_backend_zstd;

        t = ngx_array_push(conf->order);
        if (t == NULL) {
            return NGX_CONF_ERROR;
        }
        t->backend = ngx_http_compression_backend_brotli;

#if (NGX_HTTP_GZIP)
        /* the gzip token joins the default only when there is a core
         * gzip filter to defer to */
        t = ngx_array_push(conf->order);
        if (t == NULL) {
            return NGX_CONF_ERROR;
        }
        t->backend = NULL;
#endif
    }

#if (NGX_HTTP_GZIP)
    /*
     * Setting r->gzip_vary only REQUESTS Vary: Accept-Encoding; the
     * core header filter emits it solely when the gzip_vary directive
     * is on — and its default is off (review round 1: the live matrix
     * had gzip_vary on and never saw this). Without it a shared cache
     * stores a zstd response with no Vary and serves it to clients
     * that cannot decode it. clcf->gzip_vary IS observable (core loc
     * conf, public — contrast WRINKLES #1's abandoned warning about
     * the gzip module's private conf), so warn like the parent repo
     * does. PHASE0: per-location; productization collapses this into
     * the #110-style per-module summary.
     */
    if (conf->enable) {
        ngx_http_core_loc_conf_t  *clcf;

        clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
        if (clcf != NULL && !clcf->gzip_vary) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "compression is enabled but \"gzip_vary\" is "
                               "off; add \"gzip_vary on\" or shared caches "
                               "may serve compressed responses to clients "
                               "that cannot decode them");
        }
    }
#endif

    return NGX_CONF_OK;
}


static char *
ngx_http_compression_order(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_compression_conf_t *ccf = conf;

    ngx_str_t                       *value;
    ngx_uint_t                       i, j, k;
    ngx_http_compression_token_t    *t;
    ngx_http_compression_backend_t  *b;

    if (ccf->order != NULL && ccf->order->nelts > 0) {
        return "is duplicate";
    }

    ccf->order = ngx_array_create(cf->pool, cf->args->nelts - 1,
                                  sizeof(ngx_http_compression_token_t));
    if (ccf->order == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        b = NULL;

        if (value[i].len == ngx_http_compression_gzip_token.len
            && ngx_strncmp(value[i].data,
                           ngx_http_compression_gzip_token.data,
                           value[i].len) == 0)
        {
#if (NGX_HTTP_GZIP)
            /* gzip: valid token, no backend — defer/veto semantics */
#else
            /* nothing to defer to: better a config error than a token
             * that silently means "identity" */
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"gzip\" in \"compression_order\" requires "
                               "nginx built with ngx_http_gzip_module");
            return NGX_CONF_ERROR;
#endif

        } else {
            for (k = 0; ngx_http_compression_backends[k]; k++) {
                if (value[i].len
                        == ngx_http_compression_backends[k]->coding.len
                    && ngx_strncmp(value[i].data,
                           ngx_http_compression_backends[k]->coding.data,
                           value[i].len) == 0)
                {
                    b = ngx_http_compression_backends[k];
                    break;
                }
            }

            if (b == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "unknown coding \"%V\" in "
                                   "\"compression_order\"", &value[i]);
                return NGX_CONF_ERROR;
            }
        }

        /* a coding may appear once: the order list IS the enable set
         * (backend == NULL is the single gzip token, so pointer
         * equality covers it too) */
        t = ccf->order->elts;
        for (j = 0; j < ccf->order->nelts; j++) {
            if (t[j].backend == b) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "duplicate coding \"%V\" in "
                                   "\"compression_order\"", &value[i]);
                return NGX_CONF_ERROR;
            }
        }

        t = ngx_array_push(ccf->order);
        if (t == NULL) {
            return NGX_CONF_ERROR;
        }
        t->backend = b;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_compression_header_filter(ngx_http_request_t *r)
{
    ngx_int_t                        w;
    ngx_uint_t                       i;
#if (NGX_HTTP_GZIP)
    ngx_uint_t                       gzip_listed;
#endif
    ngx_table_elt_t                 *ae;
    ngx_http_compression_ctx_t      *ctx;
    ngx_http_compression_conf_t     *conf;
    ngx_http_compression_token_t    *t;
    ngx_http_compression_backend_t  *elected;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_compression_module);

    /*
     * PHASE0: 200 only. The real module inherits the zstd filter's
     * status set (2xx minus 204/205, plus 403/404).
     */
    if (!conf->enable
        || r != r->main
        || r->headers_out.status != NGX_HTTP_OK
        || r->header_only
        || (r->headers_out.content_encoding != NULL
            && r->headers_out.content_encoding->value.len != 0)
        || ngx_http_test_content_type(r, &conf->types) == NULL)
    {
        return ngx_http_next_header_filter(r);
    }

    if (r->headers_out.content_length_n != -1
        && r->headers_out.content_length_n < conf->min_length)
    {
        return ngx_http_next_header_filter(r);
    }

    /*
     * Vary before any accept decision, so identity fallbacks vary too.
     * With the gzip module present, emission is delegated to nginx's
     * own writers (h1/h2/h3) via the r->gzip_vary mechanism — the
     * module never pushes a literal Vary: Accept-Encoding itself, and
     * the compression_vary module's cooperation (it keys on this flag)
     * comes free. NOTE the emission is still gated on "gzip_vary on";
     * merge_conf warns when it is off (review round 1). Without the
     * gzip module neither the flag nor the core emitter exists, so
     * push the header ourselves.
     */
#if (NGX_HTTP_GZIP)
    r->gzip_vary = 1;

    ae = r->headers_in.accept_encoding;
#else
    {
        ngx_table_elt_t  *v;

        v = ngx_list_push(&r->headers_out.headers);
        if (v == NULL) {
            return NGX_ERROR;
        }
        v->hash = 1;
        v->next = NULL;
        ngx_str_set(&v->key, "Vary");
        ngx_str_set(&v->value, "Accept-Encoding");
    }

    ae = ngx_http_compression_accept_encoding(r);
#endif

    if (ae == NULL || ae->value.len == 0) {
        return ngx_http_next_header_filter(r);
    }

    elected = NULL;
#if (NGX_HTTP_GZIP)
    gzip_listed = 0;
#endif

    t = conf->order->elts;

    for (i = 0; i < conf->order->nelts; i++) {

        if (t[i].backend == NULL) {
            /* without the gzip module this token cannot exist — the
             * order parser rejects it at config load */
#if (NGX_HTTP_GZIP)
            gzip_listed = 1;

            w = ngx_http_compression_coding_weight(
                    &ae->value, &ngx_http_compression_gzip_token, 1);
            if (w > 0) {
                /*
                 * DEFER: gzip won the election, and gzip is never
                 * implemented here. Stand aside WITHOUT touching the
                 * r->gzip_tested latch — the core gzip filter below
                 * then applies its ENTIRE rule set (gzip_types,
                 * gzip_proxied, gzip_disable, gzip's own on/off).
                 * One-way door by design: if gzip's own gates decline,
                 * there is no second pass back into this election.
                 */
                return ngx_http_next_header_filter(r);
            }
#endif
            continue;
        }

        w = ngx_http_compression_coding_weight(&ae->value,
                                               &t[i].backend->coding, 1);
        if (w > 0) {
            elected = t[i].backend;
            break;
        }
    }

    if (elected == NULL) {
#if (NGX_HTTP_GZIP)
        /*
         * VETO: the election concluded and gzip was absent from the
         * list — gzip is genuinely off for this response, latch so the
         * core filter stands down. When gzip WAS listed the client
         * simply didn't accept it; the core filter's own AE check
         * reaches the same conclusion, no latch needed.
         */
        if (!gzip_listed) {
            r->gzip_tested = 1;
            r->gzip_ok = 0;
        }
#endif
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_compression_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->backend = elected;
    ctx->out_size = elected->out_size(r->headers_out.content_length_n);

    if (elected->create(r, ngx_http_compression_default_level(elected),
                        &ctx->bctx)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (elected->hint_input_size != NULL
        && r->headers_out.content_length_n > 0)
    {
        if (elected->hint_input_size(ctx->bctx,
                                     r->headers_out.content_length_n)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    /* PHASE1 seam: dictionary negotiation would run here —
     * Available-Dictionary against the shared store, then
     * elected->attach_dictionary(ctx->bctx, raw) and the dict_coding
     * Content-Encoding instead of the base one. */

    ngx_http_set_ctx(r, ctx, ngx_http_compression_module);

    /*
     * The copy filter must hand the body filter memory buffers —
     * without this, sendfile-backed responses arrive as file bufs and
     * the (deliberate) in-memory-only cut used to fire AFTER the
     * compressed headers had gone out, truncating the response
     * instead of failing cleanly (review round 1). Same line core
     * gzip uses.
     */
    r->main_filter_need_in_memory = 1;

#if (NGX_HTTP_GZIP)
    /* we compress: the core gzip filter must stand down */
    r->gzip_tested = 1;
    r->gzip_ok = 0;
#endif

    r->headers_out.content_encoding =
        ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.content_encoding == NULL) {
        return NGX_ERROR;
    }

    r->headers_out.content_encoding->hash = 1;
    r->headers_out.content_encoding->next = NULL;
    ngx_str_set(&r->headers_out.content_encoding->key, "Content-Encoding");
    r->headers_out.content_encoding->value = elected->coding;

    ngx_http_clear_content_length(r);
    ngx_http_clear_accept_ranges(r);
    ngx_http_weak_etag(r);

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_compression_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                    rc;
    ngx_buf_t                   *b;
    ngx_uint_t                   last_seen, flush_seen;
    ngx_chain_t                 *out, **last_out, *cl;
    ngx_http_compression_op_e    op;
    ngx_http_compression_io_t    io;
    ngx_http_compression_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_compression_module);

    if (ctx == NULL || ctx->done) {
        return ngx_http_next_body_filter(r, in);
    }

    if (in != NULL) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    out = NULL;
    last_out = &out;

    while (ctx->in != NULL) {

        b = ctx->in->buf;

        /*
         * PHASE0: in-memory bufs only (wrinkle #9: chassis complexity,
         * no backend hook needed). Belt only — the header filter sets
         * r->main_filter_need_in_memory, so the copy filter converts
         * file bufs before they reach here; if this fires, that
         * contract broke upstream of us.
         */
        if (b->in_file && !ngx_buf_in_memory(b)) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "compression: file buffers unsupported in the "
                          "phase-0 prototype");
            return NGX_ERROR;
        }

        last_seen = b->last_buf;
        flush_seen = b->flush;

        for ( ;; ) {

            size_t  data;

            /*
             * Special bufs (flags only) have pos == last == NULL, and
             * NULL pointer arithmetic is UB even when the difference
             * would be zero (review round 1) — gate on
             * ngx_buf_in_memory before touching the cursors.
             */
            data = ngx_buf_in_memory(b) ? (size_t) (b->last - b->pos) : 0;

            if (data > 0) {
                op = NGX_HTTP_COMPRESSION_OP_PROCESS;
            } else if (last_seen) {
                op = NGX_HTTP_COMPRESSION_OP_FINISH;
            } else if (flush_seen) {
                op = NGX_HTTP_COMPRESSION_OP_FLUSH;
            } else {
                break;      /* buf drained, no flags: next link */
            }

            if (ctx->ob == NULL) {
                ctx->ob = ngx_create_temp_buf(r->pool, ctx->out_size);
                if (ctx->ob == NULL) {
                    return NGX_ERROR;
                }
                ctx->ob->tag = (ngx_buf_tag_t) &ngx_http_compression_module;
            }

            ngx_memzero(&io, sizeof(io));
            if (data > 0) {
                io.in = b->pos;
                io.in_len = data;
            }
            io.out = ctx->ob->last;
            io.out_len = ctx->ob->end - ctx->ob->last;

            if (ctx->backend->process(ctx->bctx, &io, op) != NGX_OK) {
                return NGX_ERROR;
            }

            if (io.in_consumed > 0) {
                b->pos += io.in_consumed;
            }
            ctx->ob->last += io.out_produced;

            /*
             * ORDER MATTERS (review round 1's double-FINISH): the
             * completion check must run BEFORE the full-buffer ship.
             * When a FINISH lands its last byte exactly at ob->end,
             * shipping first and looping used to call FINISH again on
             * a finished encoder — zstd silently appends an empty
             * frame, brotli hard-errors mid-response. done means done:
             * the flags ride whatever buffer the op ended in, full or
             * not.
             */
            if (io.done && op != NGX_HTTP_COMPRESSION_OP_PROCESS) {
                ngx_buf_t  *ob;

                if (op == NGX_HTTP_COMPRESSION_OP_FINISH) {
                    ctx->done = 1;
                }

                ob = ctx->ob;
                ctx->ob = NULL;

                if (ob->last == ob->pos) {
                    /*
                     * The op's bytes all left in earlier full-buffer
                     * shipments; the flags must not ride a zero-size
                     * temp buf (ngx_output_chain alerts on those) —
                     * use a special buf. An empty flush also keeps
                     * the drained buf for reuse.
                     */
                    if (!ctx->done) {
                        ctx->ob = ob;
                    }
                    ob = ngx_calloc_buf(r->pool);
                    if (ob == NULL) {
                        return NGX_ERROR;
                    }
                }

                ob->flush = ctx->done ? 0 : 1;
                ob->last_buf = ctx->done ? 1 : 0;

                cl = ngx_alloc_chain_link(r->pool);
                if (cl == NULL) {
                    return NGX_ERROR;
                }
                cl->buf = ob;
                cl->next = NULL;
                *last_out = cl;
                last_out = &cl->next;

                flush_seen = 0;
                last_seen = 0;
                break;
            }

            if (ctx->ob->last == ctx->ob->end) {
                /* output space exhausted mid-op: ship it, keep
                 * stepping the SAME op per the vtable contract */
                cl = ngx_alloc_chain_link(r->pool);
                if (cl == NULL) {
                    return NGX_ERROR;
                }
                cl->buf = ctx->ob;
                cl->next = NULL;
                *last_out = cl;
                last_out = &cl->next;
                ctx->ob = NULL;
            }

            /* PROCESS with io.done falls through to the op
             * recomputation above: input drained → flags or next
             * link; io.done == 0 → step the same op again with
             * fresh output space */
        }

        /*
         * Link consumed: free it (review round 1 — these used to
         * accumulate for the request's lifetime; core gzip frees them
         * too, and this is separate from the declared no-recycling
         * cut, which is about OUTPUT bufs).
         */
        cl = ctx->in;
        ctx->in = cl->next;
        ngx_free_chain(r->pool, cl);
    }

    if (out == NULL) {
        return NGX_OK;
    }

    /*
     * PHASE0: no busy/free buf recycling — output bufs are pool-fresh
     * and NGX_AGAIN from downstream is returned as-is without
     * retry-tracking. Fine for a prototype exercising the interface;
     * a real module lifts the gzip filter's recycling.
     */
    rc = ngx_http_next_body_filter(r, out);

    return rc;
}


static ngx_int_t
ngx_http_compression_init(ngx_conf_t *cf)
{
    (void) cf;

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_compression_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_compression_body_filter;

    return NGX_OK;
}
