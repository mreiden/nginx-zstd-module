/*
 * nginx-compression — phase 2: unified static sidecar serving.
 *
 * One content-phase handler probes for precompressed sidecars
 * (file.zst / file.br / file.gz) in compression_static_order and
 * serves the first hit with the right Content-Encoding. NO compression
 * library is ever called — this is file serving, which is also why
 * gzip is FIRST-CLASS here (serving a premade .gz needs no zlib; the
 * unified static subsumes gzip_static for free, gzip-less builds
 * included), unlike the filter side's defer/veto.
 *
 * The #76 latch-bug class is structurally inexpressible here: one
 * handler probing codings in order falls through to the next coding —
 * or declines entirely, letting the identity original (and the
 * dynamic filter) take over — without any cross-module latch that
 * could strand a fallback.
 *
 * The zstd probe (magic + declared-window cap, RFC 8878) is the
 * parent zstd_static module's reviewed implementation ported intact,
 * directio geometry included; see that history (#101) for why every
 * branch is shaped the way it is.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_compression.h"
#include "ngx_http_compression_ae.h"


/*
 * RFC 8878 FORMAT constants, deliberately NOT taken from <zstd.h>:
 * static serving is file serving for every coding — a build without
 * libzstd (or without any compression library at all) still probes
 * and serves .zst sidecars byte-exact, exactly as it serves .gz
 * without zlib. The values are the format's, frozen by the RFC:
 * frame magic 0xFD2FB528, skippable magics 0x184D2A5? (low nibble
 * masked).
 */
#define NGX_HTTP_COMPRESSION_STATIC_ZSTD_MAGIC       0xFD2FB528U
#define NGX_HTTP_COMPRESSION_STATIC_SKIPPABLE_MASK   0xFFFFFFF0U
#define NGX_HTTP_COMPRESSION_STATIC_SKIPPABLE_START  0x184D2A50U

/* browsers enforce 8 MB for Content-Encoding: zstd (RFC 8878 §3.1.1.1.2) */
#define NGX_HTTP_COMPRESSION_STATIC_MAX_WINDOW  (8 * 1024 * 1024)

/* directio probe floor: one logical block, raised to the operator's
 * directio_alignment when larger */
#define NGX_HTTP_COMPRESSION_STATIC_DIO_PROBE   4096


static ngx_int_t ngx_http_compression_static_check_zstd(
    ngx_http_request_t *r, ngx_open_file_info_t *of,
    ngx_http_core_loc_conf_t *clcf, ngx_str_t *path);


/*
 * The static coding table: order token, sidecar extension (no dot),
 * Content-Encoding value == token, and an optional serve-time
 * validator. PHASE2 note: productization derives this from the
 * backend registry (a sidecar_ext field) so a new coding lands in
 * static serving automatically; the prototype keeps it literal
 * because gzip has no backend to hang an ext on either way.
 */
typedef struct {
    ngx_str_t    coding;
    ngx_str_t    ext;
    ngx_int_t  (*check)(ngx_http_request_t *r, ngx_open_file_info_t *of,
                        ngx_http_core_loc_conf_t *clcf, ngx_str_t *path);
} ngx_http_compression_static_coding_t;


static ngx_http_compression_static_coding_t
    ngx_http_compression_static_codings[] =
{
    { ngx_string("zstd"), ngx_string("zst"),
      ngx_http_compression_static_check_zstd },
    { ngx_string("br"),   ngx_string("br"),   NULL },
    { ngx_string("gzip"), ngx_string("gz"),   NULL },
    { ngx_null_string,    ngx_null_string,    NULL }
};


char *
ngx_http_compression_static_order(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_compression_conf_t *ccf = conf;

    ngx_str_t                              *value;
    ngx_uint_t                              i, j, k;
    ngx_http_compression_static_coding_t   *c, **cp, **list;

    (void) cmd;

    if (ccf->static_order != NULL && ccf->static_order->nelts > 0) {
        return "is duplicate";
    }

    ccf->static_order = ngx_array_create(cf->pool, cf->args->nelts - 1,
                        sizeof(ngx_http_compression_static_coding_t *));
    if (ccf->static_order == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        c = NULL;
        for (k = 0; ngx_http_compression_static_codings[k].coding.len; k++) {
            if (value[i].len
                    == ngx_http_compression_static_codings[k].coding.len
                && ngx_strncmp(value[i].data,
                       ngx_http_compression_static_codings[k].coding.data,
                       value[i].len) == 0)
            {
                c = &ngx_http_compression_static_codings[k];
                break;
            }
        }

        if (c == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "unknown coding \"%V\" in "
                               "\"compression_static_order\"", &value[i]);
            return NGX_CONF_ERROR;
        }

        /* the order list IS the enable set: once each */
        list = ccf->static_order->elts;
        for (j = 0; j < ccf->static_order->nelts; j++) {
            if (list[j] == c) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "duplicate coding \"%V\" in "
                                   "\"compression_static_order\"",
                                   &value[i]);
                return NGX_CONF_ERROR;
            }
        }

        cp = ngx_array_push(ccf->static_order);
        if (cp == NULL) {
            return NGX_CONF_ERROR;
        }
        *cp = c;
    }

    return NGX_CONF_OK;
}


/* shipped default: br zstd gzip — static prefers br because its CPU
 * was spent at build time (the deliberate filter/static asymmetry) */
ngx_int_t
ngx_http_compression_static_default_order(ngx_conf_t *cf,
    ngx_http_compression_conf_t *conf)
{
    ngx_uint_t                              i;
    static ngx_uint_t                       def[3] = { 1, 0, 2 };
    ngx_http_compression_static_coding_t  **cp;

    conf->static_order = ngx_array_create(cf->pool, 3,
                         sizeof(ngx_http_compression_static_coding_t *));
    if (conf->static_order == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < 3; i++) {
        cp = ngx_array_push(conf->static_order);
        if (cp == NULL) {
            return NGX_ERROR;
        }
        *cp = &ngx_http_compression_static_codings[def[i]];
    }

    return NGX_OK;
}


/*
 * The parent zstd_static probe, ported intact: magic sanity (a
 * truncated / half-downloaded / mistakenly-renamed file must not be
 * served as zstd) plus the declared-window cap on the LEADING regular
 * frame (streaming encoders that were never told the input size stamp
 * the level's default window — a 93 KB asset can declare 128 MB, and
 * every browser rejects it before decoding a byte). pread only: an
 * lseek would corrupt the open_file_cache's shared fd position. Under
 * directio the read is block-aligned at max(4096, directio_alignment)
 * into an equally aligned buffer, and a failed aligned read DECLINES —
 * for a validation read, falling back beats certifying a file we
 * could not inspect.
 */
static ngx_int_t
ngx_http_compression_static_check_zstd(ngx_http_request_t *r,
    ngx_open_file_info_t *of, ngx_http_core_loc_conf_t *clcf,
    ngx_str_t *path)
{
#if !(NGX_WIN32) && (NGX_HAVE_PREAD)
    u_char      hdrbuf[18];
    u_char     *hdr;
    size_t      want;
    ssize_t     n;
    uint32_t    mw;
    ngx_log_t  *log;

    log = r->connection->log;

    if (of->size < 4) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "compression static: \"%V\" too small to be a zstd "
                      "frame (%O bytes)", path, of->size);
        return NGX_DECLINED;
    }

    if (of->is_directio) {
        want = NGX_HTTP_COMPRESSION_STATIC_DIO_PROBE;
        if ((size_t) clcf->directio_alignment > want) {
            want = (size_t) clcf->directio_alignment;
        }

        hdr = ngx_pmemalign(r->pool, want, want);
        if (hdr == NULL) {
            return NGX_ERROR;
        }

    } else {
        hdr = hdrbuf;
        want = sizeof(hdrbuf);
    }

    n = pread(of->fd, hdr, want, 0);
    if (n < 4) {
        if (of->is_directio) {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                          "compression static: %uz-byte aligned probe on "
                          "directio file \"%V\" returned %z — declining; "
                          "check directio_alignment against the device "
                          "geometry", want, path, n);
            return NGX_DECLINED;
        }

        ngx_log_error(NGX_LOG_CRIT, log, ngx_errno,
                      "compression static: pread(\"%V\", frame header) "
                      "returned %z", path, n);
        return NGX_DECLINED;
    }

    if (of->is_directio) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                       "compression static: %uz-byte aligned probe on "
                       "directio file \"%V\"", want, path);
    }

    mw = ((uint32_t) hdr[0])
       | ((uint32_t) hdr[1] << 8)
       | ((uint32_t) hdr[2] << 16)
       | ((uint32_t) hdr[3] << 24);

    if (mw != NGX_HTTP_COMPRESSION_STATIC_ZSTD_MAGIC
        && (mw & NGX_HTTP_COMPRESSION_STATIC_SKIPPABLE_MASK)
           != NGX_HTTP_COMPRESSION_STATIC_SKIPPABLE_START)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "compression static: \"%V\" is not a zstd frame "
                      "(leading bytes 0x%02xd%02xd%02xd%02xd)", path,
                      (ngx_uint_t) hdr[0], (ngx_uint_t) hdr[1],
                      (ngx_uint_t) hdr[2], (ngx_uint_t) hdr[3]);
        return NGX_DECLINED;
    }

    /* leading REGULAR frame only — a skippable lead is exempt (its
     * real header sits after a variable skip) and multi-frame assets
     * are pathological; the parent README documents the scope */
    if (mw == NGX_HTTP_COMPRESSION_STATIC_ZSTD_MAGIC) {
        uint64_t    window;
        ngx_uint_t  i, fhd, fcs_size, off;

        static const ngx_uint_t  did_len[4] = { 0, 1, 2, 4 };

        if (n < 5) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "compression static: \"%V\" frame header "
                          "truncated", path);
            return NGX_DECLINED;
        }

        fhd = hdr[4];

        if (!(fhd & 0x20)) {
            /* Window_Descriptor follows */
            if (n < 6) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "compression static: \"%V\" frame header "
                              "truncated", path);
                return NGX_DECLINED;
            }

            window = (uint64_t) 1 << (10 + (hdr[5] >> 3));
            window += (window >> 3) * (hdr[5] & 7);

        } else {
            /* Single_Segment: window = frame content size, behind the
             * optional dictionary id */
            fcs_size = (fhd >> 6) ? ((ngx_uint_t) 1 << (fhd >> 6)) : 1;
            off = 5 + did_len[fhd & 3];

            if ((size_t) n < off + fcs_size) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "compression static: \"%V\" frame header "
                              "truncated", path);
                return NGX_DECLINED;
            }

            window = 0;
            for (i = 0; i < fcs_size; i++) {
                window |= (uint64_t) hdr[off + i] << (8 * i);
            }

            if (fcs_size == 2) {
                window += 256;  /* RFC 8878: the 2-byte field is offset */
            }
        }

        if (window > NGX_HTTP_COMPRESSION_STATIC_MAX_WINDOW) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "compression static: \"%V\" declares a %uL-byte "
                          "decompression window, above the 8 MB limit "
                          "browsers enforce for Content-Encoding: zstd "
                          "(RFC 8878) — declining so a fallback coding is "
                          "used; recompress with a window log <= 23", path,
                          window);
            return NGX_DECLINED;
        }
    }

#else
    (void) r; (void) of; (void) clcf; (void) path;
#endif

    return NGX_OK;
}


ngx_int_t
ngx_http_compression_static_handler(ngx_http_request_t *r)
{
    u_char                                 *p;
    size_t                                  root;
    ngx_int_t                               rc, w;
    ngx_str_t                               path;
    ngx_buf_t                              *b;
    ngx_log_t                              *log;
    ngx_uint_t                              i, level;
    ngx_chain_t                             out;
    ngx_table_elt_t                        *h, *ae;
    ngx_open_file_info_t                    of;
    ngx_http_core_loc_conf_t               *clcf;
    ngx_http_compression_conf_t            *conf;
    ngx_http_compression_static_coding_t   *c, **order;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_DECLINED;
    }

    if (r->uri.len == 0 || r->uri.data[r->uri.len - 1] == '/') {
        return NGX_DECLINED;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_compression_module);

    if (conf->static_enable == NGX_HTTP_COMPRESSION_STATIC_OFF) {
        return NGX_DECLINED;
    }

    ae = NULL;

    if (conf->static_enable == NGX_HTTP_COMPRESSION_STATIC_ON) {
        /*
         * Negotiated mode varies on Accept-Encoding — requested before
         * any existence probe so identity fallbacks vary too. "always"
         * deliberately does NOT: it ignores Accept-Encoding, so the
         * response genuinely does not vary (gzip_static always
         * parity).
         */
        if (ngx_http_compression_vary(r) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ae = ngx_http_compression_ae_header(r);
        if (ae == NULL || ae->value.len == 0) {
            return NGX_DECLINED;
        }
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    log = r->connection->log;

    order = conf->static_order->elts;

    for (i = 0; i < conf->static_order->nelts; i++) {

        c = order[i];

        if (conf->static_enable == NGX_HTTP_COMPRESSION_STATIC_ON) {
            /* base codings accept the "*" wildcard, same as the
             * filter election */
            w = ngx_http_compression_coding_weight(&ae->value,
                                                   &c->coding, 1);
            if (w <= 0) {
                continue;
            }
        }

        p = ngx_http_map_uri_to_path(r, &path, &root, c->ext.len + 2);
        if (p == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        *p++ = '.';
        p = ngx_cpymem(p, c->ext.data, c->ext.len);
        *p = '\0';
        path.len = p - path.data;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                       "compression static probe: \"%s\"", path.data);

        ngx_memzero(&of, sizeof(ngx_open_file_info_t));

        of.read_ahead = clcf->read_ahead;
        of.directio = clcf->directio;
        of.valid = clcf->open_file_cache_valid;
        of.min_uses = clcf->open_file_cache_min_uses;
        of.errors = clcf->open_file_cache_errors;
        of.events = clcf->open_file_cache_events;

        if (ngx_http_set_disable_symlinks(r, clcf, &path, &of) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
            != NGX_OK)
        {
            switch (of.err) {

            case 0:
                return NGX_HTTP_INTERNAL_SERVER_ERROR;

            case NGX_ENOENT:
            case NGX_ENOTDIR:
            case NGX_ENAMETOOLONG:
                continue;       /* next coding in the order */

            case NGX_EACCES:
#if (NGX_HAVE_OPENAT)
            case NGX_EMLINK:
            case NGX_ELOOP:
#endif
                level = NGX_LOG_ERR;
                break;

            default:
                level = NGX_LOG_CRIT;
                break;
            }

            ngx_log_error(level, log, of.err,
                          "%s \"%s\" failed", of.failed, path.data);
            continue;           /* decline-and-log, keep probing */
        }

        if (of.is_dir) {
            continue;
        }

#if !(NGX_WIN32)
        if (!of.is_file) {
            ngx_log_error(NGX_LOG_CRIT, log, 0,
                          "\"%s\" is not a regular file", path.data);
            continue;
        }
#endif

        if (c->check != NULL
            && c->check(r, &of, clcf, &path) != NGX_OK)
        {
            /* already logged; fall through to the next coding — the
             * unified probe loop is what makes decline-and-log land on
             * a BETTER answer than identity when one exists */
            continue;
        }

        /* ── serve this sidecar ─────────────────────────────────── */

        r->root_tested = !r->error_page;

        rc = ngx_http_discard_request_body(r);
        if (rc != NGX_OK) {
            return rc;
        }

        log->action = (char *) "sending response to client";

        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = of.size;
        r->headers_out.last_modified_time = of.mtime;

        if (ngx_http_set_etag(r) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /* content type derives from the ORIGINAL uri's extension */
        if (ngx_http_set_content_type(r) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        h = ngx_list_push(&r->headers_out.headers);
        if (h == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        h->hash = 1;
        h->next = NULL;
        ngx_str_set(&h->key, "Content-Encoding");
        h->value = c->coding;
        r->headers_out.content_encoding = h;

        /* gzip_static parity: on the static side the representation IS
         * the sidecar's bytes and the validator is strong, so byte
         * ranges are coherent — and they only work by opting in (the
         * range filter bails unless r->allow_ranges is set; a content
         * handler serving a local file never gets it otherwise).
         * "Ranges are meaningless on a compressed body" is a FILTER
         * truth: there the encoded stream is generated on the fly. */
        r->allow_ranges = 1;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                       "compression static: serving \"%s\"", path.data);

        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
        if (b->file == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }

        b->file_pos = 0;
        b->file_last = of.size;

        b->in_file = b->file_last ? 1 : 0;
        b->last_buf = (r == r->main) ? 1 : 0;
        b->last_in_chain = 1;

        /* an empty sidecar in a subrequest leaves in_file and last_buf
         * both 0 — sync marks the flagless zero-size buf deliberate so
         * the output chain doesn't alert (gzip_static parity) */
        b->sync = (b->last_buf || b->in_file) ? 0 : 1;

        b->file->fd = of.fd;
        b->file->name = path;
        b->file->log = log;
        b->file->directio = of.is_directio;

        out.buf = b;
        out.next = NULL;

        return ngx_http_output_filter(r, &out);
    }

    /* nothing served: the identity original (and possibly the dynamic
     * filter) takes over — no latches touched, by design */
    return NGX_DECLINED;
}