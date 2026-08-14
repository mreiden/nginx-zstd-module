/*
 * zstd backend for nginx-compression (phase-0 prototype).
 * The reference implementation the vtable was shaped against; see
 * ngx_http_compression.h for the contract each hook satisfies.
 */

#include "ngx_http_compression.h"

#include <zstd.h>


typedef struct {
    ZSTD_CCtx           *cctx;
    ngx_http_request_t  *r;      /* for error logging with context */
} ngx_http_compression_zstd_ctx_t;


static void
ngx_http_compression_zstd_cleanup(void *data)
{
    ngx_http_compression_zstd_ctx_t  *z = data;

    if (z->cctx != NULL) {
        ZSTD_freeCCtx(z->cctx);
        z->cctx = NULL;
    }
}


static ngx_int_t
ngx_http_compression_zstd_create(ngx_http_request_t *r, ngx_int_t level,
    void **bctx)
{
    ngx_pool_cleanup_t               *cln;
    ngx_http_compression_zstd_ctx_t  *z;

    cln = ngx_pool_cleanup_add(r->pool,
                               sizeof(ngx_http_compression_zstd_ctx_t));
    if (cln == NULL) {
        return NGX_ERROR;
    }

    z = cln->data;
    z->r = r;
    z->cctx = ZSTD_createCCtx();
    if (z->cctx == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_http_compression_zstd_cleanup;

    if (ZSTD_isError(ZSTD_CCtx_setParameter(z->cctx,
                                            ZSTD_c_compressionLevel,
                                            (int) level)))
    {
        return NGX_ERROR;
    }

    *bctx = z;
    return NGX_OK;
}


static ngx_int_t
ngx_http_compression_zstd_hint_input_size(void *bctx, off_t bytes)
{
    ngx_http_compression_zstd_ctx_t  *z = bctx;

    if (ZSTD_isError(ZSTD_CCtx_setPledgedSrcSize(z->cctx,
                                                 (unsigned long long) bytes)))
    {
        return NGX_ERROR;
    }
    return NGX_OK;
}


static ngx_int_t
ngx_http_compression_zstd_attach_dictionary(void *bctx, ngx_str_t *raw)
{
    ngx_http_compression_zstd_ctx_t  *z = bctx;

    /*
     * Zero-copy: the CCtx references the raw bytes in place for the
     * whole stream — the reason the interface contract makes the
     * caller keep `raw` alive for the request.
     */
    if (ZSTD_isError(ZSTD_CCtx_refPrefix(z->cctx, raw->data, raw->len))) {
        return NGX_ERROR;
    }
    return NGX_OK;
}


static ngx_int_t
ngx_http_compression_zstd_process(void *bctx, ngx_http_compression_io_t *io,
    ngx_http_compression_op_e op)
{
    size_t                            rem;
    ZSTD_inBuffer                     zin;
    ZSTD_outBuffer                    zout;
    ZSTD_EndDirective                 ed;
    ngx_http_compression_zstd_ctx_t  *z = bctx;

    zin.src = io->in;
    zin.size = io->in_len;
    zin.pos = 0;

    zout.dst = io->out;
    zout.size = io->out_len;
    zout.pos = 0;

    switch (op) {
    case NGX_HTTP_COMPRESSION_OP_FINISH: ed = ZSTD_e_end;      break;
    case NGX_HTTP_COMPRESSION_OP_FLUSH:  ed = ZSTD_e_flush;    break;
    default:                             ed = ZSTD_e_continue; break;
    }

    rem = ZSTD_compressStream2(z->cctx, &zout, &zin, ed);

    if (ZSTD_isError(rem)) {
        ngx_log_error(NGX_LOG_ERR, z->r->connection->log, 0,
                      "compression: ZSTD_compressStream2() failed: %s",
                      ZSTD_getErrorName(rem));
        return NGX_ERROR;
    }

    io->in_consumed = zin.pos;
    io->out_produced = zout.pos;

    if (ed == ZSTD_e_continue) {
        /* PROCESS: zstd buffers internally; consumed == done */
        io->done = (zin.pos == zin.size);
    } else {
        /* FLUSH / FINISH: rem is the bytes still to be flushed */
        io->done = (rem == 0);
    }

    return NGX_OK;
}


static size_t
ngx_http_compression_zstd_out_size(off_t content_length)
{
    (void) content_length;
    return ZSTD_CStreamOutSize();
}


static ngx_http_compression_backend_t  ngx_http_compression_zstd_backend = {
    ngx_string("zstd"),
    ngx_string("dcz"),
    ngx_http_compression_zstd_create,
    ngx_http_compression_zstd_hint_input_size,
    ngx_http_compression_zstd_attach_dictionary,
    NULL,       /* PHASE1: dcz's 40-byte skippable-frame prologue
                 * (magic 0x184D2A5E + size + SHA-256) lands here with
                 * the store — libzstd will not emit it; refPrefix is
                 * transparent (review round 1). NULL keeps "dcz"
                 * UNELECTABLE until then (the election gates dict
                 * codings on wire_prologue != NULL) */
    ngx_http_compression_zstd_process,
    ngx_http_compression_zstd_out_size,
};

ngx_http_compression_backend_t  *ngx_http_compression_backend_zstd =
    &ngx_http_compression_zstd_backend;
