/*
 * nginx-compression — phase-0 prototype (see RFC: nginx-zstd-module #109).
 *
 * THE BACKEND INTERFACE. This header is the deliverable of phase 0: a
 * seam that two real encoders (zstd, brotli) sit behind today, that a
 * future coding can implement without touching the election, and that
 * reserves the phase-1 dictionary hooks. Every place the two libraries
 * refused to be shaped the same way is documented at the member that
 * absorbs the difference — those notes are the "wrinkles found", also
 * collected in WRINKLES.md.
 *
 * Deliberately NOT here: gzip. Per the RFC's "defer or veto, never
 * implement", gzip is an election TOKEN, not a backend — the election
 * either stands aside for the core gzip filter (defer: decline without
 * touching the r->gzip_tested latch) or shuts it off (veto: latch).
 * The interface proves itself partly by gzip never needing a slot in it.
 */

#ifndef NGX_HTTP_COMPRESSION_H
#define NGX_HTTP_COMPRESSION_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

/*
 * Floor: 1.23.0 (May 2022) — the list-linked header change
 * (ngx_table_elt_t.next) this module relies on when pushing
 * Content-Encoding and Vary. Review round 1 caught the config
 * script claiming 1.9.11.
 */
#if (nginx_version < 1023000)
#error "nginx-compression requires nginx >= 1.23.0 (ngx_table_elt_t.next)"
#endif


/*
 * One streaming step. The caller owns both buffers; the backend
 * reports how much of each it used. A step never fails "partially":
 * on NGX_ERROR the stream is dead and the caller unhooks.
 */
typedef struct {
    const u_char  *in;            /* remaining input (may be NULL/0)   */
    size_t         in_len;
    u_char        *out;           /* output space for this step        */
    size_t         out_len;

    size_t         in_consumed;   /* OUT: bytes of `in` eaten          */
    size_t         out_produced;  /* OUT: bytes written to `out`       */

    /*
     * OUT: "this operation needs no further steps." The meaning is
     * op-relative, and pinning it down was the first real wrinkle —
     * the two libraries report completion through different channels
     * and the interface must define done per-op, not globally:
     *
     *   PROCESS: all input consumed AND the encoder is not sitting on
     *            ready output (brotli can hold output while zstd
     *            buffers input silently; both map, via different
     *            probes: zstd "input consumed", brotli additionally
     *            BrotliEncoderHasMoreOutput()).
     *   FLUSH:   everything buffered so far is in `out` bytes the
     *            caller has seen (zstd: compressStream2 returned 0;
     *            brotli: !HasMoreOutput && input drained).
     *   FINISH:  the stream's final byte is emitted (zstd: returned 0;
     *            brotli: BrotliEncoderIsFinished()).
     *
     * done == 0 after a step means: give me a fresh `out` and call
     * again with the SAME op and the unconsumed remainder.
     */
    unsigned       done:1;
} ngx_http_compression_io_t;


typedef enum {
    NGX_HTTP_COMPRESSION_OP_PROCESS = 0,  /* more input will follow    */
    NGX_HTTP_COMPRESSION_OP_FLUSH,        /* make output decodable now */
    NGX_HTTP_COMPRESSION_OP_FINISH        /* end of stream             */
} ngx_http_compression_op_e;


typedef struct ngx_http_compression_backend_s  ngx_http_compression_backend_t;

struct ngx_http_compression_backend_s {

    /*
     * The content-coding: election-order token, Accept-Encoding token
     * and Content-Encoding value, all one string ("zstd", "br").
     */
    ngx_str_t    coding;

    /*
     * RFC 9842 dictionary variant of the coding ("dcz", "dcb"), or
     * empty when the backend has none. Phase-1 seam: negotiation
     * (Available-Dictionary) happens in the core module against the
     * shared store; the backend only ever sees raw bytes.
     *
     * BOTH dictionary codings carry a wire prologue the compression
     * library does not emit (review round 1 corrected the earlier
     * "dcz is a plain zstd frame" text): dcz prepends a 40-byte zstd
     * SKIPPABLE frame (magic 0x184D2A5E, size 0x20, then the
     * dictionary's SHA-256) which a zstd decoder skips natively;
     * dcb prepends 36 raw bytes (0xFF 'D' 'C' 'B' + SHA-256) the
     * brotli decoder does NOT consume. Same shape — magic plus hash —
     * different framing and different consumer obligations, which is
     * why wire_prologue is a per-backend hook rather than chassis
     * code. (Phase-1 alternative on the table: since both prologues
     * are derivable from {magic, hash}, the chassis could emit them
     * from two descriptor fields and the hook disappears.)
     */
    ngx_str_t    dict_coding;

    /*
     * Per-request lifecycle. INVARIANT (wrinkle #2, both libraries
     * force it): create → hint_input_size → attach_dictionary →
     * process. zstd's ZSTD_CCtx_refPrefix must precede the first
     * compress call and its parameters must already be final; brotli's
     * BrotliEncoderPrepareDictionary bakes in the QUALITY, so the
     * level cannot change after attach either. The core module
     * enforces the order; backends may assume it.
     *
     * create() allocates the backend ctx from r->pool and registers
     * its own pool cleanup for the library handle — the core module
     * never sees a raw encoder pointer and there is no destroy() slot
     * to forget to call on error paths.
     */
    ngx_int_t  (*create)(ngx_http_request_t *r, ngx_int_t level,
                         void **bctx);

    /*
     * Optional (NULL = skip): declared input size, when known, before
     * the first byte. Exists because brotli's SIZE_HINT measurably
     * improves ratio and must be set up front; zstd has
     * ZSTD_CCtx_setPledgedSrcSize with the same up-front constraint.
     * A backend without the concept just omits the hook (wrinkle #3:
     * the hook must be optional, not a required no-op, or every future
     * backend inherits dead code).
     */
    ngx_int_t  (*hint_input_size)(void *bctx, off_t bytes);

    /*
     * Phase-1 seam, wired but not yet driven by a store: attach one
     * RAW (unstructured) dictionary. `raw` must outlive the request —
     * zstd references the bytes in place (refPrefix, zero copy);
     * brotli builds a prepared form and could drop them, but the
     * contract is written for the cheapest backend to keep the store's
     * "raw bytes live in the cycle pool" ownership model load-bearing.
     */
    ngx_int_t  (*attach_dictionary)(void *bctx, ngx_str_t *raw);

    /*
     * Wire prologue BEFORE the first encoder byte, from the elected
     * dictionary's SHA-256. Both dict codings need one — see
     * dict_coding above — and neither library emits it (zstd's
     * refPrefix is transparent; brotli's header is outside the
     * stream). Returns the number of bytes written into `out`
     * (bounded by out_len), or NGX_ERROR.
     *
     * SETTLED in phase 1b (the chassis-vs-backend question from
     * round 1): emission stays per-backend. dcz's prologue is a
     * VALID ZSTD SKIPPABLE FRAME — its shape (magic 0x184D2A5E,
     * little-endian size word, then the hash) is zstd format
     * knowledge; dcb's is raw out-of-band bytes the decoder never
     * sees. A chassis emitter would need per-backend format
     * descriptors, which is this hook wearing a struct costume.
     *
     * NULL still means the dictionary coding is NOT SERVABLE (review
     * round 2): the prologue is mandatory on the wire, so the
     * election gates dict codings on `wire_prologue != NULL`, never
     * on `dict_coding.len` alone.
     */
    ssize_t    (*wire_prologue)(void *bctx, const u_char *dict_sha256,
                                u_char *out, size_t out_len);

    /*
     * The streaming step. See ngx_http_compression_io_t for the
     * per-op `done` contract.
     */
    ngx_int_t  (*process)(void *bctx, ngx_http_compression_io_t *io,
                          ngx_http_compression_op_e op);

    /*
     * Recommended output-buffer size for one step. The two libraries
     * answer a different question here (wrinkle #4): zstd has a fixed
     * stream-chunk recommendation (ZSTD_CStreamOutSize()), brotli
     * only offers a whole-input bound (BrotliEncoderMaxCompressedSize)
     * that needs a length we may not have. So the contract is the
     * modest one both can honour: "a size at which repeated steps make
     * progress without pathological ping-ponging"; content_length may
     * be -1.
     */
    size_t     (*out_size)(off_t content_length);
};


/*
 * Registry: compiled-in backends, NULL-terminated. The extensibility
 * contract from the RFC in its smallest form — a new coding is one
 * translation unit exporting one of these plus a registry entry.
 */
extern ngx_http_compression_backend_t  *ngx_http_compression_backends[];


/*
 * One election-order entry. backend == NULL is the gzip token: on the
 * FILTER side gzip is never implemented (defer/veto); on the STATIC
 * side gzip is fully first-class — serving a premade .gz is file
 * serving and needs no zlib (how the unified static subsumes
 * gzip_static for free, gzip-less builds included).
 */
typedef struct {
    ngx_http_compression_backend_t  *backend;
} ngx_http_compression_token_t;


/* compression_static modes (parent *_static enum semantics) */
#define NGX_HTTP_COMPRESSION_STATIC_OFF     0
#define NGX_HTTP_COMPRESSION_STATIC_ON      1
#define NGX_HTTP_COMPRESSION_STATIC_ALWAYS  2


/*
 * The module's location configuration — in the header because the
 * filter chassis (module.c) and the static handler (static.c) share
 * it. See each directive's parser for the semantics.
 */
typedef struct {
    ngx_flag_t     enable;
    ssize_t        min_length;
    ngx_hash_t     types;
    ngx_array_t   *types_keys;
    ngx_array_t   *order;          /* of ngx_http_compression_token_t */

    /*
     * PHASE1a: this level's active dictionaries — pointers into the
     * cycle-global store (see ngx_http_compression_dict.h). NULL =
     * inherit.
     */
    ngx_array_t   *dicts;          /* of ngx_http_compression_dict_t * */

    /*
     * PHASE2: static sidecar serving. static_order is the enable set
     * AND the probe order (of ngx_http_compression_static_coding_t *,
     * see static.c); NULL = inherit / shipped default `br zstd gzip`
     * — static prefers br because its CPU was spent at build time,
     * the deliberate asymmetry with the filter default.
     */
    ngx_uint_t     static_enable;
    ngx_array_t   *static_order;
} ngx_http_compression_conf_t;


extern ngx_module_t  ngx_http_compression_module;


/*
 * Cross-TU helpers, defined in module.c. Both absorb the
 * NGX_HTTP_GZIP build split in ONE place: with the gzip module, Vary
 * is delegated via r->gzip_vary (core emits under "gzip_vary on") and
 * Accept-Encoding comes off r->headers_in; without it, the header is
 * pushed literally and Accept-Encoding is found by a list walk.
 */
ngx_int_t ngx_http_compression_vary(ngx_http_request_t *r);
ngx_table_elt_t *ngx_http_compression_ae_header(ngx_http_request_t *r);

/* static.c exports, wired by module.c */
char *ngx_http_compression_static_order(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
ngx_int_t ngx_http_compression_static_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_compression_static_default_order(ngx_conf_t *cf,
    ngx_http_compression_conf_t *conf);


#endif /* NGX_HTTP_COMPRESSION_H */
