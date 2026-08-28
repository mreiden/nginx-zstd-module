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
 * ITS OWN MODULE since the split (Mark's packaging call, gzip_static /
 * parent-pair precedent): static serving must ship as a
 * dependency-free .so — this TU calls no compression library, so a
 * static-only deployment (CDN edge, internal artifact host) loads a
 * module whose ldd shows nothing but libc. The filter module is not
 * required to be present, loaded, or even built.
 */

#define NGX_HTTP_COMPRESSION_STATIC_OFF     0
#define NGX_HTTP_COMPRESSION_STATIC_ON      1
#define NGX_HTTP_COMPRESSION_STATIC_ALWAYS  2


typedef struct {
    ngx_uint_t     enable;
    ngx_array_t   *order;   /* the enable set AND the probe order */
    ngx_flag_t     dict_bypass;
} ngx_http_compression_static_conf_t;


typedef struct {
    /*
     * "Could this cycle ever serve a sidecar" latch (parent #182), set at
     * directive PARSE time whenever "compression_static on|always" is
     * parsed anywhere. compression_static does NOT take NGX_HTTP_LIF_CONF,
     * so there is no "if"-block conf to reason about — but parse-time
     * latching stays symmetric with the filter module and avoids walking
     * the merge tree. When it stays clear, postconfiguration skips
     * registering the content-phase handler entirely.
     */
    ngx_flag_t     any_enabled;
} ngx_http_compression_static_main_conf_t;


static char *ngx_http_compression_static_order(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static void *ngx_http_compression_static_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_compression_static_set_enable_slot(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_compression_static_default_order(ngx_conf_t *cf,
    ngx_http_compression_static_conf_t *conf);
static ngx_int_t ngx_http_compression_static_handler(ngx_http_request_t *r);
static void *ngx_http_compression_static_create_conf(ngx_conf_t *cf);
static char *ngx_http_compression_static_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_compression_static_init(ngx_conf_t *cf);


static ngx_conf_enum_t  ngx_http_compression_static_enum[] = {
    { ngx_string("off"), NGX_HTTP_COMPRESSION_STATIC_OFF },
    { ngx_string("on"), NGX_HTTP_COMPRESSION_STATIC_ON },
    { ngx_string("always"), NGX_HTTP_COMPRESSION_STATIC_ALWAYS },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_compression_static_commands[] = {

    { ngx_string("compression_static"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_compression_static_set_enable_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_compression_static_conf_t, enable),
      &ngx_http_compression_static_enum },

    { ngx_string("compression_static_order"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_compression_static_order,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("compression_static_dict_bypass"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_compression_static_conf_t, dict_bypass),
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_compression_static_module_ctx = {
    NULL,                                    /* preconfiguration */
    ngx_http_compression_static_init,        /* postconfiguration */

    ngx_http_compression_static_create_main_conf, /* create main config */
    NULL,                                    /* init main configuration */

    NULL,                                    /* create server configuration */
    NULL,                                    /* merge server configuration */

    ngx_http_compression_static_create_conf, /* create location config */
    ngx_http_compression_static_merge_conf   /* merge location config */
};


ngx_module_t  ngx_http_compression_static_module = {
    NGX_MODULE_V1,
    &ngx_http_compression_static_module_ctx, /* module context */
    ngx_http_compression_static_commands,    /* module directives */
    NGX_HTTP_MODULE,                         /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    NULL,                                    /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NGX_MODULE_V1_PADDING
};


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

/*
 * The frame probe runs on Win32 too (parent #162) and on any POSIX
 * build with pread(2); a POSIX build without pread skips it (a
 * build-time tripwire — every modern target has pread). Gated so the
 * verdict logic below is shared byte-for-byte across platforms and
 * cannot drift, which is exactly how Win32 came to serve .zst files
 * with no validation at all.
 */
#if (NGX_WIN32)
#define NGX_HTTP_COMPRESSION_STATIC_HAVE_PROBE  1
#define NGX_HTTP_COMPRESSION_STATIC_PREAD_NAME  "ReadFile"
#elif (NGX_HAVE_PREAD)
#define NGX_HTTP_COMPRESSION_STATIC_HAVE_PROBE  1
#define NGX_HTTP_COMPRESSION_STATIC_PREAD_NAME  "pread"
#else
#define NGX_HTTP_COMPRESSION_STATIC_HAVE_PROBE  0
#endif

/* ngx_http_compression_static_probe_frame() verdicts (parent #159) */
#define NGX_HTTP_COMPRESSION_STATIC_FRAME_OK          0
#define NGX_HTTP_COMPRESSION_STATIC_FRAME_NOT_ZSTD    1
#define NGX_HTTP_COMPRESSION_STATIC_FRAME_TRUNCATED   2
#define NGX_HTTP_COMPRESSION_STATIC_FRAME_WINDOW_BIG  3
#define NGX_HTTP_COMPRESSION_STATIC_FRAME_SKIP        4

/*
 * How many leading skippable frames the handler follows before it
 * declines. A dcz-style prefix is exactly ONE skippable frame ahead of
 * the payload, so 4 is generous headroom while still bounding the walk:
 * an attacker cannot turn a skippable-frame chain into an unbounded
 * scan, since each frame past the bound is a hard decline.
 */
#define NGX_HTTP_COMPRESSION_STATIC_MAX_SKIP_FRAMES   4


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


/*
 * RFC 9842 dictionary-coding tokens, for the dict-bypass check. Spec
 * constants like the format magics above — NOT registry lookups: this
 * module links nothing, the filter's registry included (the split's
 * whole point).
 */
static ngx_str_t  ngx_http_compression_static_dcz = ngx_string("dcz");
static ngx_str_t  ngx_http_compression_static_dcb = ngx_string("dcb");


static ngx_http_compression_static_coding_t
    ngx_http_compression_static_codings[] =
{
    { ngx_string("zstd"), ngx_string("zst"),
      ngx_http_compression_static_check_zstd },
    { ngx_string("br"),   ngx_string("br"),   NULL },
    { ngx_string("gzip"), ngx_string("gz"),   NULL },
    { ngx_null_string,    ngx_null_string,    NULL }
};


static char *
ngx_http_compression_static_order(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_compression_static_conf_t *ccf = conf;

    ngx_str_t                              *value;
    ngx_uint_t                              i, j, k;
    ngx_http_compression_static_coding_t   *c, **cp, **list;

    (void) cmd;

    if (ccf->order != NULL && ccf->order->nelts > 0) {
        return "is duplicate";
    }

    ccf->order = ngx_array_create(cf->pool, cf->args->nelts - 1,
                        sizeof(ngx_http_compression_static_coding_t *));
    if (ccf->order == NULL) {
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
        list = ccf->order->elts;
        for (j = 0; j < ccf->order->nelts; j++) {
            if (list[j] == c) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "duplicate coding \"%V\" in "
                                   "\"compression_static_order\"",
                                   &value[i]);
                return NGX_CONF_ERROR;
            }
        }

        cp = ngx_array_push(ccf->order);
        if (cp == NULL) {
            return NGX_CONF_ERROR;
        }
        *cp = c;
    }

    return NGX_CONF_OK;
}


/* shipped default: br zstd gzip — static prefers br because its CPU
 * was spent at build time (the deliberate filter/static asymmetry) */
static ngx_int_t
ngx_http_compression_static_default_order(ngx_conf_t *cf,
    ngx_http_compression_static_conf_t *conf)
{
    ngx_uint_t                              i;
    static ngx_uint_t                       def[3] = { 1, 0, 2 };
    ngx_http_compression_static_coding_t  **cp;

    conf->order = ngx_array_create(cf->pool, 3,
                         sizeof(ngx_http_compression_static_coding_t *));
    if (conf->order == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < 3; i++) {
        cp = ngx_array_push(conf->order);
        if (cp == NULL) {
            return NGX_ERROR;
        }
        *cp = &ngx_http_compression_static_codings[def[i]];
    }

    return NGX_OK;
}


#if (NGX_HTTP_COMPRESSION_STATIC_HAVE_PROBE)

/*
 * Pure frame-header probe (parent #159): decides the leading frame of a
 * .zst file from the first `n` bytes read at some offset. No I/O, no
 * logging, no request state — the arithmetic only. Reads at most 18
 * bytes and never past `n`; every layout path checks it got the bytes
 * that layout requires. On FRAME_WINDOW_BIG the declared window is
 * stored through `window`; on FRAME_SKIP the skippable frame's 4-byte
 * little-endian declared skip length (RFC 8878 §3.2) is stored there
 * instead — same out-param, different unit, read only against the
 * matching verdict. Hardcoded magic constants, not zstd.h: the static
 * module links no compression library.
 */
static ngx_int_t
ngx_http_compression_static_probe_frame(const u_char *hdr, size_t n,
    uint64_t *window)
{
    uint32_t    mw;
    uint64_t    w;
    ngx_uint_t  i, fhd, fcs_size, off;

    static const ngx_uint_t  did_len[4] = { 0, 1, 2, 4 };

    mw = ((uint32_t) hdr[0])
       | ((uint32_t) hdr[1] << 8)
       | ((uint32_t) hdr[2] << 16)
       | ((uint32_t) hdr[3] << 24);

    if (mw != NGX_HTTP_COMPRESSION_STATIC_ZSTD_MAGIC
        && (mw & NGX_HTTP_COMPRESSION_STATIC_SKIPPABLE_MASK)
           != NGX_HTTP_COMPRESSION_STATIC_SKIPPABLE_START)
    {
        return NGX_HTTP_COMPRESSION_STATIC_FRAME_NOT_ZSTD;
    }

    /*
     * Skippable frame: magic(4) + Frame_Size(4, LE) + Frame_Size opaque
     * bytes. There is no window here, only a length to jump, so the
     * caller must resolve the skip (bounded) and probe the frame that
     * follows — an attacker-controlled skippable prefix must not dodge
     * the window check on the frame that actually decodes. That was the
     * bug: OK-ing every skippable magic let a one-frame-longer file
     * bypass the 8 MB guard entirely.
     */
    if (mw != NGX_HTTP_COMPRESSION_STATIC_ZSTD_MAGIC) {
        if (n < 8) {
            return NGX_HTTP_COMPRESSION_STATIC_FRAME_TRUNCATED;
        }

        *window = ((uint64_t) hdr[4])
                | ((uint64_t) hdr[5] << 8)
                | ((uint64_t) hdr[6] << 16)
                | ((uint64_t) hdr[7] << 24);

        return NGX_HTTP_COMPRESSION_STATIC_FRAME_SKIP;
    }

    /* declared-window check on the leading regular frame (RFC 8878) */
    if (n < 5) {
        return NGX_HTTP_COMPRESSION_STATIC_FRAME_TRUNCATED;
    }

    fhd = hdr[4];

    if (!(fhd & 0x20)) {
        /* Window_Descriptor follows */
        if (n < 6) {
            return NGX_HTTP_COMPRESSION_STATIC_FRAME_TRUNCATED;
        }

        w = (uint64_t) 1 << (10 + (hdr[5] >> 3));
        w += (w >> 3) * (hdr[5] & 7);

    } else {
        /* Single_Segment: window = frame content size, behind the
         * optional dictionary id */
        fcs_size = (fhd >> 6) ? ((ngx_uint_t) 1 << (fhd >> 6)) : 1;
        off = 5 + did_len[fhd & 3];

        if (n < off + fcs_size) {
            return NGX_HTTP_COMPRESSION_STATIC_FRAME_TRUNCATED;
        }

        w = 0;
        for (i = 0; i < fcs_size; i++) {
            w |= (uint64_t) hdr[off + i] << (8 * i);
        }

        if (fcs_size == 2) {
            w += 256;  /* RFC 8878: the 2-byte field is offset */
        }
    }

    if (w > NGX_HTTP_COMPRESSION_STATIC_MAX_WINDOW) {
        *window = w;
        return NGX_HTTP_COMPRESSION_STATIC_FRAME_WINDOW_BIG;
    }

    return NGX_HTTP_COMPRESSION_STATIC_FRAME_OK;
}


/*
 * The probe's only platform-dependent step (parent #162): fetch up to
 * `size` bytes from `offset` WITHOUT moving the descriptor's file
 * position — pread(2) on POSIX, ngx_read_file() (offset-explicit
 * ReadFile via OVERLAPPED) on Win32. Everything else is shared, so the
 * two platforms cannot drift. Returns the byte count, or -1 on error,
 * matching pread(2) so the caller's short-read handling is unchanged.
 */
static ssize_t
ngx_http_compression_static_pread(ngx_fd_t fd, u_char *buf, size_t size,
    off_t offset, ngx_log_t *log, ngx_str_t *name)
{
#if (NGX_WIN32)
    ssize_t     n;
    ngx_file_t  file;

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.fd = fd;
    file.log = log;
    file.name = *name;

    n = ngx_read_file(&file, buf, size, offset);

    if (n == NGX_ERROR) {
        return -1;
    }

    return n;
#else
    (void) log;
    (void) name;

    return pread(fd, buf, size, offset);
#endif
}

#endif /* NGX_HTTP_COMPRESSION_STATIC_HAVE_PROBE */


/*
 * The parent zstd_static probe (ported): magic sanity (a truncated /
 * half-downloaded / mistakenly-renamed file must not be served as zstd)
 * plus the declared-window cap on the leading REGULAR frame — reached
 * by walking a bounded chain of leading skippable frames so the guard
 * cannot be dodged by prepending one (parent #159). Reads are
 * offset-explicit (parent #162: pread(2)/ngx_read_file()) so they never
 * corrupt the open_file_cache's shared fd position. Under directio the
 * read is block-aligned at max(4096, directio_alignment) into an
 * equally aligned buffer, and a failed aligned read DECLINES — for a
 * validation read, falling back beats certifying a file we could not
 * inspect. Runs on Win32 too now (parent #162).
 */
static ngx_int_t
ngx_http_compression_static_check_zstd(ngx_http_request_t *r,
    ngx_open_file_info_t *of, ngx_http_core_loc_conf_t *clcf,
    ngx_str_t *path)
{
#if (NGX_HTTP_COMPRESSION_STATIC_HAVE_PROBE)
    u_char      hdrbuf[18];
    u_char     *hdr, *frame;
    size_t      want, align, frame_off, avail;
    ssize_t     n;
    uint64_t    window, skip;
    ngx_uint_t  frames;
    off_t       pos, base;
    ngx_log_t  *log;

    log = r->connection->log;

    if (of->size < 4) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "compression static: \"%V\" too small to be a zstd "
                      "frame (%O bytes)", path, of->size);
        return NGX_DECLINED;
    }

    if (of->is_directio) {
        align = NGX_HTTP_COMPRESSION_STATIC_DIO_PROBE;
        if ((size_t) clcf->directio_alignment > align) {
            align = (size_t) clcf->directio_alignment;
        }

        /*
         * TWO blocks, not one (parent #197). The probe offset is rounded
         * down to `align` — an O_DIRECT descriptor rejects an unaligned
         * file offset with EINVAL — so a frame header can start as late
         * as align-1 bytes into the first block and would then straddle
         * the boundary; parsing only one block would misreport that
         * legitimate frame as truncated. A second block guarantees at
         * least `align` (>= 4096) bytes behind any in-block start, far
         * more than the 18 a frame header needs. Both the length and the
         * buffer stay `align`-aligned, which is what O_DIRECT requires.
         */
        want = align * 2;

        hdr = ngx_pmemalign(r->pool, want, align);
        if (hdr == NULL) {
            return NGX_ERROR;
        }

    } else {
        align = 0;
        hdr = hdrbuf;
        want = sizeof(hdrbuf);
    }

    pos = 0;

    /*
     * Walk a bounded chain of leading skippable frames to reach the
     * first regular frame. Each iteration reads at the current offset.
     * Under directio the O_DIRECT descriptor rejects an unaligned file
     * offset with EINVAL, and `pos` after a leading skippable frame is
     * whatever that frame's length made it (40 for the canonical dcz
     * SHA-256 prefix) — almost never a block multiple. So the read
     * offset is rounded DOWN to `align` and the frame is parsed at its
     * offset inside the block: `base` is the aligned read offset,
     * `frame_off` the distance from there to `pos`, and `avail` the
     * bytes of the read that lie at or after `pos`. Off the directio
     * path `base == pos`, `frame_off == 0`, `avail == n` — byte-for-byte
     * the previous behaviour (parent #197).
     */
    for (frames = 0; ; frames++) {

        if (frames >= NGX_HTTP_COMPRESSION_STATIC_MAX_SKIP_FRAMES) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "compression static: \"%V\" has more than %ui "
                          "leading skippable frames — declining rather "
                          "than searching further for the first regular "
                          "frame", path,
                          (ngx_uint_t)
                              NGX_HTTP_COMPRESSION_STATIC_MAX_SKIP_FRAMES);
            return NGX_DECLINED;
        }

        if (of->is_directio) {
            frame_off = (size_t) ((uint64_t) pos % (uint64_t) align);
            base = pos - (off_t) frame_off;

        } else {
            frame_off = 0;
            base = pos;
        }

        n = ngx_http_compression_static_pread(of->fd, hdr, want, base, log,
                                              path);

        /*
         * Bytes of the block that lie at or after `pos`. A short read
         * that stopped inside the prefix leaves nothing for the frame,
         * the same "too few bytes" condition as a short read at offset 0
         * and taking the same branch.
         */
        avail = ((size_t) (n > 0 ? n : 0) > frame_off)
                    ? (size_t) n - frame_off : 0;

        frame = hdr + frame_off;

        if (n < 0 || avail < 4) {
            if (of->is_directio) {
                ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                              "compression static: %uz-byte aligned probe "
                              "on directio file \"%V\" returned %z — "
                              "declining; check directio_alignment against "
                              "the device geometry", align, path, n);
                return NGX_DECLINED;
            }

            ngx_log_error(NGX_LOG_CRIT, log, ngx_errno,
                          "compression static: "
                          NGX_HTTP_COMPRESSION_STATIC_PREAD_NAME
                          "(\"%V\", frame header) returned %z", path, n);
            return NGX_DECLINED;
        }

        if (of->is_directio) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                           "compression static: %uz-byte aligned probe on "
                           "directio file \"%V\"", align, path);
        }

        switch (ngx_http_compression_static_probe_frame(frame, avail,
                                                        &window))
        {

        case NGX_HTTP_COMPRESSION_STATIC_FRAME_NOT_ZSTD:
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "compression static: \"%V\" is not a zstd frame "
                          "(leading bytes 0x%02xd%02xd%02xd%02xd)", path,
                          (ngx_uint_t) frame[0], (ngx_uint_t) frame[1],
                          (ngx_uint_t) frame[2], (ngx_uint_t) frame[3]);
            return NGX_DECLINED;

        case NGX_HTTP_COMPRESSION_STATIC_FRAME_TRUNCATED:
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "compression static: \"%V\" frame header "
                          "truncated", path);
            return NGX_DECLINED;

        case NGX_HTTP_COMPRESSION_STATIC_FRAME_WINDOW_BIG:
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "compression static: \"%V\" declares a %uL-byte "
                          "decompression window, above the 8 MB limit "
                          "browsers enforce for Content-Encoding: zstd "
                          "(RFC 8878) — declining so a fallback coding is "
                          "used; recompress with a window log <= 23", path,
                          window);
            return NGX_DECLINED;

        case NGX_HTTP_COMPRESSION_STATIC_FRAME_SKIP:

            /*
             * `window` carries the declared skip length here. Prove the
             * 8-byte skippable header AND the full declared skip both
             * fit within of->size before trusting the jump — checked
             * arithmetic throughout, since `skip` is attacker-controlled
             * and wide enough to overflow a 32-bit add on its own.
             */
            skip = window;

            if ((uint64_t) pos > (uint64_t) of->size
                || (uint64_t) of->size - (uint64_t) pos < 8)
            {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "compression static: \"%V\" skippable frame "
                              "header runs past end of file", path);
                return NGX_DECLINED;
            }

            if (skip > (uint64_t) of->size - (uint64_t) pos - 8) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "compression static: \"%V\" skippable frame "
                              "declares a %uL-byte skip past end of file",
                              path, skip);
                return NGX_DECLINED;
            }

            pos += (off_t) 8 + (off_t) skip;

            continue;

        default:
            break;
        }

        break;
    }

#else
    (void) r; (void) of; (void) clcf; (void) path;
#endif

    return NGX_OK;
}




static ngx_int_t
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
    ngx_list_part_t                        *part;
    ngx_table_elt_t                        *h, *ae;
    ngx_open_file_info_t                    of;
    ngx_http_core_loc_conf_t               *clcf;
    ngx_http_compression_static_conf_t     *conf;
    ngx_http_compression_static_coding_t   *c, **order;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_DECLINED;
    }

    if (r->uri.len == 0 || r->uri.data[r->uri.len - 1] == '/') {
        return NGX_DECLINED;
    }

    conf = ngx_http_get_module_loc_conf(r,
                                        ngx_http_compression_static_module);

    if (conf->enable == NGX_HTTP_COMPRESSION_STATIC_OFF) {
        return NGX_DECLINED;
    }

    /*
     * PHASE3 (found in the production soak): a request that both
     * HOLDS a dictionary (Available-Dictionary) and explicitly
     * accepts a dictionary coding can be served dramatically smaller
     * by the FILTER module's dcz/dcb delta path than by any
     * precompressed sidecar — but this handler runs first in the
     * content phase and would serve the sidecar before negotiation
     * ever happens. compression_static_dict_bypass makes this
     * handler stand aside for exactly those requests, in BOTH on and
     * always modes. Opt-in per location (deploy tooling emits it
     * beside compression_dict_file), default off so a static-only
     * deployment never serves identity to dict-capable clients. The
     * check runs BEFORE the Vary delegation below on purpose: a
     * declined request must not carry a delegated AE line beside the
     * filter's combined one (the split-Vary cache hazard). Documented
     * tradeoff: an Available-Dictionary that misses the filter's
     * store pays runtime compression instead of the sidecar — rare
     * by construction, since clients only advertise dictionaries
     * whose match pattern covers the URL.
     *
     * Main requests only (parent #222's gate, which this port
     * originally lacked): a subrequest inherits the main request's
     * headers_in, but the filter never negotiates a dictionary
     * coding for subrequests — standing aside would hand the
     * subrequest to a filter that cannot dcz/dcb it, losing the
     * sidecar with zero upside.
     *
     * NO secure-context precheck, deliberately: the honest check is
     * "ssl || assume_secure" and the ack lives in the filter's conf,
     * unreadable across the module split — while a bare-ssl shortcut
     * would misfire in exactly the TLS-terminating-proxy topology the
     * ack exists for. The cost of not checking lands only on
     * hand-built clients: browsers gate dictionary advertisement on
     * secure contexts CLIENT-side, so over genuine cleartext no
     * browser sends Available-Dictionary and the bypass never fires.
     */
    if (conf->dict_bypass && r == r->main) {

        part = &r->headers_in.headers.part;
        h = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    h = NULL;
                    break;
                }
                part = part->next;
                h = part->elts;
                i = 0;
            }

            if (h[i].key.len == sizeof("Available-Dictionary") - 1
                && ngx_strncasecmp(h[i].key.data,
                                   (u_char *) "Available-Dictionary",
                                   sizeof("Available-Dictionary") - 1) == 0)
            {
                h = &h[i];
                break;
            }
        }

        if (h != NULL) {
            ae = ngx_http_compression_ae_header(r);

            if (ae != NULL
                && ae->value.len != 0
                && (ngx_http_compression_coding_weight(&ae->value,
                        &ngx_http_compression_static_dcz, 0) > 0
                    || ngx_http_compression_coding_weight(&ae->value,
                        &ngx_http_compression_static_dcb, 0) > 0))
            {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "compression static: standing aside for "
                               "dictionary negotiation");
                return NGX_DECLINED;
            }
        }
    }

    ae = NULL;

    if (conf->enable == NGX_HTTP_COMPRESSION_STATIC_ON) {
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

    order = conf->order->elts;

    for (i = 0; i < conf->order->nelts; i++) {

        c = order[i];

        if (conf->enable == NGX_HTTP_COMPRESSION_STATIC_ON) {
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

        /*
         * HEAD fast path (parent #179): the response headers already
         * carry everything a HEAD needs — Content-Encoding above and the
         * Vary line emitted earlier in the negotiated path — so send them
         * and skip the body buffer + ngx_file_t allocations below. Strict
         * r->method == NGX_HTTP_HEAD, NOT r->header_only: the latter also
         * covers 304/204, whose existing header_only return past the
         * body-buffer setup stays correct.
         */
        if (r->method == NGX_HTTP_HEAD) {
            return ngx_http_send_header(r);
        }

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

static void *
ngx_http_compression_static_create_main_conf(ngx_conf_t *cf)
{
    /* pcalloc zeroes any_enabled — cycle-owned, no reset hook needed */
    return ngx_pcalloc(cf->pool,
                       sizeof(ngx_http_compression_static_main_conf_t));
}


/*
 * "compression_static off|on|always" (parent #182): the standard enum
 * slot plus a parse-time latch of the cycle-global any_enabled bit, so
 * postconfiguration can skip the content-phase handler when static
 * serving is off in every location. Latched for "on"/"always", not "off".
 */
static char *
ngx_http_compression_static_set_enable_slot(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_str_t                                *value;
    char                                     *rc;
    ngx_http_compression_static_main_conf_t  *smcf;

    rc = ngx_conf_set_enum_slot(cf, cmd, conf);
    if (rc != NGX_CONF_OK) {
        return rc;
    }

    /* value[1] is "off", "on", or "always" — the enum already rejected
     * anything else above. */
    value = cf->args->elts;
    if (value[1].len == 3 && ngx_strncmp(value[1].data, "off", 3) == 0) {
        return NGX_CONF_OK;
    }

    smcf = ngx_http_conf_get_module_main_conf(cf,
                                        ngx_http_compression_static_module);
    smcf->any_enabled = 1;

    return NGX_CONF_OK;
}


static void *
ngx_http_compression_static_create_conf(ngx_conf_t *cf)
{
    ngx_http_compression_static_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_compression_static_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET_UINT;
    conf->order = NULL;     /* NULL = inherit / shipped default */
    conf->dict_bypass = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_compression_static_merge_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_http_compression_static_conf_t *prev = parent;
    ngx_http_compression_static_conf_t *conf = child;

    ngx_conf_merge_uint_value(conf->enable, prev->enable,
                              NGX_HTTP_COMPRESSION_STATIC_OFF);
    ngx_conf_merge_value(conf->dict_bypass, prev->dict_bypass, 0);

    if (conf->order == NULL) {
        conf->order = prev->order;
    }

    if (conf->order == NULL) {
        if (ngx_http_compression_static_default_order(cf, conf) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    /*
     * No "gzip_vary off" warning any more (parent #163): the handler's
     * negotiated path calls ngx_http_compression_vary(), which now
     * emits Vary: Accept-Encoding by construction regardless of the
     * gzip_vary directive. "always" mode ignores Accept-Encoding and
     * deliberately does not call it, so it still carries no Vary — the
     * correct behaviour for a non-negotiated response.
     */

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_compression_static_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt                      *h;
    ngx_http_core_main_conf_t                *cmcf;
    ngx_http_compression_static_main_conf_t  *smcf;

    /*
     * Skip registering the content-phase handler when "compression_static"
     * is off in every location (parent #182). any_enabled is latched at
     * directive parse time, so a build that carries the static module but
     * never enables it pays no per-request always-declining handler.
     */
    smcf = ngx_http_conf_get_module_main_conf(cf,
                                        ngx_http_compression_static_module);
    if (smcf == NULL || !smcf->any_enabled) {
        return NGX_OK;
    }

    /* the content phase, exactly like gzip_static and the parent
     * *_static modules */
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_compression_static_handler;

    return NGX_OK;
}
