/*
 * nginx-compression — phase-0 prototype core (RFC: nginx-zstd-module
 * #109). One filter module, N backends, election by compression_order,
 * gzip by defer/veto. Throwaway by charter: the deliverable is the
 * backend interface and the seams, not production polish — the known
 * shortcuts are marked "PHASE0:" and collected in WRINKLES.md.
 */

#include "ngx_http_compression.h"
#include "ngx_http_compression_ae.h"
#include "ngx_http_compression_dict.h"


#if (NGX_HTTP_COMPRESSION_HAVE_ZSTD)
extern ngx_http_compression_backend_t  *ngx_http_compression_backend_zstd;
#endif
#if (NGX_HTTP_COMPRESSION_HAVE_BROTLI)
extern ngx_http_compression_backend_t  *ngx_http_compression_backend_brotli;
#endif

/* filled densely in preconfiguration (add_backends); static storage
 * zero-fills the NULL terminator for every NBACKENDS value */
ngx_http_compression_backend_t
    *ngx_http_compression_backends[NGX_HTTP_COMPRESSION_NBACKENDS + 1];


/* conf struct + token type moved to ngx_http_compression.h in phase 2:
 * the static handler TU shares them */


typedef struct {
    ngx_http_compression_backend_t  *backend;
    void                            *bctx;
    ngx_chain_t                     *in;
    ngx_buf_t                       *ob;        /* current output buf */
    size_t                           out_size;

    /*
     * PHASE3: output-buffer recycling (the gzip filter's busy/free
     * pattern). Shipped bufs sit on `busy` until downstream drains
     * them; ngx_chain_update_chains reclaims drained ones onto
     * `free`, and get_buf prefers a reclaimed buf over a fresh
     * allocation. `allocated` counts live temp bufs against the
     * compression_buffers cap; at the cap with nothing reclaimable,
     * `nomem` stops production until a later invocation flushes the
     * busy chain — the backstop that keeps a slow client from pinning
     * unbounded output memory.
     */
    ngx_chain_t                     *free;
    ngx_chain_t                     *busy;
    ngx_uint_t                       allocated;
    ngx_uint_t                       bufs_num;

    /*
     * PHASE1b: the elected dictionary variant's wire prologue,
     * prepared at election time and emitted ahead of the first
     * encoder byte (40 bytes dcz, 36 dcb; 0 = base coding).
     */
    u_char                           prologue[40];
    size_t                           prologue_len;

    unsigned                         done:1;
    unsigned                         started:1; /* encoder has consumed
                                                 * input: it (and maybe
                                                 * ctx->ob) holds bytes
                                                 * until FINISH drains —
                                                 * drives r->buffered */
    unsigned                         prologue_sent:1;
    unsigned                         nomem:1;
} ngx_http_compression_ctx_t;


static ngx_int_t ngx_http_compression_add_backends(ngx_conf_t *cf);
static void *ngx_http_compression_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_compression_create_conf(ngx_conf_t *cf);
static char *ngx_http_compression_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_compression_order(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_compression_level_cmd(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_compression_window_cmd(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_compression_buffers_cmd(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_compression_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_compression_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_compression_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);


static ngx_conf_enum_t  ngx_http_compression_static_enum[] = {
    { ngx_string("off"), NGX_HTTP_COMPRESSION_STATIC_OFF },
    { ngx_string("on"), NGX_HTTP_COMPRESSION_STATIC_ON },
    { ngx_string("always"), NGX_HTTP_COMPRESSION_STATIC_ALWAYS },
    { ngx_null_string, 0 }
};


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

    { ngx_string("compression_level"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_compression_level_cmd,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("compression_window"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_compression_window_cmd,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("compression_bypass"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_set_predicate_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_compression_conf_t, bypass),
      NULL },

    { ngx_string("compression_bypass_vary"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_compression_conf_t, bypass_vary),
      NULL },

    { ngx_string("compression_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_compression_buffers_cmd,
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

    { ngx_string("compression_dict_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_compression_dict_file,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_compression_conf_t, dicts),
      NULL },

    { ngx_string("compression_static"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_compression_conf_t, static_enable),
      &ngx_http_compression_static_enum },

    { ngx_string("compression_static_order"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_compression_static_order,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_compression_module_ctx = {
    ngx_http_compression_add_backends,     /* preconfiguration */
    ngx_http_compression_init,             /* postconfiguration */

    ngx_http_compression_create_main_conf, /* create main configuration */
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


/*
 * Vary: Accept-Encoding, requested once per response through whichever
 * mechanism this build has (see the header). Both the filter and the
 * static handler call this BEFORE their accept checks, so identity
 * fallbacks vary too.
 */
ngx_int_t
ngx_http_compression_vary(ngx_http_request_t *r)
{
#if (NGX_HTTP_GZIP)
    r->gzip_vary = 1;
    return NGX_OK;
#else
    ngx_table_elt_t  *v;

    v = ngx_list_push(&r->headers_out.headers);
    if (v == NULL) {
        return NGX_ERROR;
    }
    v->hash = 1;
    v->next = NULL;
    ngx_str_set(&v->key, "Vary");
    ngx_str_set(&v->value, "Accept-Encoding");
    return NGX_OK;
#endif
}


ngx_table_elt_t *
ngx_http_compression_ae_header(ngx_http_request_t *r)
{
#if (NGX_HTTP_GZIP)
    return r->headers_in.accept_encoding;
#else
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
#endif
}


/*
 * PHASE1b: RFC 9842 negotiation. The client names the dictionary it
 * holds via Available-Dictionary — an RFC 8941 Byte Sequence, i.e.
 * `:<base64 of the raw SHA-256>:` — and it matches (or doesn't)
 * against this location's list of store entries. First match wins;
 * the lists are short by construction (a handful of dictionaries per
 * location), so a linear scan is the right tool.
 */
static ngx_http_compression_dict_t *
ngx_http_compression_match_dict(ngx_http_request_t *r,
    ngx_http_compression_conf_t *conf)
{
    /*
     * Decode target: sized by ngx_base64_decoded_length(44) = 33, NOT
     * by the hash length — the macro is an upper bound that ignores
     * padding, and a pad-less 44-char value legitimately decodes to
     * 33 bytes. Sizing this at 32 was a one-byte overflow waiting for
     * a malicious header; the dst.len == 32 check below rejects that
     * input AFTER it decoded safely.
     */
    u_char                         raw[36];
    u_char                        *p, *last;
    ngx_str_t                      b64, dst;
    ngx_uint_t                     i;
    ngx_list_part_t               *part;
    ngx_table_elt_t               *h, *ad;
    ngx_http_compression_dict_t  **list;

    if (conf->dicts == NULL || conf->dicts->nelts == 0) {
        return NULL;
    }

    /* no built-in field for Available-Dictionary: generic list walk */
    ad = NULL;
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

        if (h[i].key.len == sizeof("Available-Dictionary") - 1
            && ngx_strncasecmp(h[i].key.data,
                               (u_char *) "Available-Dictionary",
                               sizeof("Available-Dictionary") - 1) == 0)
        {
            ad = &h[i];
            break;
        }
    }

    if (ad == NULL || ad->value.len == 0) {
        return NULL;
    }

    /* strict RFC 8941 byte-sequence shape: OWS ":" base64 ":" OWS */
    p = ad->value.data;
    last = ad->value.data + ad->value.len;

    while (p < last && (*p == ' ' || *p == '\t')) { p++; }
    while (last > p && (last[-1] == ' ' || last[-1] == '\t')) { last--; }

    if (last - p < 2 || *p != ':' || last[-1] != ':') {
        return NULL;    /* malformed: negotiate nothing, serve base */
    }

    b64.data = p + 1;
    b64.len = (last - 1) - (p + 1);

    /*
     * base64 of exactly 32 bytes is exactly 44 characters. Checked by
     * ENCODED length, not ngx_base64_decoded_length() — that macro is
     * an upper bound that ignores '=' padding (44 chars → 33), and
     * comparing it against 32 rejected every valid header this
     * negotiation exists to read (caught by the fallback matrix: all
     * dict elections silently degraded to base codings).
     */
    if (b64.len != 44) {
        return NULL;
    }

    dst.data = raw;
    if (ngx_decode_base64(&dst, &b64) != NGX_OK
        || dst.len != NGX_HTTP_COMPRESSION_SHA256_LEN)
    {
        return NULL;
    }

    list = conf->dicts->elts;
    for (i = 0; i < conf->dicts->nelts; i++) {
        if (ngx_memcmp(list[i]->sha256, raw,
                       NGX_HTTP_COMPRESSION_SHA256_LEN) == 0)
        {
            return list[i];
        }
    }

    return NULL;
}


/* the gzip-less Accept-Encoding walk moved into
 * ngx_http_compression_ae_header() above (phase 2: the static handler
 * needs it too) */


static ngx_int_t
ngx_http_compression_add_backends(ngx_conf_t *cf)
{
    ngx_uint_t  n;

    (void) cf;

    /*
     * Filled here rather than by static initializer only because the
     * backends live in separate TUs exporting pointers. Fill is DENSE
     * under the HAVE guards — a library-less build compacts the
     * registry instead of leaving a hole, so registry position stays
     * a valid conf-slot index everywhere.
     */
    n = 0;

#if (NGX_HTTP_COMPRESSION_HAVE_ZSTD)
    ngx_http_compression_backends[n++] = ngx_http_compression_backend_zstd;
#endif

#if (NGX_HTTP_COMPRESSION_HAVE_BROTLI)
    ngx_http_compression_backends[n++] = ngx_http_compression_backend_brotli;
#endif

    ngx_http_compression_backends[n] = NULL;

    return ngx_http_compression_dict_add_variables(cf);
}


static void *
ngx_http_compression_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_compression_main_conf_t  *cmcf;

    cmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_compression_main_conf_t));
    if (cmcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&cmcf->store, cf->pool, 4,
                       sizeof(ngx_http_compression_dict_t *))
        != NGX_OK)
    {
        return NULL;
    }

    /* pcalloc zeroes dicts_hashed — cycle-owned, no reset hook */

    return cmcf;
}


/*
 * PHASE3 tuning directives. Phase 0 rejected one unified level VALUE
 * (zstd 3 and brotli 6 are both "the sane default" yet share no axis
 * — wrinkle #8); what survives is one unified level NAME, keyed by
 * coding: `compression_level zstd 9` / `compression_level br 11`.
 * The backend declares its scale's bounds and default in the vtable,
 * so a new coding gets both directives for free with its registry
 * entry — and the tokens that are NOT backends (gzip, dcz/dcb) get
 * educational rejections instead of silently doing nothing.
 */

/*
 * Coding names whose backend is compiled OUT of this build, for
 * error text: "unknown coding" would be wrong advice when the fix is
 * the build line, not the config. Returns NULL when the token is not
 * a compiled-out coding.
 */
static const char *
ngx_http_compression_absent_coding(ngx_str_t *token)
{
#if !(NGX_HTTP_COMPRESSION_HAVE_ZSTD)
    if ((token->len == 4 && ngx_strncmp(token->data, "zstd", 4) == 0)
        || (token->len == 3 && ngx_strncmp(token->data, "dcz", 3) == 0))
    {
        return "zstd";
    }
#endif

#if !(NGX_HTTP_COMPRESSION_HAVE_BROTLI)
    if ((token->len == 2 && ngx_strncmp(token->data, "br", 2) == 0)
        || (token->len == 3 && ngx_strncmp(token->data, "dcb", 3) == 0))
    {
        return "brotli";
    }
#endif

    (void) token;
    return NULL;
}


/*
 * Resolve a directive's coding token to a registry index. Returns
 * NGX_ERROR after logging when the token is known but not tunable
 * here (gzip, dict codings) or unknown entirely; `what` names the
 * directive for the message.
 */
static ngx_int_t
ngx_http_compression_tuning_index(ngx_conf_t *cf, ngx_str_t *token,
    const char *what)
{
    ngx_int_t                        i;
    ngx_http_compression_backend_t  *b;

    /* terminator-walked, not count-walked: compiles warning-free at
     * every NBACKENDS including zero */
    for (i = 0; ngx_http_compression_backends[i] != NULL; i++) {
        b = ngx_http_compression_backends[i];

        if (token->len == b->coding.len
            && ngx_strncmp(token->data, b->coding.data, token->len) == 0)
        {
            return i;
        }

        if (b->dict_coding.len != 0
            && token->len == b->dict_coding.len
            && ngx_strncmp(token->data, b->dict_coding.data,
                           token->len) == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"%V\" is tuned through its base coding: "
                               "use \"%s %V ...\" (a dictionary variant "
                               "shares the base coding's parameters)",
                               token, what, &b->coding);
            return NGX_ERROR;
        }
    }

    if (token->len == 4 && ngx_strncmp(token->data, "gzip", 4) == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "gzip is compressed by the core gzip filter "
                           "(defer/veto): tune it with the core "
                           "\"gzip_comp_level\" directive, not \"%s\"",
                           what);
        return NGX_ERROR;
    }

    {
        const char  *absent = ngx_http_compression_absent_coding(token);

        if (absent != NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "coding \"%V\" in \"%s\" is not available: "
                               "this nginx was built without %s support",
                               token, what, absent);
            return NGX_ERROR;
        }
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "unknown coding \"%V\" in \"%s\"", token, what);
    return NGX_ERROR;
}


static char *
ngx_http_compression_level_cmd(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_compression_conf_t *ccf = conf;

    u_char                          *p;
    size_t                           len;
    ngx_int_t                        i, n;
    ngx_str_t                       *value;
    ngx_uint_t                       neg;
    ngx_http_compression_backend_t  *b;

    (void) cmd;

    value = cf->args->elts;

    i = ngx_http_compression_tuning_index(cf, &value[1],
                                          "compression_level");
    if (i == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    b = ngx_http_compression_backends[i];

    /* ngx_atoi has no sign handling; zstd's fast levels are negative */
    p = value[2].data;
    len = value[2].len;
    neg = 0;

    if (len > 0 && p[0] == '-') {
        neg = 1;
        p++;
        len--;
    }

    n = ngx_atoi(p, len);
    if (n == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid level \"%V\" in \"compression_level\"",
                           &value[2]);
        return NGX_CONF_ERROR;
    }

    if (neg) {
        n = -n;
    }

    if (n < b->level_min || n > b->level_max) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "compression level for \"%V\" must be between "
                           "%i and %i", &b->coding, b->level_min,
                           b->level_max);
        return NGX_CONF_ERROR;
    }

    if (ccf->levels[i] != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    ccf->levels[i] = n;

    return NGX_CONF_OK;
}


/*
 * compression_buffers <num> [size] — TAKE12 rather than the stock
 * bufs slot's TAKE2 because size is genuinely optional here: the
 * backend already recommends a step size (out_size), so most
 * operators only ever want the COUNT cap. An explicit size overrides
 * the recommendation; the dict-prologue clamp applies to either.
 */
static char *
ngx_http_compression_buffers_cmd(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_compression_conf_t *ccf = conf;

    ssize_t     size;
    ngx_int_t   n;
    ngx_str_t  *value;

    (void) cmd;

    if (ccf->bufs.num != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    n = ngx_atoi(value[1].data, value[1].len);
    if (n == NGX_ERROR || n < 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid number \"%V\" in \"compression_buffers\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    size = 0;   /* backend-recommended */

    if (cf->args->nelts == 3) {
        size = ngx_parse_size(&value[2]);
        if (size == NGX_ERROR || size == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid size \"%V\" in "
                               "\"compression_buffers\"", &value[2]);
            return NGX_CONF_ERROR;
        }
    }

    ccf->bufs.num = n;
    ccf->bufs.size = (size_t) size;

    return NGX_CONF_OK;
}


static char *
ngx_http_compression_window_cmd(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_compression_conf_t *ccf = conf;

    ssize_t                          size;
    ngx_int_t                        i, bits;
    ngx_str_t                       *value;
    ngx_http_compression_backend_t  *b;

    (void) cmd;

    value = cf->args->elts;

    i = ngx_http_compression_tuning_index(cf, &value[1],
                                          "compression_window");
    if (i == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    b = ngx_http_compression_backends[i];

    size = ngx_parse_size(&value[2]);
    if (size == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid size \"%V\" in \"compression_window\"",
                           &value[2]);
        return NGX_CONF_ERROR;
    }

    /* the window is a power of two by both formats' definition; the
     * directive takes the human SIZE (512k, 8m) and stores its log2 */
    for (bits = b->window_bits_min; bits <= b->window_bits_max; bits++) {
        if (size == (ssize_t) 1 << bits) {
            break;
        }
    }

    if (bits > b->window_bits_max) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "compression window for \"%V\" must be a "
                           "power-of-two size between %uz and %uz bytes",
                           &b->coding,
                           (size_t) 1 << b->window_bits_min,
                           (size_t) 1 << b->window_bits_max);
        return NGX_CONF_ERROR;
    }

    if (ccf->window_bits[i] != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    ccf->window_bits[i] = bits;

    return NGX_CONF_OK;
}


static void *
ngx_http_compression_create_conf(ngx_conf_t *cf)
{
    ngx_uint_t                    i;
    ngx_http_compression_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_compression_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->min_length = NGX_CONF_UNSET;
    conf->order = NULL;     /* NULL = inherit / shipped default */
    conf->static_enable = NGX_CONF_UNSET_UINT;
    conf->bufs.num = NGX_CONF_UNSET;
    conf->bypass = NGX_CONF_UNSET_PTR;

    for (i = 0; i < NGX_HTTP_COMPRESSION_CONF_SLOTS; i++) {
        conf->levels[i] = NGX_CONF_UNSET;
        conf->window_bits[i] = NGX_CONF_UNSET;
    }

    return conf;
}


static char *
ngx_http_compression_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_compression_conf_t *prev = parent;
    ngx_http_compression_conf_t *conf = child;

    ngx_uint_t                     i;
    ngx_http_compression_token_t  *t;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->min_length, prev->min_length, 20);

    ngx_conf_merge_ptr_value(conf->bypass, prev->bypass, NULL);
    ngx_conf_merge_str_value(conf->bypass_vary, prev->bypass_vary, "");

    /*
     * compression_bypass_vary only makes sense beside a bypass
     * predicate: it names the request header the bypass decision
     * varies on so shared caches key correctly. Alone it just emits a
     * Vary field no response varies on — harmless over-varying, but
     * warn so the misconfig is visible rather than silently degrading
     * hit rate (parent zstd_bypass_vary parity).
     */
    if (conf->bypass_vary.len && conf->bypass == NULL) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "\"compression_bypass_vary\" is set without a "
                           "\"compression_bypass\" predicate; it adds a "
                           "\"Vary: %V\" field no response actually varies "
                           "on", &conf->bypass_vary);
    }

    /* default cap 32 in-flight bufs (core gzip's number), size 0 =
     * backend-recommended */
    if (conf->bufs.num == NGX_CONF_UNSET) {
        if (prev->bufs.num != NGX_CONF_UNSET) {
            conf->bufs = prev->bufs;

        } else {
            conf->bufs.num = 32;
            conf->bufs.size = 0;
        }
    }

    /*
     * PHASE3: tuning slots resolve to the backend's declared defaults
     * here, so election-time values are always concrete and backends
     * never re-implement defaulting. Merge runs after preconfiguration
     * filled the registry.
     */
    for (i = 0; ngx_http_compression_backends[i] != NULL; i++) {
        ngx_conf_merge_value(conf->levels[i], prev->levels[i],
                             ngx_http_compression_backends[i]->level_default);
        ngx_conf_merge_value(conf->window_bits[i], prev->window_bits[i],
                             ngx_http_compression_backends[i]
                                 ->window_bits_default);
    }

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

    /*
     * A level that declares its own compression_dict_file list
     * replaces the inherited one WHOLESALE (the RFC's alias-merge
     * rule; standard array-directive semantics). The pointers target
     * the cycle-global store either way — inheritance shares entries,
     * never bytes.
     */
    if (conf->dicts == NULL) {
        conf->dicts = prev->dicts;
    }

    /* PHASE2: static serving */
    ngx_conf_merge_uint_value(conf->static_enable, prev->static_enable,
                              NGX_HTTP_COMPRESSION_STATIC_OFF);

    if (conf->static_order == NULL) {
        conf->static_order = prev->static_order;
    }

    if (conf->static_order == NULL) {
        if (ngx_http_compression_static_default_order(cf, conf) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    if (conf->order == NULL) {
        /* shipped default: zstd br gzip (RFC: dynamic prefers the
         * cheap coding; gzip last makes deferral risk-free) — each
         * token joins only when its implementation is in the build */
        conf->order = ngx_array_create(cf->pool, 3,
                                    sizeof(ngx_http_compression_token_t));
        if (conf->order == NULL) {
            return NGX_CONF_ERROR;
        }

#if (NGX_HTTP_COMPRESSION_HAVE_ZSTD)
        t = ngx_array_push(conf->order);
        if (t == NULL) {
            return NGX_CONF_ERROR;
        }
        t->backend = ngx_http_compression_backend_zstd;
#endif

#if (NGX_HTTP_COMPRESSION_HAVE_BROTLI)
        t = ngx_array_push(conf->order);
        if (t == NULL) {
            return NGX_CONF_ERROR;
        }
        t->backend = ngx_http_compression_backend_brotli;
#endif

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
    /* dict-configured locations push their own combined Vary line and
     * never depend on "gzip_vary on" — the warning would be wrong
     * advice there (review round 2) */
    if (conf->enable
        && (conf->dicts == NULL || conf->dicts->nelts == 0))
    {
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
                const char  *absent =
                    ngx_http_compression_absent_coding(&value[i]);

                if (absent != NULL) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "coding \"%V\" in "
                                       "\"compression_order\" is not "
                                       "available: this nginx was built "
                                       "without %s support",
                                       &value[i], absent);
                    return NGX_CONF_ERROR;
                }

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
    ssize_t                          plen;
    ngx_uint_t                       i;
#if (NGX_HTTP_GZIP)
    ngx_uint_t                       gzip_listed;
#endif
    ngx_table_elt_t                 *ae;
    ngx_http_compression_ctx_t      *ctx;
    ngx_http_compression_conf_t     *conf;
    ngx_http_compression_token_t    *t;
    ngx_http_compression_dict_t     *dict, *elected_dict;
    ngx_http_compression_tuning_t    tuning;
    ngx_http_compression_backend_t  *elected;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_compression_module);

    /*
     * PHASE3: the parent zstd filter's status set — every 2xx except
     * 204/205 (no body by definition) and 206 (ranges address the
     * ENCODED representation; compressing a slice would corrupt it),
     * plus 403 and 404, whose bodies are often the most-served
     * compressible content on a busy origin.
     */
    if (!conf->enable
        || r != r->main
        || r->headers_out.status < NGX_HTTP_OK
        || r->headers_out.status == NGX_HTTP_NO_CONTENT
        || r->headers_out.status == 205  /* Reset Content: no core macro */
        || r->headers_out.status == NGX_HTTP_PARTIAL_CONTENT
        || (r->headers_out.status > 299
            && r->headers_out.status != NGX_HTTP_FORBIDDEN
            && r->headers_out.status != NGX_HTTP_NOT_FOUND)
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
     * PHASE3 bypass (parent zstd_bypass semantics). The operator-named
     * extra Vary field rides BOTH paths — the bypassed identity
     * response and the compressed one — so a shared cache keys on the
     * request header that drove the predicate (the module cannot infer
     * which header that is; compression_bypass_vary names it). A
     * second Vary line is fine: caches union all Vary fields.
     */
    if (conf->bypass_vary.len) {
        ngx_table_elt_t  *bv;

        bv = ngx_list_push(&r->headers_out.headers);
        if (bv == NULL) {
            return NGX_ERROR;
        }

        bv->hash = 1;
        bv->next = NULL;
        ngx_str_set(&bv->key, "Vary");
        bv->value = conf->bypass_vary;
    }

    /*
     * Any predicate variable resolving non-empty and not "0" serves
     * identity — the operator lever for endpoints that must not be
     * compressed (BREACH-style secret+reflection mixes,
     * already-compressed dynamic payloads) without splitting the
     * location. UNIFIED-MODULE DELTA from the parents: the gzip token
     * is part of THIS stack, so bypass vetoes it too — the parents'
     * standalone bypass falls through to core gzip, which would
     * quietly defeat the operator's intent here.
     */
    if (conf->bypass != NULL
        && ngx_http_test_predicates(r, conf->bypass) != NGX_OK)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "compression: bypassed by compression_bypass");

#if (NGX_HTTP_GZIP)
        r->gzip_tested = 1;
        r->gzip_ok = 0;
#endif

        return ngx_http_next_header_filter(r);
    }

    /*
     * Vary before any accept decision, so identity fallbacks vary too.
     *
     * Locations WITHOUT dictionaries delegate Accept-Encoding via the
     * helper (r->gzip_vary with the gzip module — gated on "gzip_vary
     * on", which merge_conf warns about — or a literal push without).
     *
     * Locations WITH dictionaries push ONE combined line,
     * "Vary: Accept-Encoding, Available-Dictionary", instead of a
     * delegated AE line plus a second literal AD line (review round
     * 2): two Vary lines are legal per RFC 9110, but a fair number of
     * intermediary caches key on the FIRST line only — precisely the
     * hazard this header exists to prevent. Delegation is skipped ON
     * PURPOSE there, so the core emitter cannot add a second line;
     * these locations therefore need no "gzip_vary on" either (the
     * merge-time warning skips them). Known narrow corner, accepted
     * and documented: a gzip DEFERRAL in a dict location lets core
     * gzip set r->gzip_vary itself and emit its own AE line beside
     * the combined one — only when gzip is elected ahead of every
     * better coding, and the combined line is still present for
     * caches that read all lines.
     */
    if (conf->dicts != NULL && conf->dicts->nelts > 0) {
        ngx_table_elt_t  *v;

        v = ngx_list_push(&r->headers_out.headers);
        if (v == NULL) {
            return NGX_ERROR;
        }
        v->hash = 1;
        v->next = NULL;
        ngx_str_set(&v->key, "Vary");
        ngx_str_set(&v->value, "Accept-Encoding, Available-Dictionary");

    } else if (ngx_http_compression_vary(r) != NGX_OK) {
        return NGX_ERROR;
    }

    ae = ngx_http_compression_ae_header(r);

    if (ae == NULL || ae->value.len == 0) {
        return ngx_http_next_header_filter(r);
    }

    /* one store match serves every token the loop considers */
    dict = ngx_http_compression_match_dict(r, conf);

    elected = NULL;
    elected_dict = NULL;
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

        /*
         * PHASE1b: at each base token, the dictionary variant runs
         * first. Electable iff the location matched the client's
         * Available-Dictionary AND the backend is dict-ready
         * (wire_prologue != NULL — the round-2 readiness gate) AND
         * the client names the dict coding EXPLICITLY: a "*" wildcard
         * must never elect dcz/dcb, since only a client that actually
         * holds the dictionary can decode them (allow_wildcard=0).
         * A client that accepts dcz but not zstd still gets dcz —
         * it is the coding they asked for.
         */
        if (dict != NULL
            && t[i].backend->dict_coding.len != 0
            && t[i].backend->wire_prologue != NULL)
        {
            w = ngx_http_compression_coding_weight(
                    &ae->value, &t[i].backend->dict_coding, 0);
            if (w > 0) {
                elected = t[i].backend;
                elected_dict = dict;
                break;
            }
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

    /* operator geometry: an explicit compression_buffers size beats
     * the backend recommendation (the dict-prologue clamp below
     * applies to either source); num caps in-flight bufs */
    if (conf->bufs.size > 0) {
        ctx->out_size = conf->bufs.size;
    }

    ctx->bufs_num = (ngx_uint_t) conf->bufs.num;

    /* PHASE3: resolve this coding's tuning slot (concrete post-merge;
     * the dict variant shares the base coding's values) */
    for (i = 0; ngx_http_compression_backends[i] != NULL; i++) {
        if (ngx_http_compression_backends[i] == elected) {
            break;
        }
    }

    if (ngx_http_compression_backends[i] == NULL) {
        /* unreachable: every order token is a registry pointer */
        return NGX_ERROR;
    }

    tuning.level = conf->levels[i];
    tuning.window_bits = conf->window_bits[i];

    if (elected->create(r, &tuning, &ctx->bctx) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "compression: create %V level %i window_bits %i",
                   &elected->coding, tuning.level, tuning.window_bits);

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

    if (elected_dict != NULL) {
        /*
         * The lifecycle invariant's last leg: attach AFTER the size
         * hint, BEFORE the first process step. The backend receives
         * raw bytes only — the store's ownership claim, load-bearing
         * to the end — and the prologue derives from the entry's
         * hash, prepared here and spent by the body filter ahead of
         * the first encoder byte.
         */
        if (elected->attach_dictionary(ctx->bctx, &elected_dict->bytes)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        plen = elected->wire_prologue(ctx->bctx, elected_dict->sha256,
                                      ctx->prologue,
                                      sizeof(ctx->prologue));
        if (plen == NGX_ERROR) {
            return NGX_ERROR;
        }
        ctx->prologue_len = (size_t) plen;

        /*
         * The output buffer must hold the prologue (review round 2's
         * blocking find): brotli's out_size is CONTENT-DERIVED —
         * BrotliEncoderMaxCompressedSize(1..29) is smaller than the
         * 36-byte dcb prologue — so a tiny known-length body sized a
         * buffer the prologue memcpy overran (heap write, worker
         * survives, response silently corrupt; ASan-reproduced).
         * The guarantee belongs to whoever sizes the buffer: clamp
         * here, where prologue_len is known, not in any backend.
         */
        if (ctx->out_size < ctx->prologue_len) {
            ctx->out_size = ctx->prologue_len;
        }
    }

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
    r->headers_out.content_encoding->value =
        (elected_dict != NULL) ? elected->dict_coding : elected->coding;

    ngx_http_clear_content_length(r);
    ngx_http_clear_accept_ranges(r);
    ngx_http_weak_etag(r);

    return ngx_http_next_header_filter(r);
}


/*
 * PHASE3: produce the working output buf — a reclaimed one when the
 * free list has any, a fresh allocation while under the
 * compression_buffers cap, or NGX_DECLINED with ctx->nomem latched
 * when neither is possible (production pauses until downstream
 * drains the busy chain).
 */
static ngx_int_t
ngx_http_compression_get_buf(ngx_http_request_t *r,
    ngx_http_compression_ctx_t *ctx)
{
    ngx_chain_t  *cl;

    if (ctx->ob != NULL) {
        return NGX_OK;
    }

    if (ctx->free != NULL) {
        /* update_chains reset pos/last to start when it reclaimed */
        cl = ctx->free;
        ctx->free = cl->next;
        ctx->ob = cl->buf;
        ngx_free_chain(r->pool, cl);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "compression: reused output buf %p", ctx->ob);
        return NGX_OK;
    }

    if (ctx->allocated < ctx->bufs_num) {
        ctx->ob = ngx_create_temp_buf(r->pool, ctx->out_size);
        if (ctx->ob == NULL) {
            return NGX_ERROR;
        }
        ctx->ob->tag = (ngx_buf_tag_t) &ngx_http_compression_module;
        ctx->allocated++;
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "compression: buffer cap %ui reached, awaiting drain",
                   ctx->bufs_num);
    ctx->nomem = 1;
    return NGX_DECLINED;
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

    if (ctx->nomem) {
        /*
         * PHASE3 recycling: the previous invocation hit the buffer
         * cap. Push the busy chain downstream first — a NULL pass
         * lets the write filter drain what it holds — then reclaim
         * whatever drained. Production resumes below with the freed
         * bufs (the loop's get_buf may trip the cap again; each
         * invocation makes the progress the client's drain rate
         * allows, which is the whole point of the cap).
         *
         * The debug line is the observable witness that the GENUINE
         * pause path ran — a same-invocation resume never comes
         * through here, only a writer-driven re-entry after a real
         * cross-invocation pause does (tools/test_slow_drain.py
         * asserts it under forced backpressure).
         */
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "compression: resuming after drain");

        if (ngx_http_next_body_filter(r, NULL) == NGX_ERROR) {
            return NGX_ERROR;
        }

        cl = NULL;
        ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &cl,
                                (ngx_buf_tag_t) &ngx_http_compression_module);

        ctx->nomem = 0;
    }

    /*
     * PHASE1b: the dict coding's wire prologue rides ahead of the
     * first encoder byte, in the same output buffer the first step
     * fills. The buffer is guaranteed to hold it by the clamp at
     * election time — NOT by any assumption about backend out_size:
     * zstd's recommendation is fixed and large, but brotli's is
     * content-derived and can be as small as 7 bytes (review round
     * 2). Emitted on the first invocation that carries input — a
     * zero-body response still gets it, since the last_buf special
     * buf arrives through ctx->in like any other link.
     */
    if (ctx->prologue_len > 0 && !ctx->prologue_sent && ctx->in != NULL) {

        /* first invocation with input: the cap cannot be reached yet */
        if (ngx_http_compression_get_buf(r, ctx) != NGX_OK) {
            return NGX_ERROR;
        }

        ngx_memcpy(ctx->ob->last, ctx->prologue, ctx->prologue_len);
        ctx->ob->last += ctx->prologue_len;
        ctx->prologue_sent = 1;
    }

    /*
     * PHASE3 recycling: the outer cycle is the parent filter's shape —
     * produce until the buffer cap pauses us, ship, reclaim what
     * downstream drained, and RESUME IN THIS INVOCATION when the
     * reclaim freed anything. Returning early with unconsumed input
     * would bet on the caller re-invoking us; nginx's contract makes
     * no such promise on a fast socket (found the hard way: the first
     * cut stalled a capped response to the test timeout). The genuine
     * pause — downstream drained nothing — returns NGX_AGAIN and
     * leans on r->buffered keeping the writer re-poking.
     */
    for ( ;; ) {

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

            rc = ngx_http_compression_get_buf(r, ctx);

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (rc == NGX_DECLINED) {
                /* buffer cap: stop producing, ship what we have; the
                 * unconsumed remainder stays on ctx->in (this link's
                 * pos is already advanced past what the encoder ate)
                 * for the invocation that follows the drain */
                goto ship;
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
                ctx->started = 1;
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

                /* the op consumed this link's data and flags; the
                 * break frees the link and the next one recomputes
                 * last_seen/flush_seen from its own buf */
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

ship:

    /*
     * Publish held state (review round 2): after a PROCESS-only
     * invocation the response's bytes live in ctx->ob AND inside the
     * encoder — both libraries buffer internally — while this filter
     * returns without sending anything downstream. Without a buffered
     * bit, ngx_http_writer and finalization can treat the response as
     * idle and stall it until the send timeout. `started` (not just
     * ctx->ob content) drives the bit because encoder-internal state
     * is held data too, and it only fully drains at FINISH. PHASE0:
     * reuses the core gzip bit — defined in every build, and the
     * elected path latches core gzip off so the owners can never
     * overlap; a dedicated bit ships with productization.
     */
    if (ctx->done) {
        r->buffered &= ~NGX_HTTP_GZIP_BUFFERED;

    } else if (ctx->started
               || (ctx->ob != NULL && ctx->ob->last != ctx->ob->pos))
    {
        r->buffered |= NGX_HTTP_GZIP_BUFFERED;
    }

    if (out == NULL) {
        if (in == NULL && !ctx->nomem) {
            /*
             * Writer-driven pass (review round 2): nothing of ours to
             * emit, but the chain below may hold undelivered output —
             * forward the poke, then reclaim whatever it drained.
             */
            rc = ngx_http_next_body_filter(r, NULL);
            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            cl = NULL;
            ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &cl,
                                (ngx_buf_tag_t) &ngx_http_compression_module);
            return rc;
        }

        /* input buffered (or the cap paused production): pending
         * shipped output makes this AGAIN, not OK — the writer keeps
         * driving until the busy chain drains */
        return ctx->busy ? NGX_AGAIN : NGX_OK;
    }

    /*
     * Ship, then fold the shipped chain into busy/free — drained bufs
     * come back through get_buf instead of growing the pool. Links of
     * untagged bufs (the flags-only specials) are released to the
     * pool's free-chain list by the same call.
     */
    rc = ngx_http_next_body_filter(r, out);

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
                            (ngx_buf_tag_t) &ngx_http_compression_module);

    if (ctx->done || !ctx->nomem) {
        /* finished, or the input was fully consumed this pass */
        return rc;
    }

    if (ctx->free == NULL) {
        /* the cap paused us and the ship drained nothing back —
         * a genuinely slow client. r->buffered is set (started
         * input implies it above), so the writer re-pokes and the
         * entry nomem block resumes us when drain happens. */
        return NGX_AGAIN;
    }

    /* the ship freed buffers: resume producing right now */
    ctx->nomem = 0;

    }   /* outer produce/ship/reclaim cycle */
}


static ngx_int_t
ngx_http_compression_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    /* PHASE2: the static sidecar handler joins the content phase,
     * exactly like gzip_static and the parent *_static modules */
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_compression_static_handler;

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_compression_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_compression_body_filter;

    return NGX_OK;
}
