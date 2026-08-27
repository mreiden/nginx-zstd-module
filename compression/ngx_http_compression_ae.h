/*
 * Accept-Encoding VALUE parsing per RFC 9110 §12.5.3 / §12.4.2 —
 * lifted from nginx-zstd-module's ngx_http_zstd_common.h, where the
 * walker was already token-parameterized and fuzz-hardened
 * (differential oracle; quoted-string, stray-comma, malformed-qvalue
 * cases). Only the name prefix changed. Strictly length-bounded,
 * never NUL-reliant.
 *
 * Scope (review round 1): the caller hands this ONE field line — the
 * first Accept-Encoding header — not the RFC 9110 §5.2 combination of
 * every AE line in the request. That is deliberate core-gzip parity:
 * ngx_http_gzip_ok() reads only the first line too, and the defer
 * decision must match what the core filter will conclude, or a
 * multi-line request could be deferred to a gzip that then declines.
 * Walking the ->next chain as a combined field is a productization
 * item, to be taken only together with the defer story.
 *
 * Weight semantics: an explicit token always decides (even q=0, which
 * then overrides a permissive "*"); with no explicit token the "*"
 * wildcard applies only when the caller allows it — base codings do,
 * dictionary codings (dcz/dcb) must not, since only a client that
 * actually holds the dictionary can decode them.
 */

#ifndef NGX_HTTP_COMPRESSION_AE_H
#define NGX_HTTP_COMPRESSION_AE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static u_char *
ngx_http_compression_skip_quoted(u_char *p, u_char *end)
{
    if (p >= end || *p != '"') {
        return p;
    }

    p++;    /* opening DQUOTE */

    while (p < end && *p != '"') {
        if (*p == '\\' && p + 1 < end) {
            p++;    /* skip the escaped octet of a quoted-pair */
        }
        p++;
    }

    if (p < end) {
        p++;    /* closing DQUOTE */
    }

    return p;
}


static ngx_int_t
ngx_http_compression_eval_qvalue(ngx_str_t *ae, u_char *p)
{
    u_char     *end = ae->data + ae->len;
    ngx_int_t   q = 1000;   /* no q parameter → q=1 */
    ngx_int_t   q_seen = 0;

    while (p < end && *p == ';') {

        u_char     *nstart, *nend;
        ngx_int_t   is_q;

        p++;    /* skip ';' */

        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
        }

        nstart = p;
        while (p < end
               && *p != '=' && *p != ';' && *p != ','
               && *p != ' ' && *p != '\t')
        {
            p++;
        }
        nend = p;

        /*
         * RFC 9110 has no empty-parameter production, so "zstd;;q=1"
         * is malformed rather than "a skipped parameter followed by
         * q=1". Reject it instead of silently resolving the element
         * to q=1. (Parent #142; core gzip refuses the gzip twin, so
         * accepting it here would split the defer decision.)
         */
        if (nend == nstart) {
            return -1;
        }

        is_q = (nend - nstart == 1
                && (nstart[0] == 'q' || nstart[0] == 'Q'));

        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
        }

        if (p < end && *p == '=') {
            p++;

            while (p < end && (*p == ' ' || *p == '\t')) {
                p++;
            }

            if (is_q) {
                if (q_seen) {
                    return -1;          /* repeated "q" parameter */
                }
                q_seen = 1;

                if (p >= end) {
                    return -1;          /* "q=" with no value */
                }

                if (*p == '0') {
                    ngx_int_t  scale = 100;

                    p++;
                    q = 0;

                    if (p < end && *p == '.') {
                        p++;
                        while (p < end && *p >= '0' && *p <= '9'
                               && scale > 0)
                        {
                            q += (*p - '0') * scale;
                            scale /= 10;
                            p++;
                        }
                    }

                } else if (*p == '1') {
                    int  i = 0;

                    p++;
                    q = 1000;

                    if (p < end && *p == '.') {
                        p++;
                        while (p < end && *p == '0' && i < 3) {
                            p++;
                            i++;
                        }
                    }

                } else {
                    return -1;          /* leading digit not 0 or 1 */
                }

                if (p < end
                    && *p != ' ' && *p != '\t' && *p != ';' && *p != ',')
                {
                    return -1;          /* trailing junk (q=1x, q=0.0001) */
                }

            } else {
                while (p < end && *p != ';' && *p != ',') {
                    if (*p == '"') {
                        p = ngx_http_compression_skip_quoted(p, end);
                    } else {
                        p++;
                    }
                }
            }

        } else {
            if (is_q) {
                return -1;              /* "q" with no "=value" */
            }
        }

        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
        }

        if (p < end && *p != ';' && *p != ',') {
            return -1;
        }
    }

    return q;
}


/*
 * Effective weight for `coding` in milli-units (0..1000), or -1 when
 * the header expresses no preference for it at all.
 */
static ngx_int_t
ngx_http_compression_coding_weight(ngx_str_t *ae, ngx_str_t *coding,
    ngx_uint_t allow_wildcard)
{
    u_char     *p   = ae->data;
    u_char     *end = ae->data + ae->len;
    ngx_int_t   coding_q = -1;
    ngx_int_t   star_q = -1;

    while (p < end) {

        u_char     *tok, *name_end;
        ngx_int_t   is_coding, is_star, q;

        while (p < end && (*p == ' ' || *p == '\t' || *p == ',')) {
            p++;
        }
        if (p >= end) {
            break;
        }

        tok = p;
        while (p < end
               && *p != ' ' && *p != '\t' && *p != ';' && *p != ','
               && *p != '"')
        {
            p++;
        }
        name_end = p;

        is_coding = ((size_t) (name_end - tok) == coding->len
                     && ngx_strncasecmp(tok, coding->data,
                                        coding->len) == 0);
        is_star = (name_end - tok == 1 && tok[0] == '*');

        /* Step over any OWS between the name and its ';' or ','. */
        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
        }

        /*
         * Only ';' (parameters), ',' (next element) or end of field
         * may follow a coding name. RFC 9110 12.5.3 makes `codings` a
         * token, so anything else means this element is not the
         * coding it looked like: `zstd"x` and `zstd "x` advertise
         * nothing, and neither does `zstd x`. (Parent #142.) Core
         * gzip's ngx_http_gzip_accept_encoding() applies the same
         * rule, so accepting these here splits the defer decision:
         * "gzip x, zstd" would defer to core gzip on the malformed
         * gzip element, core gzip declines it, and a client that
         * validly offered zstd gets identity.
         *
         * The check must sit AFTER the OWS skip: the name scan stops
         * on OWS as well as on '"', so testing the stopping byte
         * alone catches `zstd"x` and misses everything hiding behind
         * a space. The quote-aware element-skip below still swallows
         * the rest of the element.
         */
        if (p < end && *p != ';' && *p != ',') {
            is_coding = 0;
            is_star = 0;
        }

        q = 1000;
        if (p < end && *p == ';') {
            q = ngx_http_compression_eval_qvalue(ae, p);
        }

        if (q >= 0) {
            if (is_coding) {
                coding_q = q;
            } else if (is_star) {
                star_q = q;
            }
        }

        while (p < end && *p != ',') {
            if (*p == '"') {
                p = ngx_http_compression_skip_quoted(p, end);
            } else {
                p++;
            }
        }
    }

    if (coding_q >= 0) {
        return coding_q;
    }
    if (allow_wildcard && star_q >= 0) {
        return star_q;
    }
    return -1;
}


/*
 * Vary: Accept-Encoding, emitted BY CONSTRUCTION on any response whose
 * representation was negotiated on Accept-Encoding — parent #163's
 * hardening, ported. The hazard it closes: r->gzip_vary alone is only
 * a REQUEST for the header. ngx_http_header_filter_module honours it
 * solely under "gzip_vary on" and CLEARS the flag otherwise, so the
 * default "gzip_vary off" used to ship a negotiated compressed body
 * with no Vary at all — and a shared cache would then hand the
 * zstd/brotli representation to a client that sent no matching
 * Accept-Encoding, i.e. an undecodable body. That correctness property
 * belonged to a directive this module does not own; now it does not.
 *
 * With the gzip module we still set r->gzip_vary (other modules read
 * the flag — e.g. a Vary-flattening filter that keys on it alone), then
 * defer to nginx when the directive is on and emit our own line when it
 * is off. The two emitters are mutually exclusive, so exactly one line
 * results in every build/directive combination. The dedup scan guards
 * the case where a preceding filter already pushed the field.
 *
 * Header-static like the parser above — since the filter/static MODULE
 * SPLIT each module carries its own copy, so neither .so links symbols
 * from the other (the static module links nothing at all).
 */
static ngx_inline ngx_int_t
ngx_http_compression_vary(ngx_http_request_t *r)
{
    ngx_uint_t        i;
    ngx_table_elt_t  *v, *h;
    ngx_list_part_t  *part;
#if (NGX_HTTP_GZIP)
    ngx_http_core_loc_conf_t  *clcf;

    r->gzip_vary = 1;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (clcf != NULL && clcf->gzip_vary) {
        /* nginx's header filter emits the line from r->gzip_vary */
        return NGX_OK;
    }
#endif

    for (part = &r->headers_out.headers.part, h = part->elts, i = 0;
         /* void */;
         i++)
    {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].hash == 0) {
            continue;
        }

        if (h[i].key.len == sizeof("Vary") - 1
            && ngx_strncasecmp(h[i].key.data, (u_char *) "Vary",
                               sizeof("Vary") - 1) == 0
            && h[i].value.len == sizeof("Accept-Encoding") - 1
            && ngx_strncasecmp(h[i].value.data,
                               (u_char *) "Accept-Encoding",
                               sizeof("Accept-Encoding") - 1) == 0)
        {
            return NGX_OK;
        }
    }

    v = ngx_list_push(&r->headers_out.headers);
    if (v == NULL) {
        return NGX_ERROR;
    }
    v->hash = 1;
    v->next = NULL;
    ngx_str_set(&v->key, "Vary");
    ngx_str_set(&v->value, "Accept-Encoding");
    return NGX_OK;
}


/* the request's Accept-Encoding header: parsed field with the gzip
 * module, list walk without (first header only — deliberate core-gzip
 * parity, the defer decision must match core gzip's conclusion) */
static ngx_inline ngx_table_elt_t *
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


#endif /* NGX_HTTP_COMPRESSION_AE_H */
