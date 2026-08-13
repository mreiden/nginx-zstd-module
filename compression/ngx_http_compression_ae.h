/*
 * Accept-Encoding parsing per RFC 9110 §12.5.3 / §12.4.2 — lifted from
 * nginx-zstd-module's ngx_http_zstd_common.h, where the walker was
 * already token-parameterized and fuzz-hardened (differential oracle;
 * quoted-string, stray-comma, malformed-qvalue cases). Only the name
 * prefix changed. Strictly length-bounded, never NUL-reliant.
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

        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
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


#endif /* NGX_HTTP_COMPRESSION_AE_H */
