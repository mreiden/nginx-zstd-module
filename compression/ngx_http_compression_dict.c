/*
 * Shared dictionary store implementation — see ngx_http_compression_dict.h
 * for the rules; comments here mark WHERE each rule bites, not what it is.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_compression_dict.h"

/*
 * Unification dividend, not a shortcut: the whole repo gets exactly one
 * SHA-256 implementation — the parent module's header-only one-shot,
 * EVP-accelerated when NGX_HTTP_ZSTD_HAVE_LIBCRYPTO is set. The macro
 * keeps the parent's name because this header keys on it;
 * compression/auto/detect defines it (probe, or nginx's own OpenSSL
 * for static addons), and NGX_HTTP_COMPRESSION_NO_LIBCRYPTO=1 keeps
 * the portable path. EVP matters MORE here than in the parent: the
 * store computes every dictionary's hash at config load — supplied
 * hashes included, the mandated compute doubling as the free audit —
 * so there is no verbatim fast path to hide slow hashing behind.
 */
#include "../ngx_http_zstd_sha256.h"


extern ngx_module_t  ngx_http_compression_filter_module;


static ngx_int_t ngx_http_compression_hex_decode(ngx_str_t *hex,
    u_char out[NGX_HTTP_COMPRESSION_SHA256_LEN]);
static ngx_int_t ngx_http_compression_dicts_hashed_variable(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);


static ngx_int_t
ngx_http_compression_hex_decode(ngx_str_t *hex,
    u_char out[NGX_HTTP_COMPRESSION_SHA256_LEN])
{
    u_char      c;
    ngx_uint_t  i, hi;

    if (hex->len != NGX_HTTP_COMPRESSION_SHA256_HEX_LEN) {
        return NGX_ERROR;
    }

    for (i = 0; i < NGX_HTTP_COMPRESSION_SHA256_HEX_LEN; i++) {
        c = ngx_tolower(hex->data[i]);

        if (c >= '0' && c <= '9') {
            hi = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            hi = c - 'a' + 10;
        } else {
            return NGX_ERROR;
        }

        if (i % 2 == 0) {
            out[i / 2] = (u_char) (hi << 4);
        } else {
            out[i / 2] |= (u_char) hi;
        }
    }

    return NGX_OK;
}


static void
ngx_http_compression_hex_encode(const u_char *bin, size_t len, u_char *out)
{
    static const u_char  hex[] = "0123456789abcdef";
    size_t               i;

    for (i = 0; i < len; i++) {
        *out++ = hex[bin[i] >> 4];
        *out++ = hex[bin[i] & 0x0f];
    }
}


char *
ngx_http_compression_dict_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                          *value, path, hex;
    ngx_fd_t                            fd;
    ssize_t                             n;
    ngx_uint_t                          i, supplied, optional;
    ngx_file_info_t                     info;
    ngx_http_compression_dict_t       **d, *entry, **dp, **list;
    ngx_http_compression_main_conf_t   *cmcf;
    ngx_array_t                       **dicts;
    u_char                              want[NGX_HTTP_COMPRESSION_SHA256_LEN];

    /* the loc conf's dicts array field, located via cmd->offset */
    dicts = (ngx_array_t **) ((char *) conf + cmd->offset);

    cmcf = ngx_http_conf_get_module_main_conf(cf,
                                              ngx_http_compression_filter_module);

    value = cf->args->elts;
    path = value[1];

    /*
     * Optional arguments in either order: a 64-hex sha256 and/or the
     * "optional" keyword — the operator-insistence demotion (Mark's
     * outage scenario, an INTENTIONAL DEVIATION from the RFC's
     * fail-fatal rule): a dictionary that cannot be loaded as
     * declared warns and degrades instead of refusing to start the
     * server. Deploy tooling emits it on generated lines; hand-written
     * critical entries stay strict by omitting it. Anything that is
     * neither the keyword nor a plausible hash falls through to the
     * hash validator below, which names the real problem.
     */
    supplied = 0;
    optional = 0;

    for (i = 2; i < cf->args->nelts; i++) {
        if (value[i].len == sizeof("optional") - 1
            && ngx_strncmp(value[i].data, "optional",
                           sizeof("optional") - 1) == 0)
        {
            optional = 1;

        } else if (supplied) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate dictionary hash argument \"%V\"",
                               &value[i]);
            return NGX_CONF_ERROR;

        } else {
            supplied = 1;
            hex = value[i];
        }
    }

    /*
     * Validate the supplied hash BEFORE touching the filesystem (the
     * parent repo's ordering pin): a malformed hash next to a
     * nonexistent path must report the hash, not the open failure —
     * the operator fixes their config once, not twice. Malformed hex
     * stays FATAL even with "optional": a typo is a config bug to fix
     * once, not a deploy race to ride out.
     */
    if (supplied) {
        if (ngx_http_compression_hex_decode(&hex, want) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid dictionary hash \"%V\": want %d "
                               "lowercase hex characters (the file's "
                               "SHA-256)", &hex,
                               NGX_HTTP_COMPRESSION_SHA256_HEX_LEN);
            return NGX_CONF_ERROR;
        }
    }

    /*
     * Relative paths resolve against the SERVER prefix (third arg 0),
     * not the conf prefix: dictionaries are data assets like roots
     * and user files, not configuration includes. (The first cut
     * passed 1; invisible while the test harness kept conf and prefix
     * in one directory, caught the moment Test::Nginx split them.)
     */
    if (ngx_conf_full_name(cf->cycle, &path, 0) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    /* ── store lookup by path: the dedup that makes it ONE copy ──────
     * (store holds POINTERS; entry objects are individually allocated
     * so aliases in per-location lists survive array growth) */

    entry = NULL;
    d = cmcf->store.elts;

    for (i = 0; i < cmcf->store.nelts; i++) {
        if (d[i]->path.len == path.len
            && ngx_strncmp(d[i]->path.data, path.data, path.len) == 0)
        {
            entry = d[i];
            break;
        }
    }

    if (entry != NULL) {

        if (supplied) {
            /*
             * Two provenances now describe one file. Verbatim trust
             * never extends to CONFLICT: whatever the existing entry
             * believes (supplied or computed), a differing hash for
             * the same path is a config error, not a shrug.
             */
            if (ngx_memcmp(entry->sha256, want,
                           NGX_HTTP_COMPRESSION_SHA256_LEN)
                != 0)
            {
                if (!optional && !entry->optional) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "conflicting sha256 for dictionary "
                                       "\"%V\": \"%V\" does not match the "
                                       "hash already recorded for this "
                                       "file", &path, &hex);
                    return NGX_CONF_ERROR;
                }

                /* optional: the file's computed truth outranks BOTH
                 * declared values — serving keys stay correct */
                ngx_http_zstd_sha256(entry->bytes.data, entry->bytes.len,
                                     entry->sha256);
                cmcf->dicts_hashed++;
                entry->verified = 1;
                ngx_http_compression_hex_encode(entry->sha256,
                                     NGX_HTTP_COMPRESSION_SHA256_LEN,
                                     entry->sha256_hex.data);
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "conflicting sha256 values for optional "
                                   "dictionary \"%V\"; the file's computed "
                                   "hash wins", &path);
            }

            if (!entry->supplied) {
                entry->verified = 1;    /* computed earlier, now agreed */
            }

        } else if (entry->supplied && !entry->verified) {
            /*
             * THE RULE: a supplied hash never satisfies a directive
             * that didn't supply one. This directive mandates a
             * computation — and since that pass is paid for anyway,
             * it doubles as a free audit of the earlier verbatim
             * hash: a mismatch here is precisely the stale-supplied-
             * hash hazard (deploy script hashed an older file) that
             * verbatim trust cannot catch on its own.
             */
            ngx_http_zstd_sha256(entry->bytes.data, entry->bytes.len, want);
            cmcf->dicts_hashed++;

            if (ngx_memcmp(entry->sha256, want,
                           NGX_HTTP_COMPRESSION_SHA256_LEN)
                != 0)
            {
                if (!optional && !entry->optional) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "dictionary \"%V\": the supplied "
                                       "sha256 does not match the file's "
                                       "actual hash (stale hash from an "
                                       "earlier deploy?)", &path);
                    return NGX_CONF_ERROR;
                }

                /* optional: `want` holds the computed truth — re-key
                 * the entry so clients holding the REAL file still
                 * negotiate */
                ngx_memcpy(entry->sha256, want,
                           NGX_HTTP_COMPRESSION_SHA256_LEN);
                ngx_http_compression_hex_encode(entry->sha256,
                                     NGX_HTTP_COMPRESSION_SHA256_LEN,
                                     entry->sha256_hex.data);
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "optional dictionary \"%V\": stale "
                                   "supplied sha256; the file's computed "
                                   "hash wins", &path);
            }

            entry->verified = 1;
        }

        /* matching hashes (or computed-and-shared): one store entry */

    } else {

        /* ── first sight of this path: load it ─────────────────────── */

        fd = ngx_open_file(path.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
        if (fd == NGX_INVALID_FILE) {
            if (optional) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, ngx_errno,
                                   "skipping optional dictionary \"%V\": "
                                   "open() failed; clients holding it "
                                   "degrade to the base coding", &path);
                return NGX_CONF_OK;
            }
            ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                               "open() dictionary \"%V\" failed", &path);
            return NGX_CONF_ERROR;
        }

        if (ngx_fd_info(fd, &info) == NGX_FILE_ERROR || ngx_file_size(&info) == 0) {
            ngx_close_file(fd);
            if (optional) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "skipping optional dictionary \"%V\": "
                                   "empty or unreadable", &path);
                return NGX_CONF_OK;
            }
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "dictionary \"%V\" is empty or unreadable",
                               &path);
            return NGX_CONF_ERROR;
        }

        entry = ngx_pcalloc(cf->pool, sizeof(ngx_http_compression_dict_t));
        if (entry == NULL) {
            ngx_close_file(fd);
            return NGX_CONF_ERROR;
        }

        entry->path = path;

        entry->bytes.len = (size_t) ngx_file_size(&info);
        entry->bytes.data = ngx_palloc(cf->pool, entry->bytes.len);
        if (entry->bytes.data == NULL) {
            ngx_close_file(fd);
            return NGX_CONF_ERROR;
        }

        n = ngx_read_fd(fd, entry->bytes.data, entry->bytes.len);
        ngx_close_file(fd);

        if (n != (ssize_t) entry->bytes.len) {
            if (optional) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "skipping optional dictionary \"%V\": "
                                   "read() returned %z of %uz bytes",
                                   &path, n, entry->bytes.len);
                return NGX_CONF_OK;
            }
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "read() dictionary \"%V\": %z of %uz bytes",
                               &path, n, entry->bytes.len);
            return NGX_CONF_ERROR;
        }

        /*
         * Parent parity (its zstd-03:13): a dictionary larger than
         * the 8 MB window browsers enforce cannot be fully referenced
         * — with the unpledged-window cap, dcz matches beyond the
         * window's reach are silently lost. Loading proceeds (the
         * near end still helps, and dcb's window rules differ), but
         * the operator should know their dictionary is bigger than
         * its useful range.
         */
        if (entry->bytes.len > 8 * 1024 * 1024) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "dictionary \"%V\" is %uz bytes — larger "
                               "than the 8 MB window browsers enforce for "
                               "Content-Encoding: zstd; content beyond the "
                               "window cannot reference it", &path,
                               entry->bytes.len);
        }

        if (supplied) {
            ngx_memcpy(entry->sha256, want,
                       NGX_HTTP_COMPRESSION_SHA256_LEN);
            entry->supplied = 1;
            /* verbatim by design: zero hashing is the whole point of
             * the deploy-system fast path */

        } else {
            ngx_http_zstd_sha256(entry->bytes.data, entry->bytes.len,
                                 entry->sha256);
            cmcf->dicts_hashed++;
            entry->verified = 1;
        }

        entry->sha256_hex.len = NGX_HTTP_COMPRESSION_SHA256_HEX_LEN;
        entry->sha256_hex.data =
            ngx_pnalloc(cf->pool, NGX_HTTP_COMPRESSION_SHA256_HEX_LEN);
        if (entry->sha256_hex.data == NULL) {
            return NGX_CONF_ERROR;
        }
        ngx_http_compression_hex_encode(entry->sha256,
                                        NGX_HTTP_COMPRESSION_SHA256_LEN,
                                        entry->sha256_hex.data);

        /*
         * Ambiguity gate: RFC 9842 negotiation keys on the hash alone,
         * so two DIFFERENT files sharing one hash could serve either
         * dictionary for a client's Available-Dictionary. Parent
         * behavior kept: config error, named after the colliding path.
         * Runs BEFORE the entry joins the store, so the scan never has
         * to exclude the newcomer.
         */
        d = cmcf->store.elts;
        for (i = 0; i < cmcf->store.nelts; i++) {
            if (ngx_memcmp(d[i]->sha256, entry->sha256,
                           NGX_HTTP_COMPRESSION_SHA256_LEN)
                == 0)
            {
                if (!optional && !d[i]->optional) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "dictionary \"%V\" has the same "
                                       "hash as \"%V\"", &path,
                                       &d[i]->path);
                    return NGX_CONF_ERROR;
                }

                /* optional: same hash = same bytes = interchangeable —
                 * alias to the entry already in the store */
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "optional dictionary \"%V\" has the "
                                   "same hash as \"%V\"; using the "
                                   "existing entry", &path, &d[i]->path);
                entry = d[i];
                break;
            }
        }

        if (i == cmcf->store.nelts) {
            dp = ngx_array_push(&cmcf->store);
            if (dp == NULL) {
                return NGX_CONF_ERROR;
            }
            *dp = entry;
        }
    }

    if (optional) {
        entry->optional = 1;    /* sticky across lines for this path */
    }

    /* ── append to this level's list (pointer into the store) ──────── */

    if (*dicts == NULL) {
        *dicts = ngx_array_create(cf->pool, 4,
                                  sizeof(ngx_http_compression_dict_t *));
        if (*dicts == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    list = (*dicts)->elts;
    for (i = 0; i < (*dicts)->nelts; i++) {
        if (list[i] == entry) {
            if (optional || entry->optional) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "optional dictionary \"%V\" already in "
                                   "this list; skipping the duplicate",
                                   &path);
                return NGX_CONF_OK;
            }
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate dictionary \"%V\" in this "
                               "\"compression_dict_file\" list", &path);
            return NGX_CONF_ERROR;
        }
    }

    dp = ngx_array_push(*dicts);
    if (dp == NULL) {
        return NGX_CONF_ERROR;
    }
    *dp = entry;

    return NGX_CONF_OK;
}


/* ── $compression_dicts_hashed ─────────────────────────────────────── */

static ngx_int_t
ngx_http_compression_dicts_hashed_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                            *p;
    ngx_http_compression_main_conf_t  *cmcf;

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_compression_filter_module);

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%ui", cmcf->dicts_hashed) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


ngx_int_t
ngx_http_compression_dict_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var;
    static ngx_str_t      name =
        ngx_string("compression_dicts_hashed");

    var = ngx_http_add_variable(cf, &name, 0);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_compression_dicts_hashed_variable;

    return NGX_OK;
}
