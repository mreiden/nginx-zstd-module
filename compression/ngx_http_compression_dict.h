/*
 * nginx-compression — the shared dictionary store (phase 1, RFC #109).
 *
 * THE DATA MODEL THE RFC CALLS LOAD-BEARING, made concrete: the only
 * persistent state per dictionary is {path, raw bytes, sha256}. Every
 * algorithm-specific structure — zstd's refPrefix window, brotli's
 * quality-baked prepared dictionary — is per-request scratch built
 * from these bytes through the backend's attach_dictionary() hook, so
 * ONE store entry feeds every coding: one copy per file instead of one
 * per module, and at most one hash pass per file per cycle.
 *
 * Store rules (review round 1 of the RFC, verbatim where possible):
 *
 *  - The STORE is cycle-global and deduplicates BY PATH: the same file
 *    named at http{} and again in a location loads once. Everything
 *    lives in the cycle's config pool — a rejected reload takes its
 *    store down with it (the #103 lesson), and worker processes share
 *    the bytes via fork COW.
 *  - Each configuration level carries a LIST of pointers into the
 *    store. A level that declares its own compression_dict_file list
 *    replaces the inherited one wholesale (standard array-directive
 *    semantics; the RFC's alias-merge rule).
 *  - An optional second argument supplies the SHA-256 (64 hex chars),
 *    trusted VERBATIM — the deploy-system fast path that takes
 *    config-load hashing to zero. Validated before the file is even
 *    opened (the parent repo's ordering pin).
 *  - "A supplied hash never satisfies a directive that didn't supply
 *    one": when an unsupplied directive references a path whose store
 *    entry knows only a supplied hash, the hash IS computed for that
 *    directive — and since the computation was already paid for, it
 *    doubles as a free cross-check: a mismatch is a config error
 *    (catching exactly the stale-supplied-hash hazard the parent
 *    documents), a match marks the entry verified.
 *  - Two DIFFERENT paths with the same hash are a config error:
 *    RFC 9842 negotiation keys on the hash, so duplicates would be
 *    ambiguous (parent behavior, kept).
 *
 * PHASE 1a SCOPE: the store loads, validates, dedups, and exposes the
 * per-location lists; nothing reads them yet. Dictionary codings stay
 * unelectable until phase 1b wires Available-Dictionary negotiation
 * and the wire-prologue emitters (the election gates on
 * wire_prologue != NULL). Because nothing non-negotiated can ever be
 * served from this store, there is no equivalent of the parent's
 * zstd_dict_file_unsafe acknowledgement — that gate guards a
 * non-RFC-9842 mode this module simply does not have.
 */

#ifndef NGX_HTTP_COMPRESSION_DICT_H
#define NGX_HTTP_COMPRESSION_DICT_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_COMPRESSION_SHA256_LEN      32
#define NGX_HTTP_COMPRESSION_SHA256_HEX_LEN  64


typedef struct {
    ngx_str_t    path;         /* resolved against the prefix */
    ngx_str_t    bytes;        /* raw contents, cycle config pool */
    u_char       sha256[NGX_HTTP_COMPRESSION_SHA256_LEN];
    ngx_str_t    sha256_hex;   /* lowercase; negotiation + compare key */
    unsigned     supplied:1;   /* hash arrived via config, verbatim */
    unsigned     verified:1;   /* a computed pass confirmed the hash */
    unsigned     optional:1;   /* any line for this path said
                                * "optional": load failures demote to
                                * warnings (sticky across lines) */
} ngx_http_compression_dict_t;


typedef struct {
    /*
     * of ngx_http_compression_dict_t * — the entry OBJECTS are
     * allocated individually and the array holds only pointers,
     * because per-location lists alias the entries and
     * ngx_array_push() RELOCATES element storage on growth: a
     * value-array here handed out pointers that went stale the
     * moment a fifth dictionary loaded (caught by the six-dict
     * duplicate test, which forces the growth).
     */
    ngx_array_t   store;

    /*
     * SHA-256 computations over dictionary files in THIS configuration
     * ($compression_dicts_hashed). Cycle-owned on purpose — the same
     * reasoning as the parent's dcz counter (#103): a rejected reload
     * takes its count down with its pool. The observable witness for
     * both store-level dedup (N references, one compute) and the
     * supplied-hash fast path (zero computes).
     */
    ngx_uint_t    dicts_hashed;

    /*
     * compression_dict_strict_path (parent #165): opt-in, off by
     * default. When on, dictionary files open with O_NOFOLLOW and a
     * target writable by group or other is rejected — a symlink or a
     * loosely-permissioned dictionary must not let a lower-privileged
     * local writer swap bytes into every worker on the next reload.
     * MAIN_CONF only: the store is cycle-global, so the policy is a
     * property of the whole load, declared once in http{}. Independent
     * of it, a non-regular target (FIFO/socket/dir/device) is rejected
     * unconditionally, and every open is O_NONBLOCK so a FIFO cannot
     * hang the config-parsing master.
     */
    ngx_flag_t    dict_strict_path;

    /*
     * "Could this cycle ever compress a response" latch (parent #182),
     * set at directive PARSE time by ngx_http_compression_set_enable_slot()
     * whenever a "compression on;" is parsed ANYWHERE — main, srv, loc, or
     * an NGX_HTTP_LIF_CONF conf synthesized for a rewrite-phase "if" block.
     * Parse time, not a merged-location walk: an "if" block's conf is not
     * reliably reachable from the ordinary merge tree, and a false negative
     * would silently drop compression for a live location. When it stays
     * clear, postconfiguration skips installing the header/body filter
     * hooks entirely — no per-response NULL-ctx pass on a build that
     * carries the module but never enables it.
     */
    ngx_flag_t    any_enabled;
} ngx_http_compression_main_conf_t;


/* compression_dict_file <path> [sha256hex] — the directive handler */
char *ngx_http_compression_dict_file(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/* registers $compression_dicts_hashed; call from preconfiguration */
ngx_int_t ngx_http_compression_dict_add_variables(ngx_conf_t *cf);


#endif /* NGX_HTTP_COMPRESSION_DICT_H */
