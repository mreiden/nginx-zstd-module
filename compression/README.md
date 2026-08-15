# nginx-compression — phase-0 prototype

Throwaway backend-interface prototype for the unified compression
module (RFC: [myguard-labs/nginx-zstd-module#109]). One filter module,
N backends behind one vtable (`ngx_http_compression.h`), election by
`compression_order`, gzip by defer/veto — never implemented.

Lives under `compression/` on the RFC's living review branch;
deliberately NOT wired into this repo's CI or its root `config` — the
zstd modules build exactly as before. Later phases land on the same
branch (phase 1 begins with the ngx_brotli history graft + the shared
dictionary store).

**The deliverable is the interface and [WRINKLES.md](WRINKLES.md)**,
not this code. Directives implemented: `compression on|off`,
`compression_order <codings...>` (tokens: `zstd`, `br`, `gzip`;
unknown or duplicate = config error; the list is the enable set),
`compression_min_length`, `compression_types`.

Build (needs system libzstd + libbrotli, nginx >= 1.23.0):

```bash
./configure --add-module=/path/to/nginx-zstd-module/compression
```

Works with and without the core gzip module: gzip-less builds do their
own Accept-Encoding lookup, push their own `Vary: Accept-Encoding`,
and reject the `gzip` order token at config load. With gzip present,
Vary is delegated via `r->gzip_vary` — which the core emits only under
`gzip_vary on`, so the module warns at config load when that is off.

**Phase 1a** adds the shared dictionary store (see
`ngx_http_compression_dict.h` for the full rules):
`compression_dict_file <path> [sha256hex]` at http/server/location
(lists replace wholesale on inheritance; the bytes live once in a
cycle-global store regardless of how many levels reference them), the
RFC's provenance rules enforced at config load, and
`$compression_dicts_hashed` as the observable witness for the dedup
and the supplied-hash fast path. Dictionary codings remain unelectable
until phase 1b wires negotiation and the prologue emitters. The branch
also now carries the full ngx_brotli hardened-fork history under
`brotli/` (subtree merge; the fork point is the merge's second
parent).

[myguard-labs/nginx-zstd-module#109]: https://github.com/myguard-labs/nginx-zstd-module/issues/109
