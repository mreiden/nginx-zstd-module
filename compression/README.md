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
and the supplied-hash fast path. The branch also carries the full
ngx_brotli hardened-fork history under `brotli/` (subtree merge; the
fork point is the merge's second parent).

**Phase 2** adds unified static sidecar serving: `compression_static
off|on|always` and `compression_static_order` (tokens `zstd`/`br`/
`gzip`; the list is the enable set AND the probe order; default
`br zstd gzip` — static prefers br because its CPU was spent at build
time). One content-phase handler probes `file.zst`/`.br`/`.gz` in
order and serves the first acceptable hit; no compression library is
called, which makes gzip fully first-class here — a gzip-less build
serves `.gz` sidecars byte-exact. The parent zstd_static's
magic + declared-window probe rides along intact (an oversized-window
`.zst` declines to the NEXT coding in the order, not just identity),
`always` serves the first existing sidecar with no Vary, and a static
miss falls through to the dynamic filter with no latches touched.

**Phase 1b** makes the dictionary codings real: RFC 9842
Available-Dictionary negotiation against the store (RFC 8941 byte
sequence, strict shape), per-backend wire-prologue emitters (dcz's
40-byte skippable frame with a checksummed stream; dcb's 36 raw
bytes), election of `dcz`/`dcb` at their base coding's position on an
explicit Accept-Encoding token only (`*` never elects them), graceful
degrade to the base coding on any negotiation miss, and a hoisted
`Vary: Available-Dictionary` on every eligible response wherever
dictionaries are configured — identity fallbacks included.

**Phase 3** (productization) begins with the per-coding tuning
directives, keyed by coding so a new backend needs no new commands:
`compression_level <coding> <n>` (zstd `-131072..22`, `0` = library
default, default `3`; br quality `0..11`, default `6`) and
`compression_window <coding> <size>` (a power-of-two size stored as
its log2: zstd `1k..128m` acting as a per-request memory ceiling,
unset by default; br `1k..16m`, default `512k`). Bounds and defaults
are declared by the backend in the vtable and validated at config
load. The `gzip` token is rejected with a pointer at
`gzip_comp_level` (defer means the core module's own tuning applies),
and `dcz`/`dcb` are rejected with a pointer at their base coding — a
dictionary variant shares the base coding's parameters (brotli bakes
quality into the prepared dictionary; there is nothing separate to
tune).

[myguard-labs/nginx-zstd-module#109]: https://github.com/myguard-labs/nginx-zstd-module/issues/109
