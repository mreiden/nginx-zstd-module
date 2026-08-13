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

[myguard-labs/nginx-zstd-module#109]: https://github.com/myguard-labs/nginx-zstd-module/issues/109
