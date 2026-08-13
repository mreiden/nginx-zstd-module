# Phase-0 findings — wrinkles in the RFC plan

What building the backend interface against both real encoders surfaced,
in descending order of consequence for the design doc (RFC:
myguard-labs/nginx-zstd-module#109). Prototype validated live: the full
election matrix (default order, explicit orders, gzip-first, q=0
exclusion, wildcard, veto, no-AE identity, `compression off` migration
floor) behaves as the RFC specifies, and both codings decode byte-exact.

## 1. The "gzip listed but gzip off" warning — INTENTIONALLY ABANDONED

**Decision: dropped from the RFC as unimplementable, 2026-08-12.** The
warning wanted to fire when `gzip` appears in `compression_order` but
the core `gzip` directive is off — and that condition cannot be
observed. The core gzip filter's configuration is invisible to other
modules: its `ngx_module_t` symbol links, but the conf struct is
private to `ngx_http_gzip_filter_module.c`, and inter-module merge
order makes even a layout-mirroring read unsound. Same visibility wall
that keeps any module from verifying another's directives
(nginx-zstd-module#110's compression_vary finding, now met from the
other side).

No harm follows from the abandonment: with gzip listed but off,
deferral hands the response to the core filter, the core filter
declines by its own switch, and the client gets identity — precisely
what the operator's `gzip off` requested. The misconfiguration
self-corrects into intent. The gzip-ahead-of-better-codings warning
survives untouched (pure order inspection, no foreign conf needed).

## 2. `done` needed a per-op definition, not a global one

The two libraries report completion through different channels: zstd's
`compressStream2` returns bytes-remaining (0 = flushed/ended), brotli
answers through `BrotliEncoderIsFinished` / `HasMoreOutput` — and
brotli can sit on ready output after a PROCESS step, which zstd never
surfaces. A single "done" bit works, but its meaning had to be defined
per-op in the interface (see `ngx_http_compression_io_t`); with that,
the caller loop is fully backend-agnostic. **Interface survived; the
contract text is the fix.**

## 3. The lifecycle ordering invariant is real and must be documented

`create → hint_input_size → attach_dictionary → process`, enforced by
the core module. zstd's `refPrefix` must precede the first compress
call and its parameters must be final; brotli's prepared dictionary
bakes in the quality at attach. Any future backend inherits the
invariant instead of each backend documenting its own footguns.

## 4. Input-size hint must be an optional hook

brotli's `SIZE_HINT` and zstd's pledged size both exist and both must
land before the first byte; a backend without the concept omits the
hook rather than shipping a dead no-op. (Same policy for
`wire_prologue` — see 6.)

## 5. Output sizing has no common question, so the contract asks the weakest one

zstd recommends a fixed stream-chunk size; brotli only offers a
whole-input bound needing a length that chunked upstreams don't have.
Contract settled on "a size at which repeated steps make progress",
`content_length` may be -1. Fine in practice; worth a sentence in the
doc so nobody later "unifies" it into `compressBound()` semantics that
one side can't honour.

## 6. RFC 9842's framing asymmetry costs exactly one nullable hook

dcb prepends a 36-byte magic+SHA-256 prologue the brotli decoder does
not consume; dcz is a plain zstd frame. `wire_prologue` (nullable)
absorbs it; nothing else in the chassis cares. The dictionary seam
otherwise matches the load-bearing claim: backends receive raw bytes
per request (`attach_dictionary`), zstd referencing them in place —
the store's "raw bytes + sha256 only" ownership model held.

## 7. gzip genuinely never needed a backend slot — defer/veto validated live

The election treats `gzip` as a NULL-backend token. Defer = return
without touching `r->gzip_tested` (core gzip below then applied its
entire rule set — the CE:gzip in the matrix came from the core filter);
veto = latch when gzip is absent from the list (client offering only
gzip against `order zstd br` got identity despite `gzip on`);
`compression off` left core gzip fully alone (the migration floor).
The "stupid config" (`compression_order gzip zstd br`) behaves exactly
as the doc's matrix row says: gzip wins by deferral when acceptable,
falls through to zstd/br when the client never offered gzip.

## 8. A unified `compression_level` was considered and rejected in code

zstd 3 and brotli 5 are both "the sane default" yet share no axis. The
real module keeps per-coding tuning directives; the prototype hardcodes
the defaults and says so.

## 9. File buffers are chassis complexity, not interface complexity

Reading file bufs (sendfile-backed responses) needs the same handling
the core gzip filter has, entirely in the shared body-filter chassis —
no backend hook required. Phase-0 rejects file bufs loudly instead.

## Review round 1 (PR #117) — wrinkles found by reading, not building

### 10. The gzip cooperation is OPTIONAL-module territory

`r->gzip_vary`, `r->gzip_tested`, `r->gzip_ok`, and even
`r->headers_in.accept_encoding` exist only under `#if (NGX_HTTP_GZIP)`
in `ngx_http_request.h` — a `--without-http_gzip_module` build got six
compile errors. The sneaky half: **`--with-compat` forces
`NGX_HTTP_GZIP=1`**, so any compat CI build is structurally incapable
of catching this; the gzip-less build shape must be tested explicitly
and without `--with-compat`. Fixed with guards: gzip-less builds do
their own Accept-Encoding lookup (first header, same parity), push
their own literal `Vary: Accept-Encoding` (no flag, no core emitter to
delegate to), and reject the `gzip` order token at config load
("requires nginx built with ngx_http_gzip_module") — better than a
token that silently means identity.

### 11. Flag-delegated Vary is gated on `gzip_vary on` — whose default is off

Setting `r->gzip_vary = 1` only *requests* emission; the core header
filter emits solely when the `gzip_vary` directive is on. The phase-0
validation matrix had `gzip_vary on` and never saw this — a
default-config deployment behind a shared cache would store compressed
responses with no Vary (the classic poisoning shape). Unlike the
abandoned warning in #1, this one IS observable — `clcf->gzip_vary`
is public core conf — so the module now warns at config load when
`compression` is on and `gzip_vary` is off, same policy as the parent
repo's modules. (PHASE0: per-location; productization collapses it
into the #110-style per-module summary.)

### 12. dcz has a wire prologue too — the earlier contract text was wrong

RFC 9842's dcz is not "a plain zstd frame": it opens with a 40-byte
zstd SKIPPABLE frame (magic `0x184D2A5E`, size `0x20`, the
dictionary's SHA-256) that libzstd will not emit — `refPrefix` is
transparent. The real asymmetry with dcb is who consumes the prologue
(zstd decoders skip theirs natively; dcb clients must strip 36 raw
bytes themselves), not whether one exists. Contract text corrected;
phase 1 implements both emitters — or, since both prologues derive
from {magic, hash}, moves emission into the chassis and deletes the
hook. Decision deferred to phase 1 with the store.

### 13. Defer/veto assumes this filter runs before core gzip

True for the default `--add-(dynamic-)module` placement (addon filters
register after core filters and therefore run earlier), but dynamic
module load order can invert it. Failure shape when inverted: core
gzip's filter sees the response first and may compress it before the
election ever runs — the order list is silently ignored for
gzip-accepting clients, not broken outright. Productization needs the
ordering pinned (static builds can order explicitly; dynamic builds
document the load_module requirement, as the parent repo already does
for zstd-vs-brotli ordering).

### Fixed outright in the same round

An exactly-buffer-boundary FINISH double-fired the op (ship-then-loop
re-entered a finished encoder; zstd appends an empty frame, brotli
hard-errors) — the completion check now precedes the full-buffer ship,
flags riding whatever buffer the op ended in. Consumed input chain
links are freed instead of accumulating for the request's lifetime.
Special bufs no longer take NULL-pointer arithmetic through their
cursors. The header filter sets `r->main_filter_need_in_memory` so the
in-memory-only cut can't truncate a sendfile response after headers.
The version floor is enforced at compile time: 1.23.0
(`ngx_table_elt_t.next`), not the 1.9.11 the config script claimed.
The AE parser's header now states its actual scope (one field line —
deliberate core-gzip parity so the defer decision matches what core
gzip concludes) rather than implying combined-field coverage.

## Phase-0 shortcuts (not findings — deliberate scope cuts)

status set is 200-only (real module inherits the zstd filter's set);
no busy/free output-buf recycling; no bypass predicates, dictionaries,
static-file serving, or per-coding tuning directives; build glue links
system libs unconditionally (the hardened auto/* patterns come from
nginx-zstd-module when this stops being throwaway).
