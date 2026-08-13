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

## Phase-0 shortcuts (not findings — deliberate scope cuts)

status set is 200-only (real module inherits the zstd filter's set);
no busy/free output-buf recycling; no bypass predicates, dictionaries,
static-file serving, or per-coding tuning directives; build glue links
system libs unconditionally (the hardened auto/* patterns come from
nginx-zstd-module when this stops being throwaway).
