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

Both dict codings prepend a magic+SHA-256 prologue (dcb: 36 raw bytes
the brotli decoder does not consume; dcz: a 40-byte zstd skippable
frame the decoder skips natively — see 12, which corrected this
section's original "dcz is a plain frame" claim). They differ in who
consumes the prologue, not whether one exists. `wire_prologue`
(nullable; NULL = the dict coding is unelectable) absorbs both;
nothing else in the chassis cares. The dictionary seam otherwise
matches the load-bearing claim: backends receive raw bytes per request
(`attach_dictionary`), zstd referencing them in place — the store's
"raw bytes + sha256 only" ownership model held.

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

## Phase 1a — the store's own findings

### 14. Store entries must be pointer-stable, and the API shape almost wasn't

First cut held `ngx_http_compression_dict_t` VALUES in the store
array while per-location lists aliased them — and `ngx_array_push()`
relocates element storage on growth, so every alias went stale the
moment a fifth dictionary loaded. Latent in 1a (nothing reads the
lists yet), lethal in 1b. Caught while writing the store's own
documentation, pinned by the six-dict growth test (a duplicate
re-declaration after forced growth: pointer-compare against a stale
alias silently accepts; the pointer-store errors). Entry objects are
now individually allocated; the array holds only pointers.

### 15. "Supplied never satisfies unsupplied" buys a free audit

The RFC rule mandates a computation whenever an unsupplied directive
references a path whose entry knows only a verbatim hash. Since that
pass is paid for regardless, comparing it against the supplied value
costs nothing — and catches exactly the stale-supplied-hash hazard
(deploy script hashed an older file) that verbatim trust cannot see.
A mismatch is a config error naming the hazard. This slightly exceeds
the RFC text, in the safe direction; the doc should adopt it.

## Phase 1b — negotiation and the wire

### 16. `ngx_base64_decoded_length()` is an upper bound, and it bit twice

The Available-Dictionary value is an RFC 8941 Byte Sequence — base64
of exactly 32 bytes, exactly 44 characters with one `=` pad. The
first-cut validity check compared `ngx_base64_decoded_length(44)`
against 32; the macro ignores padding and returns 33, so the check
rejected EVERY valid header and all dict elections silently degraded
to base codings. The failure was invisible to roundtrip-style tests
(fallback still decodes fine) and was caught only when the matrix
asserted the Content-Encoding per case — graceful-degrade negative
paths need positive assertions or they hide. Second bite: the decode
buffer must be sized by the macro's bound (33+), not the hash length —
a pad-less 44-character value legitimately decodes to 33 bytes, and a
32-byte buffer was a one-byte overflow awaiting a malicious header.
Rule now in code: validate the ENCODED length (== 44), decode into a
bound-sized buffer, then require the decoded length (== 32).

### 17. Chassis-vs-backend prologue emission: SETTLED, per-backend

The round-1 alternative (chassis emits both prologues from {magic,
hash} descriptor fields) dies on inspection: dcz's prologue is a
VALID ZSTD SKIPPABLE FRAME — magic and little-endian size word are
zstd format knowledge — while dcb's is raw out-of-band bytes the
decoder never sees. A chassis emitter needs per-backend format
descriptors, which is the hook wearing a struct costume. The hook
stays; the readiness gate (`wire_prologue != NULL`) now also covers
capability holes for free — a libbrotli < 1.1 build simply cannot
elect dcb.

### Wire behavior pinned by the phase-1b matrix

dcz = 40-byte skippable frame (`5e 2a 4d 18 20 00 00 00` + SHA-256)
then a checksummed zstd frame (the parent's #102 defence-in-depth,
set at attach so plain zstd keeps bare frames); dcb = 36 raw bytes
(`ff 44 43 42` + SHA-256) the client strips. Dict codings elect only
on an EXPLICIT Accept-Encoding token — `*` never elects them — and a
client that accepts dcz without zstd still gets dcz. No match, wrong
hash, or malformed header degrade to the base coding. Wherever
dictionaries are configured, every eligible response varies on
Available-Dictionary (module-pushed, both build shapes), identity
included. Both codings verified byte-exact through the reference
CLIs with the dictionary proven load-bearing (99 and 92 bytes for a
19,400-byte fixture).

## Phase 2 — static serving (mostly a confirmation round)

Phase 2 produced no new interface wrinkles — as predicted, it never
touches a compression library, and the backend vtable sits it out
entirely. What it CONFIRMED:

- **The #76 latch class is structurally gone.** One handler probing
  codings in order either serves, falls to the next coding, or
  declines whole — there is no cross-module latch to strand a
  fallback. The window-cap decline now lands on a BETTER answer than
  the split modules could produce: an oversized `.zst` falls through
  to the `.gz` sidecar (pinned by test), where the parent zstd_static
  could only decline to identity.
- **gzip subsumption is literal.** A `--without-http_gzip_module`
  build serves `.gz` sidecars byte-exact with `Content-Encoding:
  gzip` — file serving needs no zlib. The static coding table carries
  gzip as a peer entry, no backend, no defer/veto.
- **The window-cap port stayed a port.** The probe (magic sanity +
  RFC 8878 declared-window parse, directio-aligned geometry,
  pread-only for open_file_cache safety) is the parent's reviewed
  implementation with names changed; its scope note (leading regular
  frame only) carries over verbatim.
- PHASE2 note for productization: the static coding table is literal
  in static.c; the registry should grow a `sidecar_ext` field so a
  future coding lands in static serving automatically (gzip stays a
  table entry either way — it has no backend to hang an ext on).

## Review round 2 (phases 1b–2)

### 18. The dcb prologue could overflow its output buffer — comment-certified "safe"

Blocking find, reviewer's. `BrotliEncoderMaxCompressedSize(1..29)` is
smaller than the 36-byte dcb prologue, so a tiny known-length body
sized an output buffer the prologue `memcpy` overran — and the comment
four lines up said "every backend's out_size dwarfs 40 bytes", which
is true for zstd's FIXED recommendation and false for brotli's
CONTENT-DERIVED bound. ASan-reproduced before fixing: the heap write
lands via the NEXT encoder step (the advanced `ob->last` makes
`out_len` wrap), the worker SURVIVES, and the client gets a 200 with
a silently corrupt body — production shape, not a crash. Fixed with a
chassis clamp where `prologue_len` becomes known (`out_size =
max(out_size, prologue_len)`) — the guarantee belongs to whoever
sizes the buffer, never to per-backend accidents. Pinned by one-byte
dcz/dcb roundtrip tests. Rule for the ground-rules list: a comment
asserting a numeric safety property is a claim, and claims get
clamps or asserts, not prose.

### 19. One combined Vary line, not two

Reviewer's find: the delegated `Vary: Accept-Encoding` (via
r->gzip_vary) plus the literal `Vary: Available-Dictionary` meant TWO
Vary lines on the wire — legal per RFC 9110, but a fair number of
intermediary caches key on the first line only, which is precisely
the hazard the header exists to prevent. Dict-configured locations
now push ONE combined `Vary: Accept-Encoding, Available-Dictionary`
and skip delegation entirely (so the core emitter cannot add a second
line, and those locations no longer need — or get warned about —
"gzip_vary on"). The suites' substring matches passed on either
shape, which is its own lesson: header-shape assertions must pin the
exact line and the ABSENCE of the split form. Accepted narrow corner,
documented in code: a gzip deferral in a dict location lets core gzip
emit its own AE line beside the combined one.

### 20. Decode roundtrips live in the suites now

Reviewer's find: every suite asserted headers and prologue bytes, but
nothing fed a response back through a real decoder — the "decodes
byte-exact" claims were hand-validated and unprotected against
regression. t/04-roundtrip.t decodes every block's body through the
reference CLIs (`add_response_body_check` + a `--- decode_with`
section), with an incompressible ~200 KB fixture forcing multiple
output-buffer ships (the double-FINISH path) and the one-byte blocks
doubling as the overflow pins. Also acknowledged for CI wiring:
clang-tidy currently errors on the compression/ files for want of the
nginx include path — its C analysis is NOT running on this tree yet
and must not be trusted as clean until wired.

### 21. gzip_static's validation ledger, read side by side

Asked whether nginx's gzip_static validates anything we don't (magic
bytes 0x1f 0x8b?), the answer from its source is that it validates
NOTHING content-wise — it never reads a byte of the file before
serving. Rename /etc/passwd to index.html.gz and it ships as
`Content-Encoding: gzip`; a zero-byte .gz (a valid gzip stream is at
least ~20 bytes) ships as an empty gzip body. Its only checks are the
filesystem-level ones we already ported (open-error triage, is_dir,
is_file).

DECISION: we intentionally do NOT add a .gz magic-byte check, matching
the existing module. Twenty years of gzip_static practice treats the
sidecar's content as the operator's contract, and guarding operator
error would cost a per-request pread on every .gz serve. The zstd
probe is not a counterexample but a different CATEGORY: it exists
because browsers hard-reject declared windows over 8 MB, so an
unprobed .zst can be a guaranteed-broken response for every client —
that's serve-safety tied to a client-enforced protocol limit, and it's
also why the probe stays unconditional rather than behind some
`compression_static_validate` knob (a knob named "validate" would
misdescribe it, and defaulting it off-for-gzip/on-for-zstd proves the
two aren't one option). Its magic check rides along in the same pread
for free. Brotli is unvalidatable by design — raw streams carry no
magic. If integrity checking is ever wanted, it's a separate opt-in
productization item, uniformly framed as such.

The side-by-side read also surfaced two deltas running the OTHER way
— things gzip_static does that the port didn't:

- it sets `r->allow_ranges = 1`. On the static side ranges are
  coherent (the representation IS the sidecar's bytes, the validator
  is strong) and they only work by opting in — the range filter bails
  unless allow_ranges is set, which is also why the parent
  zstd_static's `clear_accept_ranges` was purely defensive (its own
  suite documents that). The port had cleared ranges with a
  filter-side justification; migrators off gzip_static would lose
  resumable downloads. Fixed: the static handler opts in.
- it sets `b->sync = (b->last_buf || b->in_file) ? 0 : 1`, guarding
  the empty-sidecar-in-a-subrequest case where a flagless zero-size
  buf trips the "zero size buf in output" alert. The port was missing
  the line. Fixed, with an SSI-include test pinning the silence.

Lesson: porting "intact" from ONE parent quietly inherits that
parent's divergences from the module being subsumed. Every subsumed
module deserves its own side-by-side read of the original.

### 22. Tuning directives: one name, keyed by coding (phase 3 opens)

Phase 0 rejected one unified level VALUE (wrinkle 8: zstd 3 and
brotli 6 share no axis); what survives phase 3 is one unified level
NAME: `compression_level <coding> <n>` and `compression_window
<coding> <size>`, validated against bounds the backend DECLARES in
the vtable (level_min/max/default, window_bits_min/max/default). The
shape buys three things: a new backend gets both directives for free
with its registry entry (the extensibility contract with zero new
commands); the non-backend tokens get educational rejections instead
of silently configuring nothing (`gzip` → "use gzip_comp_level" —
defer means the core's own tuning applies; `dcz`/`dcb` → "tuned
through the base coding" — a prepared brotli dictionary bakes in the
quality, so a separate dict knob would be a lie); and defaulting
lives in ONE place (conf merge resolves unset slots from the declared
defaults, so backends never see an unset value).

Found while declaring the defaults: the phase-0 shim said brotli 5;
ngx_brotli's `brotli_comp_level` default is 6. The drift is corrected
and pinned (suite block on the default's debug witness). Lesson:
prototype constants that stand in for "the parent's default" get a
parity check the moment the real seam lands, because nobody re-reads
a shim.

The deterministic test witness is a debug line logging exactly what
reached the encoder ("compression: create zstd level 19 window_bits
23") — applied-parameter witnesses beat ratio assertions, which hang
test outcomes on codec internals. Tuned blocks still decode through
the reference CLIs so "a tuned stream is a valid stream" stays
proven (the parent's negative-level lesson).

Known interaction deferred with a note in the zstd backend: the
parent's dcz path sizes the window UP to dictionary + expected
content (far end of a big dictionary must stay addressable); an
operator window ceiling below the dictionary size degrades ratio
silently. That computation belongs to attach_dictionary and lands
with the prepared-dictionary work.

### 23. The backend roster is a build-time variable (review question)

Asked directly on the branch: does `NGX_HTTP_COMPRESSION_NBACKENDS 2`
hold up when the module is built without libbrotli or libzstd? It
did not — the constant was hand-set, the backend TUs included their
library headers unconditionally, the registry fill referenced extern
symbols that would not link, and the conf's tuning arrays were sized
to a roster that stopped being true. Now:
`NGX_HTTP_COMPRESSION_HAVE_ZSTD`/`_BROTLI` (default 1; the config
script or -D sets 0), NBACKENDS is DERIVED as their sum, each backend
TU compiles to nothing under its 0, the registry fill is DENSE under
the same guards (no holes — registry position stays a valid conf-slot
index), and absent codings fail with "this nginx was built without X
support" instead of the lying "unknown coding". Registry walks are
terminator-based, not count-based — count-walks trip
-Wtype-limits/-Werror the moment a constant bound can be zero.

The zero-backend build is deliberately LEGAL and useful: static
sidecar serving is file serving for every coding, so the .zst window
probe now reads RFC 8878 format constants instead of <zstd.h> macros
and static.c includes no compression library at all — a lib-less
build still subsumes gzip_static and serves .zst/.br byte-exact.
Verified live: all three reduced shapes (no-brotli / no-zstd /
neither) build clean and smoke — static .zst + .br served with
correct CE in every shape, dynamic election falling to the remaining
backend, absent-coding config errors asserted. What this does NOT yet
include: the config-script feature detection that would set the HAVE
macros from a real probe — that stays with the hardened-build-glue
item; the -D path is how CI can exercise the shapes meanwhile.

Script lesson (again): `set -o pipefail` + `nginx -t | grep -q` eats
the match — nginx -t exits nonzero BY DESIGN on the config errors
under test, and pipefail propagates it past grep's success. Capture
first, then grep.

### 24. Buffer recycling: never return holding unconsumed input

The busy/free recycling (core gzip's pattern, via the parent) landed
with one real lesson re-learned from scratch: the first cut handled
the buffer cap by shipping what it had and RETURNING, betting the
caller would re-invoke with the remainder. nginx's filter contract
makes no such promise — on a fast local socket the capped response
stalled to the test timeout ("no last chunk found"), because nothing
downstream had a reason to poke again. The parent's outer loop is the
correct shape and is now ours: produce until the cap pauses, ship,
reclaim via ngx_chain_update_chains, and RESUME IN THE SAME
INVOCATION whenever the reclaim freed anything. The only legitimate
early return is the genuinely-slow-client case (ship drained nothing
back), which returns NGX_AGAIN and leans on r->buffered keeping the
writer re-poking — the entry-path nomem block picks the request back
up on the next pass.

`compression_buffers <num> [size]` is TAKE12, not the stock bufs
slot's TAKE2, because size is genuinely optional here: the backend
already recommends a step size, so most operators only want the
count cap. An explicit size overrides the recommendation; the
dict-prologue clamp applies to either source. Suite witnesses: with
cap 2 against ~200 KB of incompressible output, the pause line AND
the reuse line are both certain (finishing at all requires reuse),
and the decode roundtrip proves the pause/drain/resume seams
preserved the stream; the default cap is pinned to stay dormant on
an ordinary response.

### 25. Bypass predicates: the gzip token is part of the stack

compression_bypass / compression_bypass_vary are the parents'
zstd_bypass pair ported near-verbatim (stock set_predicate_slot /
test_predicates; the operator-named extra Vary field on BOTH paths;
the orphaned-bypass_vary config warning). ONE deliberate delta: in
the parents, bypass falls through to whatever other compression
modules run below — a zstd_bypass'd response can still come back
gzip-compressed by core gzip, which is arguably fine for standalone
modules that own only their coding. In the unified module gzip is an
election TOKEN of this stack, so bypass VETOES it too (latches
r->gzip_tested/gzip_ok): "do not compress this endpoint" has to mean
the whole stack, or the BREACH-mitigation use case silently fails
through the deferral door. Pinned by a paired test: bypass + gzip on
+ AE gzip serves identity, and the same config without the predicate
match compresses via the deferral (the positive control that proves
the veto is doing the work).

Suite note: Test::Nginx's response_headers matcher FOLDS same-name
header lines with ", " — asserting the folded value is how you pin
"both Vary lines present" (and the fold initially read as a failure).

### 26. The proxy-backed tools land: what they pin vs patrol

compression/tools/ gains the two harnesses everything above kept
deferring to, both parent-tool-disciplined (threaded backend verified
before nginx starts, decode-and-byte-compare oracles, root-run
umask/chmod fixes, 30s reap budgets):

- test_flush_paths.py PINS end-to-end mid-stream FLUSH: an unbuffered
  proxy in front of a chunked upstream with real inter-write delays
  makes every delayed segment reach the filter with a flush flag, and
  the client's arrival-timestamp witness (compressed bytes on the
  wire BEFORE the response ends, gaps matching the upstream's long
  pauses) proves FLUSH produced decodable output mid-stream. The
  chunk-size matrix varies per-flush output sizes — the honest form
  of FLUSH/FINISH-at-exactly-ob->end coverage stays a PATROL:
  compressed sizes aren't controllable, so the boundary is swept, not
  forced. Tool-rig lesson: witness math must derive from the case
  (the first cut hard-coded every-8th-chunk long delays and demanded
  2 gaps — a 3-chunk case can never produce them; positions and the
  requirement now derive from the chunk count).

- test_slow_drain.py PINS the recycling pause that local sockets
  cannot produce: sndbuf=16384 + compression_buffers 2 + ~1 MB
  incompressible + a deliberately slow reader (small SO_RCVBUF too —
  without it the client kernel buffers everything and nginx never
  feels backpressure). The genuine cross-invocation pause got its own
  witness line for exactly this: "resuming after drain" logs ONLY on
  the writer-driven re-entry through the nomem block, never on a
  same-invocation resume. Measured on landing: 52 genuine pauses
  across the two codings, streams byte-exact through all of them.

Both tools need the module compiled in (checked via nginx -V);
slow-drain additionally requires --with-debug and says so instead of
passing vacuously. CI wiring for both remains with the CI item.

### 27. The exact-boundary corner is PINNED (Mark's inversion)

The FLUSH/FINISH-lands-exactly-at-ob->end case was recorded twice
below as honestly unpinnable: compressed sizes are not controllable,
so the suites and test_flush_paths could only patrol the
neighborhood. Mark's insight during the phase-3 soak inverts the
problem: the compressed size of a DETERMINISTIC input is itself a
deterministic value C, and the buffer size became an operator
directive in this very phase — so instead of steering content onto a
fixed boundary, MOVE THE BOUNDARY ONTO THE CONTENT.
tools/test_exact_boundary.py measures C per coding with a generous
buffer, restarts nginx with compression_buffers 2 <C> (and C/2, which
produces a full-buffer ship AT the boundary mid-op and then
done-at-boundary; plus C+-1/C+-2 neighbors), and asserts the module's
new witness line — "finish landed exactly at buffer end", logged only
when an op completes with its last byte parked on ob->end — fired for
every exact case, with every case decoding byte-exact. First run: C =
16394 (zstd) / 16388 (br) for the 16 KB fixture, witness x4, all
neighbors clean.

Preconditions the tool asserts rather than assumes: the fixture is
small enough that both encoders buffer ALL input through PROCESS and
emit the entire stream at FINISH (nothing reaches ob earlier — if
that drifts, the witness count comes up short and the tool fails
loudly). The FLUSH-at-boundary variant would need the same trick
against a measured first-flush segment; left as a patrol in
test_flush_paths for now. For the record: the seed idea arrived as a
generated script that padded random bytes AFTER a brotli stream to
hit an exact file size — invalid output and the wrong layer (files
have no buffers), but the exact-size INSTINCT was the right one; it
just belonged on the buffer knob.

## Boundary coverage (post round 2)

Round 2's overflow was a boundary bug, so the boundaries got a sweep
of their own. Now pinned deterministically: the dcb clamp crossing
(content lengths 29 and 30 — 30 also exercises
prologue-exactly-fills-buffer, forcing a full-buffer ship before the
encoder's first byte); `min_length` equality (the gate is `<`);
Available-Dictionary encoded lengths 43/45 beside 44; supplied-hash
lengths 63/65; the empty dictionary file; and the zstd window-cap
EDGES via hand-crafted frame headers (tiny byte strings — the probe
only reads headers and decline paths never serve, so no 8 MB fixtures
needed): descriptor window exactly 8 MB passes vs 16 MB declines,
single-segment exactly 8 MB passes vs 8 MB + 1 declines, the 2-byte
FCS +256 offset, 3/4/5-byte truncation branches, and the
skippable-lead exemption. The directio property from the parent's
#101 review — the window check must not be skipped under O_DIRECT —
is now witnessed in-suite (aligned-probe debug line + decline, at
default and 16k alignment).

Honestly NOT deterministically pinned AT THE TIME (see 27 — the
FINISH case is now pinned by tools/test_exact_boundary.py): a
FLUSH/FINISH landing at
exactly `ob->end` (the round-1 double-FINISH class) — compressed
sizes aren't controllable, so the multi-buffer roundtrips exercise
the neighborhood every run without guaranteeing the exact byte; and
the empty-FLUSH special-buf path, which needs a mid-stream flush a
`return`-based test cannot produce. Both belong to the proxy-backed
tools at productization (the parent repo's pattern), not to prose
claims of coverage.

## Phase-0 shortcuts (not findings — deliberate scope cuts)

status set is 200-only (real module inherits the zstd filter's set);
no busy/free output-buf recycling; no bypass predicates, dictionaries,
static-file serving, or per-coding tuning directives; build glue links
system libs unconditionally (the hardened auto/* patterns come from
nginx-zstd-module when this stops being throwaway).
