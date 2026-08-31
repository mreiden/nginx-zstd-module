# Compression-branch catch-up ledger (phase0 ← master #149–#192)

Working audit of eilandert's standalone-module (`src/`) commits since the
phase0 merge-base (#148), one row per commit: how it maps to the unified
compression module, whether it also touches the brotli backend, and any
review notes (correctness / security first). "Port" = a compression-side
code commit; "WRINKLES" = a note explaining why no code change; "Skip" =
standalone-repo CI/tooling with no compression analogue (rolled into one
WRINKLES entry at the end).

Legend: ✅ done · 🔜 queued · 🔎 needs inspection · ➖ n/a

| # | commit | subject | disposition | brotli? | notes |
|---|--------|---------|-------------|---------|-------|
| 150 | e8dc483 | docs: zstd_min_length can't apply to chunked | ✅ 1ef0617 | n/a | WRINKLES.md #33 (README defers reference here) |
| 151 | 3434bf4 | ci: ab_bench.py request-path harness | Skip (CI tooling) | — | compression has own CI |
| 152 | 131b1a7 | ci: config_bench.py config-load harness | Skip (CI tooling) | — | proved dcz dedup O(n²) not worth fixing |
| 153 | 97fa10d | perf: drop unread request pointer from ctx | WRINKLES (already clean) | ➖ | compression ctx has no dead request field — every member is read |
| 154 | b6b50d7 | perf: config-time caching (preformat var, free dict buf) | ◑ preformat ✅ 778d0c2 | ➖ | preformat $compression_dicts_hashed at init_main_conf; free-dict-buf half N/A (refPrefix zero-copy keeps bytes) |
| 155 | 466dfb8 | perf: per-profile CCtx slot ring (4) | WRINKLES (N/A here) | ➖ | no worker-lifetime CCtx cache to ring — backend uses per-request createCCtx |
| 156 | b1557a3 | fix(ab_bench): escape % in help | Skip (CI tooling) | — | |
| 157 | 184ebcd | perf(filter): output/streaming alloc cleanups | ✅ f0c143e | 🔎 | O(1) input tail ported (with #176); first-buf sizing/prefix-precompute/no-op-skip skipped (N/A or risky here) |
| 158 | 8fce91d | security: secure-context (TLS) before dcz | ✅ 10868b4 | BOTH (dcz+dcb) | one gate at match_dict covers both codings; compression_dict_assume_secure_transport |
| 159 | 718958b | security: validate skippable .zst frames | ✅ eb4c02b | ➖ zstd-only | done with #162 (coupled) |
| 160 | 9ba4f81 | security(dcz): key caches on Sec-Fetch-Site | ✅ a236023 | YES (dcz+dcb) | done; Vary line covers both codings |
| 161 | 97ef7b3 | security(ci): trust-anchor downloads | Skip (CI) | — | |
| 162 | bc364ed | security: run .zst frame probe on Windows | ✅ eb4c02b | ➖ zstd-only | done with #159 (coupled) |
| 163 | 947a8b4 | security(vary): Vary by construction | ✅ 704ad03 | YES (both) | done; 2 warnings removed, tests inverted; brotli-fork has same gap |
| 164 | afcf5e6 | fix: SIGFPE zstd_long+zstd_max_cctx_memory | WRINKLES (N/A here) | ➖ | module exposes neither zstd_long nor max_cctx_memory — no config-load estimator to divide by zero |
| 165 | f64eaca | security(dict): reject non-regular paths, strict policy | ✅ acb2598 | YES (dict store shared) | done; +O_NONBLOCK-clear fixes a latent parent short-read hazard |
| 166 | e4c15c6 | feat: warn on large per-request memory | WRINKLES (N/A here) | ➖ | depends on the max_cctx_memory estimator the module doesn't have; revisit if a CCtx budget lands (see #188 note) |
| 167 | dc0cac1 | security(buffers): bound number*size | ✅ 34be27c | YES (both) | compression_buffers_unsafe; size-0 default unbounded |
| 168 | 70593d6 | batch G6 — 7 verified NITs | ◑ rows 6,7 ✅ | mixed | row 7 (d4c7d82) + row 6 bypass_vary token validation (62d910a); rows 1/2/3/4/5 dropped or N/A — see per-nit note |
| 169 | 4db03aa | ci: dcz CDict-vs-refPrefix equivalence probes | Skip (test-proof) | — | refutes config-time CDict cache |
| 170 | 6f672a5 | perf: cache zstd_dict_file CDicts in registry | WRINKLES (N/A here) | ➖ | no CDict at all — backend uses ZSTD_CCtx_refPrefix zero-copy, nothing to cache in a registry |
| 171 | 3256288 | perf(dict): trained CDicts by reference | WRINKLES (N/A here) | ➖ | CDict-specific; refPrefix path has no CDict |
| 172 | 6882c44 | refactor: dedup Available-Dictionary gate | WRINKLES (already unified) | ➖ | match_dict() is already the single AD/SFS gate for both codings |
| 173 | a357575 | perf(cctx): return loan through slot | WRINKLES (N/A here) | ➖ | CCtx-ring-specific; no ring |
| 174 | d7660e5 | perf(cctx): slot profile compare → portable unit | WRINKLES (N/A here) | ➖ | CCtx-ring-specific; no ring |
| 175 | 9852547 | perf(dcz): single-pass AD+SFS header collect | WRINKLES (already present) | ➖ | match_dict()'s one header walk already collects AD and SFS together |
| 176 | 4f8cef6 | perf: fuse chain-copy and tail-track | ✅ f0c143e | 🔎 | single-pass input-chain append + tail track; committed with #157 |
| 177 | 2979ca0 | perf: pack CCtx memory profile into 64-bit key | WRINKLES (N/A here) | ➖ | CCtx-ring-key-specific; no ring |
| 179 | c66cdeb | perf: HEAD fast path in static handler | ✅ 8e2d216 | ➖ static | HEAD returns after send_header (Vary/CE already set); TEST 34 pins header parity |
| 180 | ab77ca2 | feat: markdownlint config + fixes | Skip (repo infra) | — | |
| 181 | 569001a | refactor: extract token validation from bypass_vary | WRINKLES (N/A here) | ➖ | compression_bypass_vary is a plain ngx_conf_set_str_slot — no token validation to extract |
| 182 | 944e6ae | perf: skip hook reg when off everywhere | ✅ f16223c | both | parse-time any_enabled latch in both modules (static grew a main conf); behavior unchanged, existing suite is the coverage |
| 183 | 04ada99 | config_bench: scale points | Skip (CI tooling) | — | |
| 184 | fbaca91 | perf: dynamically cacheable $zstd_ratio etc. | ✅ 0681ed1 | both | per-call no_cacheable; existing 00 TESTs 24a/24b cover the path |
| 185 | ec468ae | warn: couple bypass predicates to cache key | ✅ 34be27c | both | committed with #167 (shared merge) |
| 186 | dda136b | Add early subrequest guard to header_filter | WRINKLES (already present) | both | our early guard already checks `r != r->main` at module.c:1207, before Vary/negotiation — #186 moved the standalone's check to where ours already is. No-op. |
| 187 | ab66a42 | Raise dcz-dicts scale points | Skip (CI tooling) | — | |
| 188 | 62dc98b | fix: clamp dcz window to CCtx budget, key ring on it | WRINKLES (N/A here) | zstd-only | both failure modes structurally absent — see note |
| 189 | 75f4166 | Inline dcz 40-byte prefix into first buffer | WRINKLES (already present) | ➖ | the module already emits the prologue inline ahead of the first encoder buffer (ctx->prologue, prologue_sent) |
| 190 | c9f97ed | test: vendor testkit, reach libzstd failure arms | Skip (CI) | — | |
| 191 | 96d69eb | ci: run gate on push:master | Skip (CI) | — | |
| 192 | 24c29a2 | test: harness under memcheck/coverage + alloc oracle | Skip (CI) | — | |

## Review notes (correctness / security)

- **#163 (Vary by construction)** — clean. The dedup scan over response
  headers is the correct guard against a doubled `Vary` field; O(n) cost
  is negligible. No correctness or security concern in the parent's
  implementation.
- **#165 (dict path hardening)** — clean, and the shared store makes it
  strictly better placed than the parent: one hardened loader covers dcz
  and dcb both, versus the parent hardening only its zstd loader. One
  latent bug in the parent: it opens O_NONBLOCK and keeps the flag through
  the single full-file read, relying on regular-file reads ignoring
  O_NONBLOCK. That holds on ext4 but NOT on every filesystem — a 9p/drvfs
  mount returns a short read and the parent's loader would reject a valid
  large dictionary. Our port clears O_NONBLOCK once the file is confirmed
  regular (fcntl F_SETFL), before the read. **Filed upstream as
  myguard-labs/nginx-zstd-module#193** (branch mreiden:fix/dict-open-nonblock-
  shortread) — reproduced deterministically against an 8 MB /mnt/c dictionary.
  CodeRabbit (2026-08-26) flagged that a single ngx_read_fd() + reject-short
  rejects a valid dictionary on ANY short read (EINTR-after-partial,
  interruptible FS), not just the O_NONBLOCK case — the complete fix is a
  read-full loop behind the O_NONBLOCK clear. **PR #193 CLOSED (not merged)
  2026-08-26.** Two reasons from eilandert: (1) our pushed e1e98ff was
  actually INCOMPLETE — a bad `git commit --amend --only` dropped the staged
  read-full helper, so what shipped was the O_NONBLOCK clear alone despite the
  body/reply claiming the loop (my error; posted an honest correction on the
  PR; see [[git-amend-verify-commit]]); (2) fork PRs can't clear the
  myguard-labs CI gate from his side. He is landing the COMPLETE fix himself
  on an in-repo branch — same design (shared read-full helper, both loaders,
  EINTR + short + early-EOF-as-error, keep the O_NONBLOCK clear, tests for
  short/EINTR/truncated/zero-length). **MERGED as #195 (9251befb).** His
  ngx_http_zstd_read_dict_file(): loop + EINTR-retry guarded #if !(NGX_WIN32)
  + early-EOF fatal (distinct "changed size during load" message), both
  loaders, O_NONBLOCK clear kept, a unit test that extracts the helper and
  kills 3 mutants, and the path-hardening test finally wired into CI.
  Reviewed clean — better than ours (the NGX_WIN32 EINTR guard our dropped
  commit lacked would have broken the MSVC build). **MIRRORED into the
  compression loader (6943086):** ngx_http_compression_read_dict_file() —
  same loop + NGX_WIN32 guard, count-returning to preserve this loader's
  optional-skip logging (his standalone has no optional mode). 710 suite
  green. **Short-read UNIT test added both sides** (Mark, 2026-08-26,
  mirroring his extract-and-drive #195 fixture): compression
  compression/tools/test_read_dict_file_unit.{sh,c} (43d7bf2, wired into
  compression.yml) and brotli-fork tools/test_read_dict_file_unit.{sh,c}
  + the dcb loader's OWN read-full fix ngx_http_brotli_read_dict_file
  (7aeb301 on hardening, wired into its build-test.yml). Extraction strips
  CR (Windows CRLF working tree) and, for the brotli google-style, picks
  the definition over the identically-opening forward decl on the body
  brace. 7 assertions each (full/short/dribble/EINTR/early-EOF/error/
  immediate-EOF), non-vacuous by construction (multi-read totals kill the
  single-read mutant). Brotli hardening commit NOT pushed — awaiting
  Mark's push+ff word.
- **#194 (bump vendored testkit) — Skip (CI).** Standalone-repo testkit
  submodule bump; no compression analogue.
- **#196 (writer-legal zero-size last_buf on a terminal empty frame) —
  WRINKLES (already handled, cleaner).** The parent shipped a zero-size
  TEMP buf (ngx_create_temp_buf) at a content-less terminal FINISH, whose
  `temporary`+in-memory flags made nginx's writer reject it ("zero size buf
  in writer"); its fix clears those flags. The compression body filter
  never has the problem: at `ob->last == ob->pos` it ships a fresh
  ngx_calloc_buf (a genuine special buf, pos==last==NULL, no `temporary`),
  which ngx_buf_special() accepts by construction (module.c:2352, comment
  documents the intent). No zero-size temp buf ever reaches the writer.
- **#197 (align directio probe offset for a skippable-prefixed .zst) —
  DONE (0adc94c).** The skippable-frame walk moved the probe offset to the
  frame end (unaligned), which O_DIRECT rejects with EINVAL → declined the
  precompressed variant. Ported the round-down-to-align + two-block read +
  parse-at-frame-offset. 03-static TEST 35 pins it; NON-VACUITY is
  ext4-block-device-only (drvfs/tmpfs don't enforce O_DIRECT alignment) —
  confirmed fail-first with the servroot on the WSL ext4 root.
- **CATCH-UP STATUS (2026-08-26): merged work fully caught up.** Every
  merged upstream PR #150–#197 is Port / WRINKLES / Skip / mirrored.
  OPEN and NOT ported by decision: #198 (Mark disagrees) and #199 (looks
  useful — wait for merge, then port). Nothing else outstanding before the
  phase0 update.
- **#158 (secure-context gate)** — clean. Note a scope difference from the
  parent worth flagging back: the parent gates only dcz (its brotli/dcb
  negotiator is a separate fork). In the unified module dcb rides the same
  match_dict() election, so a dcb response over cleartext is the identical
  length-oracle exposure — our single gate closes both. The brotli fork
  (mreiden/ngx_brotli) needed the SAME gate on its dcb path; **DONE on the
  hardening branch (9f98219): brotli_dcb_assume_secure_transport +
  fail-closed gate in ngx_http_brotli_dcb_negotiate().**
- **#188 (dcz window clamp) — WRINKLES, does not apply yet.** The parent
  fixes two things that both depend on machinery the compression zstd
  backend does not have: (1) *ring contamination* — the parent keys a
  worker-lifetime CCtx ring on window_log and a dcz request poisoned a
  slot's retained workspace. Our backend calls ZSTD_createCCtx() ONCE per
  request, r->pool-cleaned (grep: a single createCCtx site, no ring, slot,
  or registry), so there is no shared slot to contaminate. (2) *budget
  escape* — the parent clamps the dcz window to zstd_max_cctx_memory. The
  compression module exposes no max_cctx_memory directive at all, so there
  is no budget to escape. And dcz does not yet size its window beyond the
  browser cap: ngx_http_compression_zstd_create()'s PHASE3 note defers the
  "size the window up to dictionary + content" work to attach_dictionary,
  unlanded. Nothing to clamp today. REVISIT when that phase-3 dcz
  window-up-sizing lands AND/OR a per-request CCtx memory ceiling is added
  — at that point port the pure-helper pattern (one function feeds both
  the applied windowLog and any ring key, so they cannot diverge).
- **Brotli fork follow-up (from #163): DONE (hardening 9f98219).**
  mreiden/ngx_brotli's static and filter modules carried the identical
  gzip_vary-directive dependency — a negotiated brotli response shipped
  without Vary under the default `gzip_vary off`. Fixed with a shared
  header-static ngx_http_brotli_vary_accept_encoding() (both modules),
  a combined "Vary: Accept-Encoding, Available-Dictionary" for dcb
  locations, and removal of the obsolete gzip_vary-off warning apparatus
  (main-conf counters + vary_handled_externally detector). Committed with
  the #158 brotli gate in the same hardening commit.
- **Brotli fork #160 (Sec-Fetch-Site in dcb Vary): DONE (hardening b66bea4).**
  The dcb combined Vary line now reads
  "Accept-Encoding, Available-Dictionary, Sec-Fetch-Site" (the gate already
  refused cross-site; this makes shared caches partition on it, including on
  the refused br fallback). The brotli fork's dcb Vary picture now matches
  the compression module's.

- **#168 (7-nit batch) per-nit disposition:** row 1 (HEAD fast path) the
  parent itself DROPPED — it caused a 500-after-headers-committed and a
  byte-ranges regression; not ported. Row 5 (dcz ceil-log2 helper) N/A —
  the module has no dcz window-log computation to replace (dcz
  window-up-sizing unlanded, #188 note); the window_cmd loop is over
  power-of-two size *values*, a different job. Rows 2/3/4 are N/A here:
  the module deliberately does NOT skip r->header_only (a HEAD must
  advertise the GET's Content-Encoding — parent-audit find, so row 2's
  reorder has nothing to reorder), never had the repeated ngx_buf_size()
  row 3 factors (grep: zero uses), and holds output in an ngx_buf_t*
  (ctx->ob) rather than the value-struct ctx->buffer_out row 4's
  memzero→NULL targets. Row 6 (bypass_vary field-name validation) PORTED
  (62d910a) — it emits a literal Vary field, so a malformed value is a
  cache-correctness issue worth rejecting at load. Row 7 (bounded header
  logging) PORTED (d4c7d82).
- **Deferred perf/refactor — ALL cleared.** #157+#176 (O(1) input-chain
  tail, f0c143e), #179 (static HEAD fast path, 8e2d216), #182 (skip hooks
  when off everywhere, f16223c), #168 row 6 (62d910a), and #154's
  preformat-variable half (778d0c2) are all ported. Nothing left open —
  every standalone commit #150–#192 is now Port / WRINKLES / Skip
  accounted for.
- **Leak detection (#192's alloc-neutral oracle) — DEFERRED, not skipped.**
  The compression CI (compression.yml) runs only the Test::Nginx suites +
  the two proxy tools; it has NO leak detection of any kind (no ASan, no
  valgrind, no per-request allocation oracle). #192's alloc-neutral oracle
  — snapshot cycle-pool counters + worker/master fds around one extra
  compressed request and assert flatness, with an anti-vacuity check —
  catches a per-request leak class that LSan-at-exit and every functional
  test miss (directly relevant: the body filter allocates chain links +
  output bufs per request). It is NOT a code port: it rests on #190's
  fault-injection testkit, so it means building/adapting a harness that
  drives the compression .so and snapshots pool/fd state — a real CI
  project. DEFERRED by Mark until phase0 is closer to merging (functional
  coverage is strong for now); revisit as its own scoped effort then.
  RELATED (2026-08-29, the A29 batch survey): our asan CI job runs with
  `detect_leaks=0` — LSan is deliberately OFF, so upstream #253 ("fail
  closed on indeterminate LSan") has nothing to attach to here yet. When
  the leak effort is picked up, do BOTH halves together: turn LSan on in
  the asan job (drop `detect_leaks=0`, budget for the known nginx-cycle
  suppressions) AND adopt #253's positive-control + fail-closed pattern
  so "the detector could not run" can never read as a pass. Same applies
  to the brotli fork's build-asan job (same detect_leaks=0 shape).

## Skipped (standalone-repo CI/tooling, no compression analogue)

Rows #151, #152, #156, #161, #169, #180, #183, #187, #190, #191, #192 — benchmark
harnesses, testkit vendoring, CI trust-anchoring, markdownlint, and
test-proofs that live in the standalone repo's `ci/` tree. The compression
module carries its own `compression.yml` and `compression/t/` suites; these
have no one-for-one target here. Recorded for completeness, not ported.

## Era 2: standalone PRs #193–#253 (2026-08-26 → 2026-08-29)

Continuation past the #150–#192 audit above, one row per merged
standalone PR (ours included where they round-tripped).

| # | subject | disposition | brotli? | notes |
|---|---------|-------------|---------|-------|
| 197 | directio probe offset for skippable prefix | ✅ (earlier) | ➖ | $skip_dio fixture pins it in 03-static.t |
| 198 | verify supplied dict hashes | ✅ e6d6e1c era | YES | verify-default; see #220 |
| 199 | strict dict path walk | ✅ acb2598 lineage | YES | with #165 |
| 200 | MINOR/NIT batch (byte counter, Vary dedup, helpers) | ✅ where applicable | ◑ | adopted piecemeal across phase-3 commits |
| 202 | Vary from usable sidecar, probe before acceptance | ✅ 4561880 | YES 4f59f21-era | round-4 ruling |
| 207 | $bytes_* via %uL | ✅ by construction | ➖ | variables print %uL (module.c:1247) |
| 208–213, 233 | perf cluster (probe cap, block reuse, gate hoist) | 🔜 queued | 🔎 | next perf pass |
| 214 | Test::Nginx @0.32 pin | ✅ dff9033 → superseded by #249 row | YES 6ecfbf8 | |
| 215 | chained Accept-Encoding negotiation | 🔜 queued | 🔎 | needs the defer-story design talk first |
| 218 | prove ZSTD_freeCCtxParams exits | ➖ N/A | ➖ | no config-time cctx estimator here (#164/#240 lineage) |
| 220 | (ours) dict trust-hashes opt-in | ✅ e6d6e1c | YES 127d5f2 | |
| 222 | dict bypass main-request gate | ✅ f5ed798 | ➖ | his review fixed our subrequest hole |
| 229 | output-side zero-delta advance guard | WRINKLES | ➖ | input side already guarded (module.c:2550); ob->last provably non-NULL; sanitized CI would trap |
| 230 | (ours) filterless bypass warning | upstream-pending | ➖ | rebased 98e1967, mergeable |
| 234–236 | perf leftovers | ◑ partial N/A | ➖ | per earlier survey |
| 237 | ZSTD_STATIC_LINKING_ONLY out of dynamic ABI | ✅ c73a5f3 (taken further) | ➖ | one accepted import, self-defined TU |
| 239 | servroot gitignore | ✅ | ➖ | .gitignore analog |
| 240 | cctx budget test pin | ➖ N/A | ➖ | no zstd_max_cctx_memory here |
| 241 | static handler decomposition | ➖ N/A | ➖ | architecture differs; nothing to decompose |
| 242 | UBSan ignorelist attempt | ➖ closed unmerged | ➖ | validates our warn-level witness approach |
| 243 | (ours, parent CI) artifact pins | ➖ parent-only | ➖ | |
| 244 | docs: directive gaps | ✅ 914d2c6 (audit: no gaps; no-transform doc added) | ➖ | |
| 245 | A29 CI gates (CodeQL scope, TAP floor, dcz alloc test) | ➖ N/A | ➖ | no CodeQL job; our perl suites propagate exit codes (no `\|\| true`) |
| 246 | fuzz regression naming contract | 🔜 minor | ➖ | when fuzz regressions/ gains entries |
| 247/248 | Windows + arm64 smokes | 🔜 optional | 🔜 | free arm64 runners make it cheap |
| 249 | CPAN lock for Test::Nginx | ✅ 82bdd9b | YES 9bf378f | + LC_ALL=C sort fix, LF gitattribute |
| 250 | forbid static-only zstd imports | ✅ c3383cc (adapted) | ➖ | asserts the ONE import present + estimators absent |
| 251 | honor no-transform | ✅ 25257d0 | YES 2bde375 | unified delta: gzip veto; fork keeps standalone semantics |
| 252 | reserved descriptor bit (still OPEN upstream) | ✅ 06e8288 | ➖ | review posted w/ cross-ref |
| 253 | fail closed on indeterminate LSan | DEFERRED | DEFERRED | joined to the #192 leak-effort TODO above (detect_leaks=0 today) |

### Batch: #254–#267 (2026-08-30)

| # | subject | disposition | brotli? | notes |
|---|---------|-------------|---------|-------|
| 254 | (ours) no-transform '=' cut | ✅ was ours; compression had it first (25257d0) | YES 2bde375 | merged upstream in <1h |
| 255/256 | A29 sweep/second-pass CI closes | ➖ N/A | ➖ | his linter estate; #255 retargeted linkage check at objs/nginx (our c3383cc shape) |
| 257 | probe decomposition (lizard CCN) | ➖ N/A | ➖ | his complexity linter's limit, not ours |
| 258 | one-block buf+payload alloc; hex nibble helper | ✅ bebc57d (buf half; hex already our shape) | 🔎 | |
| 259 | fixed-width frame decodes | ✅ 14106ac | ➖ | LE memcpy + bytewise fallback |
| 260 | lazy input-chain retention | ✅ 5dd4955 | 🔎 | simpler here (per-link FINISH); drain-order oracle gap joined to deferred-testkit item |
| 261 | probe read-ahead reuse (58B) | 🔜 with #233 | ➖ | stacks on unported #233's have_block cache; goes with the perf-cluster probe pass (#208/#233/#261 as one unit) |
| 262 | EVP digest ctx reuse | ✅ 16c65ae (self-contained; header signature owed nothing to his #262 change) | 🔎 | |
| 263 | shared vary token scanner | ➖ N/A | ➖ | our Vary is by-construction single-line; no scanner pair to dedup |
| 264–267 | linter work-list/LSan/docs/tarball-verify | ➖ N/A | ➖ | CI estate |
