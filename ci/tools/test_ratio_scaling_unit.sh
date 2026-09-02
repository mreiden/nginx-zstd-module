#!/bin/bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Unit fixture for ngx_http_zstd_ratio_parts() -- the overflow-safe
# $zstd_ratio integer/fractional scaling helper.
#
# The helper lives in src/ngx_http_zstd_ratio.h, THE authoritative copy,
# and the fixture includes that header directly (the frame-probe fixture's
# shape): there is no extracted or hand-copied duplicate here to drift from
# production. No nginx tree and no libzstd needed: pure C, self-contained.
set -euo pipefail

# ci/tools/ -> ci/ -> repo root.
cd "$(dirname "$0")/../.."

HDR="src/ngx_http_zstd_ratio.h"
SRC="src/ngx_http_zstd_filter_module.c"
CC="${CC:-cc}"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/zstd-ratio-scaling-unit.XXXXXX")"
trap 'rm -rf "$OUT"' EXIT

for marker in 'ngx_http_zstd_ratio_parts(uint64_t bytes_in' \
	'remainder <= UINT64_MAX / 10' 'ratio_int' 'ratio_frac'; do
	if ! grep -q "$marker" "$HDR"; then
		echo "FAIL: $HDR lacks marker: $marker" >&2
		exit 1
	fi
done

# Production must route through the header's helper: a reintroduced inline
# `* 1000 /` in the variable would leave this fixture green while
# $zstd_ratio overflowed again.
if ! grep -Fq '#include "ngx_http_zstd_ratio.h"' "$SRC"; then
	echo "FAIL: $SRC no longer includes $HDR" >&2
	exit 1
fi
if ! grep -q 'ngx_http_zstd_ratio_parts(ctx->bytes_in, ctx->bytes_out' "$SRC"; then
	echo "FAIL: \$zstd_ratio no longer calls ngx_http_zstd_ratio_parts()" >&2
	exit 1
fi
if grep -q 'bytes_in \* 1000 / ctx->bytes_out' "$SRC"; then
	echo "FAIL: \$zstd_ratio computes the ratio inline again" >&2
	exit 1
fi

"$CC" -std=gnu99 -Wall -Wextra -Werror -O2 -I ci/tools \
	-o "$OUT/ratio_scaling_unit" ci/tools/test_ratio_scaling_unit.c
"$OUT/ratio_scaling_unit"

# The header itself must stay C89-clean for the portable build (the
# frame-probe header's same control); the fixture's own 128-bit oracle and
# ULL literals are gnu99 and stay out of this pass.
printf '#include <stdint.h>\ntypedef uintptr_t ngx_uint_t;\n#include "../../src/ngx_http_zstd_ratio.h"\nint main(void) { ngx_uint_t a, b; ngx_http_zstd_ratio_parts(3, 2, &a, &b); return a == 1 && b == 500 ? 0 : 1; }\n' \
	>"$OUT/c89.c"
"$CC" -std=c89 -pedantic-errors -Wall -Wextra -Werror -O1 \
	-Dngx_inline=__inline -I ci/tools -o "$OUT/ratio_c89" "$OUT/c89.c"
"$OUT/ratio_c89"

echo "OK: ratio scaling unit fixture (against $HDR)"
