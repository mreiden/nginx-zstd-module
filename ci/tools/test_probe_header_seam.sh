#!/bin/sh
set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)

# Production must consume the authoritative header, not a copy.
grep -Fq '#include "ngx_http_zstd_frame_probe.h"' \
    "$root/src/ngx_http_zstd_static_module.c"

# Each probe function is defined exactly once in the tree. A second
# column-0 definition anywhere in the module sources is the
# synchronized-copy drift #270 removed coming back -- possible while
# the unit tests keep exercising only the header.
for fn in ngx_http_zstd_static_probe_frame ngx_http_zstd_static_probe_reuse
do
    defs=$(grep -r -l "^$fn(" \
               "$root/src" "$root/filter" "$root/static" | sort)
    if [ "$defs" != "$root/src/ngx_http_zstd_frame_probe.h" ]; then
        echo "probe seam: unexpected definition sites for $fn:" >&2
        echo "$defs" >&2
        exit 1
    fi
done

# Detection control: the definition pattern must actually catch a
# planted duplicate, or the checks above pass vacuously.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
printf 'static ngx_inline ngx_int_t\nngx_http_zstd_static_probe_frame(const u_char *hdr, size_t n)\n{\n}\n' \
    > "$tmp/planted.c"
if ! grep -q "^ngx_http_zstd_static_probe_frame(" "$tmp/planted.c"; then
    echo 'probe seam: detection control failed to match a duplicate' >&2
    exit 1
fi

echo 'probe header seam: PASS'
