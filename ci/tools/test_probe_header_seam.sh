#!/bin/sh
set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)

# Production must consume the authoritative header, not a copy.
grep -Fq '#include "ngx_http_zstd_frame_probe.h"' \
    "$root/src/ngx_http_zstd_static_module.c"

check_definition() {
    expected=$1
    fn=$2
    shift 2

    defs=$(grep -r -n -h "^$fn(" "$@" || true)
    sites=$(grep -r -l "^$fn(" "$@" | sort || true)
    count=$(printf '%s\n' "$defs" | grep -c . || true)

    if [ "$count" -ne 1 ] || [ "$sites" != "$expected" ]; then
        echo "probe seam: unexpected definition sites for $fn:" >&2
        echo "$sites" >&2
        echo "probe seam: expected 1 definition, found $count" >&2
        return 1
    fi
}

# Each probe function is defined exactly once in the tree. A second
# column-0 definition anywhere in the module sources is the
# synchronized-copy drift #270 removed coming back -- possible while
# the unit tests keep exercising only the header.
for fn in ngx_http_zstd_static_probe_frame ngx_http_zstd_static_probe_reuse
do
    check_definition "$root/src/ngx_http_zstd_frame_probe.h" "$fn" \
        "$root/src" "$root/filter" "$root/static"
done

# Detection control: the definition pattern must actually catch a
# planted duplicate, or the checks above pass vacuously.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cp "$root/src/ngx_http_zstd_frame_probe.h" "$tmp/planted.h"
printf '\nngx_http_zstd_static_probe_frame(const u_char *hdr, size_t n)\n' \
    >> "$tmp/planted.h"
if check_definition "$tmp/planted.h" ngx_http_zstd_static_probe_frame \
        "$tmp/planted.h" >/dev/null 2>&1; then
    echo 'probe seam: detection control failed to match a duplicate' >&2
    exit 1
fi

echo 'probe header seam: PASS'
