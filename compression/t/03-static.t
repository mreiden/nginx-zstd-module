use Test::Nginx::Socket;
use File::Temp qw(tempdir);

# Phase-2 static sidecar serving. Fixtures are REAL compressed files
# built in this prelude via the reference CLIs (zstd, brotli, gzip must
# be on PATH — the same tools the wire matrix uses), so every serve
# assertion compares against the exact bytes on disk.

our $src = "static fixture body: the compressible original content\n" x 30;

my $dir = tempdir(CLEANUP => 1);
my $f = "$dir/fixture";
open my $fh, '>', $f or die $!;
binmode $fh; print $fh $src; close $fh;

sub slurp { open my $h, '<', $_[0] or die "$_[0]: $!"; binmode $h; local $/; <$h> }

system("zstd -q -f -o $f.zst $f") == 0        or die "zstd fixture";
system("brotli -f -o $f.br $f") == 0          or die "brotli fixture";
system("gzip -c $f > $f.gz") == 0             or die "gzip fixture";
# oversized declared window: stdin = unpledged input size, so the level
# default window (128 MB at --long=27) is stamped into the header — the
# vite/Node production incident in fixture form
system("zstd -q -19 --long=27 < $f > $f.bigwin.zst") == 0 or die "bigwin";

our $zst    = slurp("$f.zst");
our $br     = slurp("$f.br");
our $gz     = slurp("$f.gz");
our $bigwin = slurp("$f.bigwin.zst");

no_long_string();
log_level 'warn';
repeat_each(1);
plan 'no_plan';
run_tests();

__DATA__


=== TEST 1: on + AE br -> serves the .br sidecar byte-exact
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.br" => $::br ] ]
--- config
    location /st/ {
        compression_static on;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: br
--- response_headers
Content-Encoding: br
--- response_body eval
$::br
--- raw_response_headers_like: Vary: Accept-Encoding
--- no_error_log
[error]



=== TEST 2: default order prefers br when both sidecars exist
--- user_files eval
[ [ "st/hello.js" => $::src ],
  [ "st/hello.js.br" => $::br ],
  [ "st/hello.js.zst" => $::zst ] ]
--- config
    location /st/ {
        compression_static on;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: zstd, br
--- response_headers
Content-Encoding: br
--- response_body eval
$::br
--- no_error_log
[error]



=== TEST 3: explicit order flips the preference
--- user_files eval
[ [ "st/hello.js" => $::src ],
  [ "st/hello.js.br" => $::br ],
  [ "st/hello.js.zst" => $::zst ] ]
--- config
    location /st/ {
        compression_static on;
        compression_static_order zstd br gzip;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: zstd, br
--- response_headers
Content-Encoding: zstd
--- response_body eval
$::zst
--- no_error_log
[error]



=== TEST 4: gzip sidecars are FIRST-CLASS — served with zero zlib involvement
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.gz" => $::gz ] ]
--- config
    location /st/ {
        compression_static on;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: gzip
--- response_headers
Content-Encoding: gzip
--- response_body eval
$::gz
--- no_error_log
[error]



=== TEST 5: the client's acceptance gates each coding in on mode
# .br exists but the client only accepts zstd, whose sidecar does not
# exist -> identity original
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.br" => $::br ] ]
--- config
    location /st/ {
        compression_static on;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: zstd
--- raw_response_headers_unlike: Content-Encoding
--- response_body eval
$::src
--- no_error_log
[error]



=== TEST 6: no Accept-Encoding in on mode -> identity, Vary still emitted
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.br" => $::br ] ]
--- config
    location /st/ {
        compression_static on;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- raw_response_headers_like: Vary: Accept-Encoding
--- raw_response_headers_unlike: Content-Encoding
--- response_body eval
$::src
--- no_error_log
[error]



=== TEST 7: always serves the first EXISTING sidecar with no negotiation
# no Accept-Encoding at all; only .zst exists (order default br zstd
# gzip -> br probe misses, zstd probe hits)
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.zst" => $::zst ] ]
--- config
    location /st/ {
        compression_static always;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- response_headers
Content-Encoding: zstd
--- response_body eval
$::zst
--- raw_response_headers_unlike: Vary
--- no_error_log
[error]



=== TEST 8: the window cap declines an oversized .zst to the NEXT coding
# bigwin.zst declares a 128 MB window (browsers reject it before
# decoding); the unified probe loop lands on the .gz sidecar instead of
# identity — decline-and-log finding a BETTER answer, which the
# split-module world could not do
--- user_files eval
[ [ "st/hello.js" => $::src ],
  [ "st/hello.js.zst" => $::bigwin ],
  [ "st/hello.js.gz" => $::gz ] ]
--- config
    location /st/ {
        compression_static on;
        compression_static_order zstd gzip;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: zstd, gzip
--- response_headers
Content-Encoding: gzip
--- response_body eval
$::gz
--- error_log
declares a 134217728-byte decompression window
--- no_error_log
[alert]



=== TEST 9: a mistakenly-renamed non-zstd file is declined, not served
--- user_files eval
[ [ "st/hello.js" => $::src ],
  [ "st/hello.js.zst" => "this is not a zstd frame at all" ] ]
--- config
    location /st/ {
        compression_static on;
        compression_static_order zstd;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: zstd
--- raw_response_headers_unlike: Content-Encoding
--- response_body eval
$::src
--- error_log
is not a zstd frame
--- no_error_log
[alert]



=== TEST 10: static miss falls through to the dynamic filter
# no sidecars exist; compression (the filter) is on -> the response is
# dynamically compressed. The handler declined without touching any
# latch — the cooperation the unified design promises.
--- user_files eval
[ [ "st/hello.js" => $::src ] ]
--- config
    location /st/ {
        compression_static on;
        compression on;
        compression_min_length 1;
        compression_types application/javascript text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 11: unknown coding in compression_static_order is a config error
--- config
    location /st/ {
        compression_static_order zstd lzma;
        root html;
    }
--- must_die
--- error_log
unknown coding "lzma"
--- no_error_log
[alert]



=== TEST 12: duplicate coding in compression_static_order is a config error
--- config
    location /st/ {
        compression_static_order br zstd br;
        root html;
    }
--- must_die
--- error_log
duplicate coding "br"
--- no_error_log
[alert]



=== TEST 13: compression_static off is inert
--- user_files eval
[ [ "st/hello.js" => $::src ], [ "st/hello.js.br" => $::br ] ]
--- config
    location /st/ {
        gzip_vary on;
        root html;
    }
--- request
GET /st/hello.js
--- more_headers
Accept-Encoding: br
--- raw_response_headers_unlike: Content-Encoding
--- response_body eval
$::src
--- no_error_log
[error]
