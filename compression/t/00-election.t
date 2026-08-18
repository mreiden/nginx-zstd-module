use Test::Nginx::Socket;

# Phase-0 election matrix as a regression suite: the shell matrix from
# the PR validation, graduated. Needs a binary built with
# --add-module=<repo>/compression AND the core gzip module (the defer
# cases exercise the real handoff; the gzip-less build shape has its
# own compile-time coverage in CI-to-be).

no_long_string();
log_level 'warn';
repeat_each(1);
plan 'no_plan';
run_tests();

__DATA__


=== TEST 1: default order elects zstd when everything is acceptable
--- config
    location /t {
        compression on;
        compression_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "election fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd, br, gzip
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 2: zstd unacceptable, brotli next in the default order
--- config
    location /t {
        compression on;
        compression_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "election fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br, gzip
--- response_headers
Content-Encoding: br
--- no_error_log
[error]



=== TEST 3: gzip-only client -> DEFER, the core gzip filter compresses
# The Content-Encoding here is produced by core gzip, not this module:
# the election stands aside without touching the r->gzip_tested latch,
# and gzip's entire rule set (gzip_types included) applies downstream.
--- config
    location /t {
        compression on;
        compression_min_length 1;
        gzip on;
        gzip_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "election fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: gzip
--- response_headers
Content-Encoding: gzip
--- no_error_log
[error]



=== TEST 4: q=0 excludes a coding the order would otherwise elect
--- config
    location /t {
        compression on;
        compression_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "election fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd;q=0, br
--- response_headers
Content-Encoding: br
--- no_error_log
[error]



=== TEST 5: explicit order is honored over the default
--- config
    location /t {
        compression on;
        compression_order br zstd gzip;
        compression_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "election fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd, br
--- response_headers
Content-Encoding: br
--- no_error_log
[error]



=== TEST 6: gzip FIRST in an explicit order wins by deferral
--- config
    location /t {
        compression on;
        compression_order gzip zstd br;
        compression_min_length 1;
        gzip on;
        gzip_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "election fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: gzip, zstd, br
--- response_headers
Content-Encoding: gzip
--- no_error_log
[error]



=== TEST 7: gzip-first order falls through when the client never offers gzip
--- config
    location /t {
        compression on;
        compression_order gzip zstd br;
        compression_min_length 1;
        gzip on;
        gzip_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "election fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd, br
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 8: gzip absent from an explicit list is VETOED despite gzip on
# The concluded election latches r->gzip_tested, so a gzip-only client
# gets identity even though the core gzip filter would happily serve it.
--- config
    location /t {
        compression on;
        compression_order zstd br;
        compression_min_length 1;
        gzip on;
        gzip_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "election fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: gzip
--- raw_response_headers_unlike: Content-Encoding
--- response_body
election fixture body, long enough to compress meaningfully
--- no_error_log
[error]



=== TEST 9: compression off is the migration floor — core gzip untouched
--- config
    location /t {
        compression off;
        gzip on;
        gzip_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "election fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: gzip, zstd, br
--- response_headers
Content-Encoding: gzip
--- no_error_log
[error]



=== TEST 10: no Accept-Encoding -> identity, Vary still emitted
--- config
    location /t {
        compression on;
        compression_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "election fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- raw_response_headers_like: Vary: Accept-Encoding
--- raw_response_headers_unlike: Content-Encoding
--- response_body
election fixture body, long enough to compress meaningfully
--- no_error_log
[error]



=== TEST 11: "*" wildcard elects the first base coding in the order
--- config
    location /t {
        compression on;
        compression_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "election fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: *
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 12: compression_min_length gates small responses to identity
--- config
    location /t {
        compression on;
        compression_min_length 4096;
        default_type text/html;
        gzip_vary on;
        return 200 "small body\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd, br
--- raw_response_headers_unlike: Content-Encoding
--- response_body
small body
--- no_error_log
[error]



=== TEST 13: compression_types gates non-matching content types
# application/json is not in a text/css list, so the response stays
# identity. (text/html deliberately NOT used as the blocked type here —
# see TEST 13b.)
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/css;
        default_type application/json;
        gzip_vary on;
        return 200 "election fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd, br
--- raw_response_headers_unlike: Content-Encoding
--- no_error_log
[error]



=== TEST 13b: text/html always passes the types gate (inherited quirk, pinned)
# ngx_http_types_slot force-seeds text/html into every types list —
# the documented gzip_types behavior ("responses with the text/html
# type are always compressed"), impossible to exclude. This module
# uses the standard slot ON PURPOSE, for semantic consistency with
# gzip_types/zstd_types/brotli_types; this block pins the inheritance
# so a future "fix" that breaks consistency announces itself. Found
# while writing TEST 13, which first used text/html as the blocked
# type and discovered it cannot be.
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/css;
        default_type text/html;
        gzip_vary on;
        return 200 "election fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd, br
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 14: unknown coding in compression_order is a config error
--- config
    location /t {
        compression_order zstd lzma;
        return 200 "x";
    }
--- must_die
--- error_log
unknown coding "lzma"
--- no_error_log
[alert]



=== TEST 15: duplicate coding in compression_order is a config error
# the order list IS the enable set; a coding may appear once
--- config
    location /t {
        compression_order zstd br zstd;
        return 200 "x";
    }
--- must_die
--- error_log
duplicate coding "zstd"
--- no_error_log
[alert]



=== TEST 16: compression on without gzip_vary warns at config load
# Flag-delegated Vary is gated on a directive whose default is off
# (review round 1 of the prototype); the observable clcf->gzip_vary
# makes this warnable where the abandoned gzip-off warning was not.
--- config
    location /t {
        compression on;
        compression_min_length 1;
        default_type text/html;
        return 200 "election fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- error_log
compression is enabled but "gzip_vary" is off
--- no_error_log
[error]



=== TEST 17: compression on WITH gzip_vary does not warn
--- config
    location /t {
        compression on;
        compression_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "election fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- no_error_log eval
[qr/"gzip_vary" is off/, qr/\[error\]/]



=== TEST 18: a body exactly at the default min_length compresses
# the gate is `< min_length` (default 20): equality passes
--- config
    location /t {
        compression on;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "12345678901234567890";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 19: one byte under the default min_length stays identity
--- config
    location /t {
        compression on;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "1234567890123456789";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- raw_response_headers_unlike: Content-Encoding
--- response_body chomp
1234567890123456789
--- no_error_log
[error]
