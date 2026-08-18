use Test::Nginx::Socket;

# Phase-3 bypass predicates: compression_bypass (any predicate variable
# resolving non-empty and not "0" serves identity, stock
# ngx_http_test_predicates semantics) and compression_bypass_vary (the
# operator-named extra Vary field, emitted on BOTH the bypassed and the
# compressed response). The unified-module delta is pinned hard here:
# bypass VETOES the gzip token too, because in this module gzip is part
# of the stack -- the parents' standalone bypass falls through to core
# gzip, and TEST 6's positive control shows exactly that path working
# when bypass does NOT fire.

our $body = "bypass fixture body: compressible repeated text line\n" x 20;

no_long_string();
log_level 'warn';
repeat_each(1);
plan 'no_plan';
run_tests();

__DATA__


=== TEST 1: a truthy predicate serves identity
--- user_files eval
[ [ "b/a.txt" => $::body ] ]
--- config
    location /b/ {
        compression on;
        compression_bypass $arg_nocomp;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /b/a.txt?nocomp=1
--- more_headers
Accept-Encoding: zstd
--- raw_response_headers_unlike: Content-Encoding
--- response_body eval
$::body
--- no_error_log
[error]


=== TEST 2: no predicate match compresses as usual
--- user_files eval
[ [ "b/a.txt" => $::body ] ]
--- config
    location /b/ {
        compression on;
        compression_bypass $arg_nocomp;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /b/a.txt
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]


=== TEST 3: "0" is falsy (stock predicate semantics)
--- user_files eval
[ [ "b/a.txt" => $::body ] ]
--- config
    location /b/ {
        compression on;
        compression_bypass $arg_nocomp;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /b/a.txt?nocomp=0
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]


=== TEST 4: several predicates -- any truthy one bypasses
--- user_files eval
[ [ "b/a.txt" => $::body ] ]
--- config
    location /b/ {
        compression on;
        compression_bypass $arg_a $arg_b;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /b/a.txt?b=yes
--- more_headers
Accept-Encoding: zstd
--- raw_response_headers_unlike: Content-Encoding
--- response_body eval
$::body
--- no_error_log
[error]


=== TEST 5: compression_bypass_vary rides BOTH paths
# bypassed request: Vary names the driving header, no Content-Encoding
--- user_files eval
[ [ "b/a.txt" => $::body ] ]
--- config
    location /b/ {
        compression on;
        compression_bypass $http_x_no_compression;
        compression_bypass_vary X-No-Compression;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /b/a.txt
--- more_headers
Accept-Encoding: zstd
X-No-Compression: 1
--- raw_response_headers_unlike: Content-Encoding
--- response_headers
Vary: X-No-Compression
--- response_body eval
$::body
--- no_error_log
[error]


=== TEST 5b: ...and on the compressed response too
# two Vary lines on the wire (delegated Accept-Encoding + the literal
# bypass field); the harness folds same-name headers with ", ", so the
# folded expectation asserts BOTH are present
--- user_files eval
[ [ "b/a.txt" => $::body ] ]
--- config
    location /b/ {
        compression on;
        compression_bypass $http_x_no_compression;
        compression_bypass_vary X-No-Compression;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /b/a.txt
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
Vary: Accept-Encoding, X-No-Compression
--- no_error_log
[error]


=== TEST 6: bypass vetoes the gzip token (the unified-module delta)
# gzip is ON and the client accepts gzip; without the veto the
# parents' behavior applies -- bypass falls through and core gzip
# compresses anyway (TEST 6b shows that path live when bypass does
# not fire). With the veto the response is identity, which is what
# "do not compress this endpoint" has to mean when gzip is part of
# the stack.
--- user_files eval
[ [ "b/a.txt" => $::body ] ]
--- config
    location /b/ {
        compression on;
        compression_order zstd gzip;
        compression_bypass $arg_nocomp;
        compression_min_length 1;
        compression_types text/plain;
        gzip on;
        gzip_min_length 1;
        gzip_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /b/a.txt?nocomp=1
--- more_headers
Accept-Encoding: gzip
--- raw_response_headers_unlike: Content-Encoding
--- response_body eval
$::body
--- no_error_log
[error]


=== TEST 6b: positive control -- no bypass, gzip deferral compresses
--- user_files eval
[ [ "b/a.txt" => $::body ] ]
--- config
    location /b/ {
        compression on;
        compression_order zstd gzip;
        compression_bypass $arg_nocomp;
        compression_min_length 1;
        compression_types text/plain;
        gzip on;
        gzip_min_length 1;
        gzip_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /b/a.txt
--- more_headers
Accept-Encoding: gzip
--- response_headers
Content-Encoding: gzip
--- no_error_log
[error]


=== TEST 7: bypass_vary without a predicate warns at config load
--- user_files eval
[ [ "b/a.txt" => $::body ] ]
--- config
    location /b/ {
        compression on;
        compression_bypass_vary X-No-Compression;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /b/a.txt
--- error_log
"compression_bypass_vary" is set without a "compression_bypass" predicate
