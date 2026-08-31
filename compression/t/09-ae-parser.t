use Test::Nginx::Socket;

# The Accept-Encoding parser's adversarial matrix, ported from the
# parent's suite (its blocks 46, 55-57, 61-64, 78-89) during the
# test-bank audit. Our ngx_http_compression_ae.h is a COPY of the
# parent's parser lineage: the parent's fuzzing covered the parent's
# bytes, so this copy earns its own pins. Every block is the same
# skeleton with one hostile header; the verdict (elects vs identity)
# is the RFC 9110 reading the parent settled.

our $body = "ae parser fixture body long enough to compress here\n";

no_long_string();
log_level 'warn';
repeat_each(1);
plan 'no_plan';
run_tests();

__DATA__


=== TEST 1: tab OWS around the q-value is accepted
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "ae parser fixture body long enough to compress here\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd;\tq=0.5"
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]


=== TEST 2: the coding name is case-insensitive
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "ae parser fixture body long enough to compress here\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: ZsTd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]


=== TEST 3: stray empty list elements are ignored
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "ae parser fixture body long enough to compress here\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: gzip,,zstd, ,
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]


=== TEST 4: a qvalue with trailing junk (q=1x) makes the element non-matching
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "ae parser fixture body long enough to compress here\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd;q=1x
--- raw_response_headers_unlike: Content-Encoding
--- error_code: 200
--- response_body
ae parser fixture body long enough to compress here
--- no_error_log
[error]


=== TEST 5: a fourth decimal digit (q=0.0001) is malformed
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "ae parser fixture body long enough to compress here\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd;q=0.0001
--- raw_response_headers_unlike: Content-Encoding
--- error_code: 200
--- response_body
ae parser fixture body long enough to compress here
--- no_error_log
[error]


=== TEST 6: qvalue followed by whitespace then junk is malformed
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "ae parser fixture body long enough to compress here\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd;q=1 x
--- raw_response_headers_unlike: Content-Encoding
--- error_code: 200
--- response_body
ae parser fixture body long enough to compress here
--- no_error_log
[error]


=== TEST 7: qvalue followed by a tab then junk is malformed
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "ae parser fixture body long enough to compress here\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd;q=1\tx"
--- raw_response_headers_unlike: Content-Encoding
--- error_code: 200
--- response_body
ae parser fixture body long enough to compress here
--- no_error_log
[error]


=== TEST 8: a repeated q parameter is malformed (at most one)
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "ae parser fixture body long enough to compress here\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd;q=1;q=0
--- raw_response_headers_unlike: Content-Encoding
--- error_code: 200
--- response_body
ae parser fixture body long enough to compress here
--- no_error_log
[error]


=== TEST 9: "q" without "=value" is malformed
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "ae parser fixture body long enough to compress here\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd;q
--- raw_response_headers_unlike: Content-Encoding
--- error_code: 200
--- response_body
ae parser fixture body long enough to compress here
--- no_error_log
[error]


=== TEST 10: a qvalue leading digit other than 0 or 1 is malformed
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "ae parser fixture body long enough to compress here\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd;q=2
--- raw_response_headers_unlike: Content-Encoding
--- error_code: 200
--- response_body
ae parser fixture body long enough to compress here
--- no_error_log
[error]


=== TEST 11: an escaped quoted-pair does not confuse the delimiter scan
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "ae parser fixture body long enough to compress here\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: gzip;foo="a\",zstd\"b", zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]


=== TEST 12: an unterminated quoted-string runs to end without OOB, q=1
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "ae parser fixture body long enough to compress here\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd;foo="unterminated
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]


=== TEST 13: OWS around the "=" of a q parameter is accepted (BWS)
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "ae parser fixture body long enough to compress here\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd;q = 0.5
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]


=== TEST 14: "q=" with the value missing at end-of-field is rejected
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "ae parser fixture body long enough to compress here\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd;q=
--- raw_response_headers_unlike: Content-Encoding
--- error_code: 200
--- response_body
ae parser fixture body long enough to compress here
--- no_error_log
[error]


=== TEST 15: an unquoted non-q parameter value is skipped to the delimiter
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "ae parser fixture body long enough to compress here\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd;foo=bar
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]


=== TEST 16: a quoted-string starting mid-value is skipped, parsing continues
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "ae parser fixture body long enough to compress here\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: gzip;foo=ba"r,baz", zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]


=== TEST 17: a similar-prefix coding does not match ("notzstd, zstd")
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "ae parser fixture body long enough to compress here\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: notzstd, zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]


=== TEST 18: explicit zstd;q=0 beats a permissive wildcard — br elected
# the wildcard covers unlisted codings; it must not resurrect an
# explicitly refused one. In the multi-coding election the next base
# coding wins through the wildcard.
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "ae parser fixture body long enough to compress here\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: *;q=0.5, zstd;q=0
--- response_headers
Content-Encoding: br
--- no_error_log
[error]

=== TEST 19: junk after the coding name (zstd x) advertises nothing
# RFC 9110 12.5.3 makes `codings` a token: only ';', ',' or end may
# follow the name. Core gzip's parser applies the same rule, so
# accepting this diverged from the sibling filter (parent #142).
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "ae parser fixture body long enough to compress here\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd x
--- raw_response_headers_unlike: Content-Encoding
--- error_code: 200
--- response_body
ae parser fixture body long enough to compress here
--- no_error_log
[error]


=== TEST 20: a quote glued to the coding name (zstd"x) advertises nothing
# The name scan stops on '"' as well as OWS, so the boundary check has
# to look at what follows the OWS skip, not the stopping byte alone.
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "ae parser fixture body long enough to compress here\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd"x
--- raw_response_headers_unlike: Content-Encoding
--- error_code: 200
--- response_body
ae parser fixture body long enough to compress here
--- no_error_log
[error]


=== TEST 21: an empty parameter (zstd;;q=1) is malformed
# RFC 9110 has no empty-parameter production; the element must not
# silently resolve to q=1 (parent #142).
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "ae parser fixture body long enough to compress here\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd;;q=1
--- raw_response_headers_unlike: Content-Encoding
--- error_code: 200
--- response_body
ae parser fixture body long enough to compress here
--- no_error_log
[error]


=== TEST 22: a malformed gzip element must not hijack the defer decision
# The divergence this drift caused: core gzip refuses "gzip x", so
# deferring on it hands the request to a filter that declines, and a
# client that validly offered zstd got identity. The malformed element
# advertises nothing; election falls through to zstd.
--- config
    location /t {
        compression on;
        compression_order gzip zstd;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "ae parser fixture body long enough to compress here\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: gzip x, zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]

=== TEST 23: a skipped foreign parameter still honours its element's q=0
# The other half of TEST 15, pinned upstream as the deliberate
# divergence from core (parent #201/m5): skipping "foo=bar" instead of
# rejecting the element preserves the trailing q the client actually
# sent. Core gzip drops the whole element and never sees the q.
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        return 200 "ae parser fixture body long enough to compress here\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd;foo=bar;q=0
--- raw_response_headers_unlike: Content-Encoding
--- error_code: 200
--- response_body
ae parser fixture body long enough to compress here
--- no_error_log
[error]


=== TEST 24: an origin Vary listing Accept-Encoding among tokens is not doubled
# parent #200 row n11: the dedup scan must tokenize the existing Vary
# value on commas — an exact-value compare misses "Accept-Encoding,
# Cookie" and pushes a second Vary: Accept-Encoding line. gzip_vary
# stays off so the module's own push path (the one with the scan) runs.
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        add_header Vary "Accept-Encoding, Cookie";
        return 200 "ae parser fixture body long enough to compress here\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
Vary: Accept-Encoding, Cookie
--- raw_response_headers_unlike eval
qr/Vary: Accept-Encoding\r/
--- no_error_log
[error]
