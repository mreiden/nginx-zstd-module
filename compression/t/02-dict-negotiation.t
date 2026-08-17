use Test::Nginx::Socket;
use Digest::SHA qw(sha256 sha256_hex);
use MIME::Base64 qw(encode_base64);

# Phase-1b negotiation and wire format. Everything derives from the
# dictionary constant below: its hash, the Available-Dictionary value,
# and the prologue regexes — nothing on the wire is hardcoded.
#
# The Content-Encoding assertion on EVERY block is load-bearing, not
# decoration: this suite's negative paths degrade gracefully to the
# base coding, and WRINKLES 16's base64 bug (every valid header
# rejected, all elections silently degraded) was invisible until the
# expected CE was pinned per case. Byte-exact decode roundtrips and
# the checksum-flag witness live in the shell tool, which drives the
# reference CLIs.

our $dict    = "const shared = 'negotiation fixture material';\n" x 40;
our $hex     = sha256_hex($dict);
our $raw     = sha256($dict);
our $b64     = encode_base64($raw, "");
our $bad_b64 = encode_base64("\x00" x 32, "");

# dcz: 40-byte skippable frame (magic 0x184D2A5E LE, size 0x20 LE,
# SHA-256), then the zstd magic of the checksummed stream
our $dcz_re = qr/^\x5E\x2A\x4D\x18\x20\x00\x00\x00\Q$raw\E\x28\xB5\x2F\xFD/s;

# dcb: 36 raw bytes (0xFF "DCB", SHA-256) the decoder never sees
our $dcb_re = qr/^\xFF\x44\x43\x42\Q$raw\E/s;

no_long_string();
log_level 'warn';
repeat_each(1);
plan 'no_plan';
run_tests();

__DATA__


=== TEST 1: dcz elects on explicit token + matching Available-Dictionary
--- user_files eval
[ [ "app.dict" => $::dict ] ]
--- http_config
    compression_dict_file html/app.dict;
--- config
    location /t {
        compression on;
        compression_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "negotiation fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers eval
qq{Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::b64:}
--- response_headers
Content-Encoding: dcz
--- response_body_like eval
$::dcz_re
--- raw_response_headers_like: Vary: Available-Dictionary
--- no_error_log
[error]



=== TEST 2: dcb elects likewise, with its 36-byte raw prologue
--- user_files eval
[ [ "app.dict" => $::dict ] ]
--- http_config
    compression_dict_file html/app.dict;
--- config
    location /t {
        compression on;
        compression_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "negotiation fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers eval
qq{Accept-Encoding: br, dcb\nAvailable-Dictionary: :$::b64:}
--- response_headers
Content-Encoding: dcb
--- response_body_like eval
$::dcb_re
--- no_error_log
[error]



=== TEST 3: no Available-Dictionary -> base coding, Vary still hoisted
--- user_files eval
[ [ "app.dict" => $::dict ] ]
--- http_config
    compression_dict_file html/app.dict;
--- config
    location /t {
        compression on;
        compression_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "negotiation fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd, dcz
--- response_headers
Content-Encoding: zstd
--- raw_response_headers_like: Vary: Available-Dictionary
--- no_error_log
[error]



=== TEST 4: an unknown hash degrades to the base coding
--- user_files eval
[ [ "app.dict" => $::dict ] ]
--- http_config
    compression_dict_file html/app.dict;
--- config
    location /t {
        compression on;
        compression_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "negotiation fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers eval
qq{Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::bad_b64:}
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 5: a malformed byte sequence (no colons) degrades gracefully
--- user_files eval
[ [ "app.dict" => $::dict ] ]
--- http_config
    compression_dict_file html/app.dict;
--- config
    location /t {
        compression on;
        compression_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "negotiation fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers eval
qq{Accept-Encoding: zstd, dcz\nAvailable-Dictionary: $::b64}
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 6: a wrong-length base64 value degrades gracefully
# WRINKLES 16 territory: the length rules are strict — encoded length
# must be exactly 44; anything else negotiates nothing
--- user_files eval
[ [ "app.dict" => $::dict ] ]
--- http_config
    compression_dict_file html/app.dict;
--- config
    location /t {
        compression on;
        compression_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "negotiation fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers eval
qq{Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :SGVsbG8=:}
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 7: "*" must never elect a dictionary coding
# only a client that actually holds the dictionary can decode dcz/dcb;
# a blanket wildcard is not that statement
--- user_files eval
[ [ "app.dict" => $::dict ] ]
--- http_config
    compression_dict_file html/app.dict;
--- config
    location /t {
        compression on;
        compression_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "negotiation fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers eval
qq{Accept-Encoding: *\nAvailable-Dictionary: :$::b64:}
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 8: dcz accepted WITHOUT zstd still gets dcz
--- user_files eval
[ [ "app.dict" => $::dict ] ]
--- http_config
    compression_dict_file html/app.dict;
--- config
    location /t {
        compression on;
        compression_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "negotiation fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers eval
qq{Accept-Encoding: dcz\nAvailable-Dictionary: :$::b64:}
--- response_headers
Content-Encoding: dcz
--- response_body_like eval
$::dcz_re
--- no_error_log
[error]



=== TEST 9: identity clients still vary on Available-Dictionary
--- user_files eval
[ [ "app.dict" => $::dict ] ]
--- http_config
    compression_dict_file html/app.dict;
--- config
    location /t {
        compression on;
        compression_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "negotiation fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- raw_response_headers_like: Vary: Available-Dictionary
--- raw_response_headers_unlike: Content-Encoding
--- response_body
negotiation fixture body, long enough to compress meaningfully
--- no_error_log
[error]



=== TEST 10: a location with no dictionaries does not vary on it
--- config
    location /t {
        compression on;
        compression_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "negotiation fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- raw_response_headers_unlike: Available-Dictionary
--- no_error_log
[error]



=== TEST 11: a location's own dict list replaces the inherited one wholesale
# http declares A; the location declares only B. A client holding A
# gets the BASE coding in that location — A is not active there. The
# RFC's alias-merge rule, witnessed end to end.
--- user_files eval
[ [ "a.dict" => $::dict ], [ "b.dict" => ("other material entirely\n" x 40) ] ]
--- http_config
    compression_dict_file html/a.dict;
--- config
    location /t {
        compression_dict_file html/b.dict;
        compression on;
        compression_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "negotiation fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers eval
qq{Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::b64:}
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 12: an inherited dict list negotiates in a child location
# the complement of TEST 11: the location declares nothing and inherits
# http's list — the same client now gets dcz
--- user_files eval
[ [ "a.dict" => $::dict ] ]
--- http_config
    compression_dict_file html/a.dict;
--- config
    location /t {
        compression on;
        compression_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "negotiation fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers eval
qq{Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::b64:}
--- response_headers
Content-Encoding: dcz
--- response_body_like eval
$::dcz_re
--- no_error_log
[error]
