use Test::Nginx::Socket;
use Digest::SHA qw(sha256 sha256_hex);
use MIME::Base64 qw(encode_base64);
use File::Temp qw(tempdir);

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

# a body + its .br sidecar for the static-vs-dictionary interplay
# blocks (the brotli CLI is already a suite dependency elsewhere)
our $src_js = "sidecar interplay body: " . ("shared material line\n" x 30);
our $br_sidecar;
{
    my $tdir = tempdir(CLEANUP => 1);
    open my $fh, '>', "$tdir/f" or die $!;
    binmode $fh; print $fh $src_js; close $fh;
    system("brotli -f -o $tdir/f.br $tdir/f") == 0 or die "brotli fixture";
    open my $bh, '<', "$tdir/f.br" or die $!;
    binmode $bh; local $/; $br_sidecar = <$bh>; close $bh;
}

our $hex     = sha256_hex($dict);
our $raw     = sha256($dict);
our $b64     = encode_base64($raw, "");
our $bad_b64 = encode_base64("\x00" x 32, "");

# dcz: 40-byte skippable frame (magic 0x184D2A5E LE, size 0x20 LE,
# SHA-256), then the zstd magic of the checksummed stream
our $dcz_re = qr/^\x5E\x2A\x4D\x18\x20\x00\x00\x00\Q$raw\E\x28\xB5\x2F\xFD/s;

# dcb: 36 raw bytes (0xFF "DCB", SHA-256) the decoder never sees
our $dcb_re = qr/^\xFF\x44\x43\x42\Q$raw\E/s;

# RFC 9842 §8 secure-context gate (#158): a dictionary coding is only
# elected on a secure context, and Test::Nginx::Socket has no TLS client
# — every connection here is cleartext. So the negotiation blocks below,
# which model a normal HTTPS deployment, run behind an http-level
# compression_dict_assume_secure_transport (the TLS-terminating-proxy
# acknowledgement) injected here. Blocks whose name contains
# "secure-context" opt OUT of the injection: they exercise the real
# fail-closed default over a genuine cleartext connection.
add_block_preprocessor(sub {
    my $block = shift;

    return if defined($block->name) && $block->name =~ /secure-context/;

    my $hc = $block->http_config;
    $hc = defined($hc) ? $hc : '';
    $block->set_value('http_config',
                      "compression_dict_assume_secure_transport on;\n$hc");
});

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
--- raw_response_headers_like eval
qr/Vary: Accept-Encoding, Available-Dictionary, Sec-Fetch-Site/
--- raw_response_headers_unlike eval
qr/Vary: Accept-Encoding\r/
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
--- raw_response_headers_like eval
qr/Vary: Accept-Encoding, Available-Dictionary, Sec-Fetch-Site/
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



=== TEST 9: identity clients still vary — ONE combined line
# review round 2: a delegated AE line plus a literal AD line meant two
# Vary lines on the wire, and first-line-keyed caches would drop the
# dictionary axis. Dict locations now push the single combined line
# and skip delegation entirely (gzip_vary on here must NOT produce a
# second line).
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
--- raw_response_headers_like eval
qr/Vary: Accept-Encoding, Available-Dictionary, Sec-Fetch-Site/
--- raw_response_headers_unlike eval
qr/Vary: Accept-Encoding\r/
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



=== TEST 13: a 43-character byte sequence degrades gracefully
# one under the only valid encoded length (WRINKLES 16's rule is
# `== 44`); charset-valid so only the length gate rejects it
--- user_files eval
[ [ "app.dict" => $::dict ] ]
--- http_config
    compression_dict_file html/app.dict;
--- config
    location /t {
        compression on;
        compression_min_length 1;
        default_type text/html;
        return 200 "negotiation fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers eval
qq{Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :} . ("A" x 43) . qq{:}
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 14: a 45-character byte sequence degrades gracefully
--- user_files eval
[ [ "app.dict" => $::dict ] ]
--- http_config
    compression_dict_file html/app.dict;
--- config
    location /t {
        compression on;
        compression_min_length 1;
        default_type text/html;
        return 200 "negotiation fixture body, long enough to compress meaningfully\n";
    }
--- request
GET /t
--- more_headers eval
qq{Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :} . ("A" x 45) . qq{:}
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]


=== TEST 15: dict bypass — the real-browser case (sidecar present, dcz wins)
# the production soak's finding: a browser holding the dictionary
# sends browser-shaped AE + Available-Dictionary, but the static
# module serves the .br sidecar before the filter can negotiate.
# compression_static_dict_bypass stands the static handler aside for
# exactly those requests; the filter then elects dcz with the
# combined Vary line.
--- user_files eval
[ [ "f/app.js" => $::src_js ], [ "f/app.js.br" => $::br_sidecar ],
  [ "app.dict" => $::dict ] ]
--- http_config
    compression_dict_file html/app.dict;
--- config
    location /f/ {
        compression on;
        compression_static on;
        compression_static_dict_bypass on;
        compression_min_length 1;
        compression_types text/javascript;
        default_type text/javascript;
        gzip_vary on;
        root html;
    }
--- request
GET /f/app.js
--- more_headers eval
qq{Accept-Encoding: gzip, deflate, br, zstd, dcb, dcz\nAvailable-Dictionary: :$::b64:}
--- response_headers
Content-Encoding: dcz
--- response_body_like eval
$::dcz_re
--- raw_response_headers_like eval
qr/Vary: Accept-Encoding, Available-Dictionary, Sec-Fetch-Site/


=== TEST 15b: control — without the bypass, the sidecar wins
--- user_files eval
[ [ "f/app.js" => $::src_js ], [ "f/app.js.br" => $::br_sidecar ],
  [ "app.dict" => $::dict ] ]
--- http_config
    compression_dict_file html/app.dict;
--- config
    location /f/ {
        compression on;
        compression_static on;
        compression_min_length 1;
        compression_types text/javascript;
        default_type text/javascript;
        gzip_vary on;
        root html;
    }
--- request
GET /f/app.js
--- more_headers eval
qq{Accept-Encoding: gzip, deflate, br, zstd, dcb, dcz\nAvailable-Dictionary: :$::b64:}
--- response_headers
Content-Encoding: br
--- response_body eval
$::br_sidecar


=== TEST 15c: bypass + store MISS pays runtime compression (the tradeoff)
# an Available-Dictionary the store doesn't hold: static stood aside,
# negotiation missed, the filter degrades to the base coding
# dynamically — the sidecar is forfeited, by documented design
--- user_files eval
[ [ "f/app.js" => $::src_js ], [ "f/app.js.br" => $::br_sidecar ],
  [ "app.dict" => $::dict ] ]
--- http_config
    compression_dict_file html/app.dict;
--- config
    location /f/ {
        compression on;
        compression_static on;
        compression_static_dict_bypass on;
        compression_min_length 1;
        compression_types text/javascript;
        default_type text/javascript;
        gzip_vary on;
        root html;
    }
--- request
GET /f/app.js
--- more_headers eval
qq{Accept-Encoding: gzip, deflate, br, zstd, dcb, dcz\nAvailable-Dictionary: :$::bad_b64:}
--- response_headers
Content-Encoding: zstd


=== TEST 16: Sec-Fetch-Site cross-site refuses the dictionary coding
# parent parity (RFC 9842 security considerations): dictionaries are
# same-origin-partitioned secrets — a cross-site response compressed
# against one leaks it. Refusal degrades to the base coding.
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
        return 200 "sec-fetch fixture body, long enough to compress well\n";
    }
--- request
GET /t
--- more_headers eval
qq{Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::b64:\nSec-Fetch-Site: cross-site}
--- response_headers
Content-Encoding: zstd
--- raw_response_headers_like eval
qr/Vary: Accept-Encoding, Available-Dictionary, Sec-Fetch-Site/


=== TEST 16b: Sec-Fetch-Site same-origin is allowed
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
        return 200 "sec-fetch fixture body, long enough to compress well\n";
    }
--- request
GET /t
--- more_headers eval
qq{Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::b64:\nSec-Fetch-Site: same-origin}
--- response_headers
Content-Encoding: dcz


=== TEST 16c: Sec-Fetch-Site none (address-bar navigation) is allowed
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
        return 200 "sec-fetch fixture body, long enough to compress well\n";
    }
--- request
GET /t
--- more_headers eval
qq{Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::b64:\nSec-Fetch-Site: none}
--- response_headers
Content-Encoding: dcz


=== TEST 16d: same-site (subdomain) is refused — same-ORIGIN partitioning
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
        return 200 "sec-fetch fixture body, long enough to compress well\n";
    }
--- request
GET /t
--- more_headers eval
qq{Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::b64:\nSec-Fetch-Site: same-site}
--- response_headers
Content-Encoding: zstd


=== TEST 17: dcz;q=0 is an explicit refusal despite a matching dictionary
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
        return 200 "refusal fixture body, long enough to compress well\n";
    }
--- request
GET /t
--- more_headers eval
qq{Accept-Encoding: zstd, dcz;q=0\nAvailable-Dictionary: :$::b64:}
--- response_headers
Content-Encoding: zstd


=== TEST 18: optional truth-wins — a stale supplied hash re-keys the entry
# the deploy-race shape: the generated line's hash predates the file's
# current bytes. With optional, the computed truth replaces it and a
# client holding the REAL file still negotiates dcz; strict mode would
# have refused to start.
--- user_files eval
[ [ "app.dict" => $::dict ] ]
--- http_config eval
qq{compression_dict_file html/app.dict 0000000000000000000000000000000000000000000000000000000000000000 optional;\ncompression_dict_file html/app.dict;}
--- config
    location /t {
        compression on;
        compression_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "truth-wins fixture body, long enough to compress well\n";
    }
--- request
GET /t
--- more_headers eval
qq{Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::b64:}
--- response_headers
Content-Encoding: dcz
--- error_log
the file's computed hash wins


=== TEST 19: duplicate Sec-Fetch-Site fails closed (agreeable value LAST)
# Parent's #140, ported — with the hazard order inverted for this walk.
# Neither header is in nginx's headers_in table, so duplicates chain
# through to the module instead of being rejected. This walk keeps the
# LAST occurrence, so the dangerous shape here is a smuggled/merged
# duplicate APPENDING same-origin after a truthful cross-site: pre-fix
# the appended value won and the §8.3 gate switched off (this test
# answered dcz). More than one occurrence now refuses the dictionary
# coding outright; a browser never sends two, so nothing real degrades.
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
        return 200 "dup sec-fetch fixture body, long enough to compress\n";
    }
--- request
GET /t
--- more_headers eval
qq{Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::b64:\nSec-Fetch-Site: cross-site\nSec-Fetch-Site: same-origin}
--- response_headers
Content-Encoding: zstd


=== TEST 19b: duplicate Sec-Fetch-Site fails closed regardless of order
# The agreeable value first: last-match already refused this shape (the
# cross-site line won), so this passes pre-fix too — kept because it
# pins the refusal as order-independent rather than an accident of
# which duplicate the walk happens to keep.
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
        return 200 "dup sec-fetch fixture body, long enough to compress\n";
    }
--- request
GET /t
--- more_headers eval
qq{Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::b64:\nSec-Fetch-Site: same-origin\nSec-Fetch-Site: cross-site}
--- response_headers
Content-Encoding: zstd


=== TEST 19c: duplicate Available-Dictionary fails closed
# Same rule for the other un-tabled header: two AD lines — even
# identical, valid ones — refuse the dictionary coding. Pre-fix the
# last line silently decided the negotiation.
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
        return 200 "dup available-dictionary fixture body to compress\n";
    }
--- request
GET /t
--- more_headers eval
qq{Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::b64:\nAvailable-Dictionary: :$::b64:}
--- response_headers
Content-Encoding: zstd


=== TEST 20: secure-context default fail-closed — dcz declines over cleartext
# No acknowledgement (this block opts out of the injected one via its
# name), and Test::Nginx speaks cleartext, so RFC 9842 §8 refuses the
# dictionary coding. The base coding still wins the election.
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
        return 200 "secure-context fixture body, long enough to compress well\n";
    }
--- request
GET /t
--- more_headers eval
qq{Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::b64:}
--- response_headers
Content-Encoding: zstd


=== TEST 21: secure-context explicit off is identical to the default
--- user_files eval
[ [ "app.dict" => $::dict ] ]
--- http_config
    compression_dict_assume_secure_transport off;
    compression_dict_file html/app.dict;
--- config
    location /t {
        compression on;
        compression_min_length 1;
        default_type text/html;
        gzip_vary on;
        return 200 "secure-context fixture body, long enough to compress well\n";
    }
--- request
GET /t
--- more_headers eval
qq{Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::b64:}
--- response_headers
Content-Encoding: zstd


=== TEST 22: secure-context X-Forwarded-Proto https does NOT re-enable dcz
# The gate is transport, never a client-settable header: a forwarded
# scheme claim on a directly reachable listener must not switch dcz back
# on over cleartext. Same for the other three common spellings below.
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
        return 200 "secure-context fixture body, long enough to compress well\n";
    }
--- request
GET /t
--- more_headers eval
qq{Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::b64:\nX-Forwarded-Proto: https}
--- response_headers
Content-Encoding: zstd


=== TEST 23: secure-context Forwarded proto=https does NOT re-enable dcz
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
        return 200 "secure-context fixture body, long enough to compress well\n";
    }
--- request
GET /t
--- more_headers eval
qq{Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::b64:\nForwarded: proto=https}
--- response_headers
Content-Encoding: zstd


=== TEST 24: secure-context X-Forwarded-Scheme https does NOT re-enable dcz
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
        return 200 "secure-context fixture body, long enough to compress well\n";
    }
--- request
GET /t
--- more_headers eval
qq{Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::b64:\nX-Forwarded-Scheme: https}
--- response_headers
Content-Encoding: zstd


=== TEST 25: secure-context X-Url-Scheme https does NOT re-enable dcz
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
        return 200 "secure-context fixture body, long enough to compress well\n";
    }
--- request
GET /t
--- more_headers eval
qq{Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::b64:\nX-Url-Scheme: https}
--- response_headers
Content-Encoding: zstd


=== TEST 26: secure-context acknowledgement at location level re-enables dcz
# Proves the opt-in path itself works (not just the injected http-level
# one): this block opts out of the injection, sets the directive in the
# location, and dcz elects — exactly the TLS-terminating-proxy case.
--- user_files eval
[ [ "app.dict" => $::dict ] ]
--- http_config
    compression_dict_file html/app.dict;
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_dict_assume_secure_transport on;
        default_type text/html;
        gzip_vary on;
        return 200 "secure-context fixture body, long enough to compress well\n";
    }
--- request
GET /t
--- more_headers eval
qq{Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::b64:}
--- response_headers
Content-Encoding: dcz
--- response_body_like eval
$::dcz_re


=== TEST 27: secure-context inheritance — http on, location off wins
# Merge semantics: the acknowledgement inherits like any flag, and a
# location-level off overrides an http-level on.
--- user_files eval
[ [ "app.dict" => $::dict ] ]
--- http_config
    compression_dict_assume_secure_transport on;
    compression_dict_file html/app.dict;
--- config
    location /t {
        compression on;
        compression_min_length 1;
        compression_dict_assume_secure_transport off;
        default_type text/html;
        gzip_vary on;
        return 200 "secure-context fixture body, long enough to compress well\n";
    }
--- request
GET /t
--- more_headers eval
qq{Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::b64:}
--- response_headers
Content-Encoding: zstd
