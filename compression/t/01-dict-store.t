use Test::Nginx::Socket;
use Digest::SHA qw(sha256_hex);

# Phase-1a store rules as a regression suite: every config-load rule
# from the shell matrix, plus the $compression_dicts_hashed witness
# and the inheritance semantics only Test::Nginx can express cleanly.
# The dictionary contents are Perl constants so their hashes are
# computed here, never hardcoded.

our $dict_a  = "const shared = 'store fixture material, dictionary A';\n" x 40;
our $dict_b  = "let other = 'store fixture material, dictionary B';\n" x 40;
our $hex_a   = sha256_hex($dict_a);
our $badhex  = '0' x 64;

# six distinct dictionaries to force the store's pointer array past its
# initial capacity (WRINKLES 14: growth relocates a value-array's
# element storage; this pins the pointer-store fix)
our @growth = map { "growth dictionary number $_ fixture content\n" x 20 } 1..6;

no_long_string();
log_level 'warn';
# config-load errors/warnings and the cycle-owned counter are observed
# once per start; repeats would re-read a wiped error.log
repeat_each(1);
plan 'no_plan';
run_tests();

__DATA__


=== TEST 1: a computed dictionary loads, and the witness counts one pass
--- user_files eval
[ [ "a.dict" => $::dict_a ] ]
--- http_config
    compression_dict_file html/a.dict;
--- config
    location /w {
        default_type text/plain;
        return 200 "hashed=$compression_dicts_hashed";
    }
--- request
GET /w
--- response_body: hashed=1
--- no_error_log
[error]



=== TEST 2: a supplied hash is the zero-hashing fast path
--- user_files eval
[ [ "a.dict" => $::dict_a ] ]
--- http_config eval
qq{    compression_dict_file html/a.dict $::hex_a;\n}
--- config
    location /w {
        default_type text/plain;
        return 200 "hashed=$compression_dicts_hashed";
    }
--- request
GET /w
--- response_body: hashed=0
--- no_error_log
[error]



=== TEST 3: store dedup + the mandated audit compute, witnessed exactly
# a.dict supplied at http (0 computes) + b.dict computed (1) + a.dict
# re-referenced UNSUPPLIED in a location (1 audit compute — "a supplied
# hash never satisfies a directive that didn't supply one") = 2. The
# same files referenced from two levels load once each.
--- user_files eval
[ [ "a.dict" => $::dict_a ], [ "b.dict" => $::dict_b ] ]
--- http_config eval
qq{    compression_dict_file html/a.dict $::hex_a;
    compression_dict_file html/b.dict;\n}
--- config
    location /w {
        compression_dict_file html/a.dict;
        compression_dict_file html/b.dict;
        default_type text/plain;
        return 200 "hashed=$compression_dicts_hashed";
    }
--- request
GET /w
--- response_body: hashed=2
--- no_error_log
[error]



=== TEST 4: a malformed hash is reported BEFORE the file is opened
# ordering pin from the parent repo: the path here does not exist, and
# the error must still be about the hash — the operator fixes their
# config once, not twice
--- http_config
    compression_dict_file html/does-not-exist.dict zz11;
--- config
    location /t { return 200 "x"; }
--- must_die
--- error_log
invalid dictionary hash
--- no_error_log
[alert]



=== TEST 5: a missing dictionary file fails at config load
--- http_config
    compression_dict_file html/does-not-exist.dict;
--- config
    location /t { return 200 "x"; }
--- must_die
--- error_log
failed
--- no_error_log
[alert]



=== TEST 6: two different paths with identical content collide on hash
# RFC 9842 negotiation keys on the hash alone; duplicates would be
# ambiguous. Config error, naming the colliding path.
--- user_files eval
[ [ "a.dict" => $::dict_a ], [ "a-copy.dict" => $::dict_a ] ]
--- http_config
    compression_dict_file html/a.dict;
    compression_dict_file html/a-copy.dict;
--- config
    location /t { return 200 "x"; }
--- must_die
--- error_log
has the same hash as
--- no_error_log
[alert]



=== TEST 7: the same path twice in one list is a duplicate
--- user_files eval
[ [ "a.dict" => $::dict_a ] ]
--- http_config
    compression_dict_file html/a.dict;
    compression_dict_file html/a.dict;
--- config
    location /t { return 200 "x"; }
--- must_die
--- error_log
duplicate dictionary
--- no_error_log
[alert]



=== TEST 8: a stale supplied hash is caught by the mandated audit
# http supplies a WRONG hash (trusted verbatim, deliberately); the
# location's unsupplied reference mandates a computation, and the
# computation doubles as the audit that catches the stale hash
--- user_files eval
[ [ "a.dict" => $::dict_a ] ]
--- http_config eval
qq{    compression_dict_file html/a.dict $::badhex;\n}
--- config
    location /t {
        compression_dict_file html/a.dict;
        return 200 "x";
    }
--- must_die
--- error_log
does not match the file
--- no_error_log
[alert]



=== TEST 9: conflicting supplied hashes for one path are a config error
--- user_files eval
[ [ "a.dict" => $::dict_a ] ]
--- http_config eval
qq{    compression_dict_file html/a.dict $::hex_a;\n}
--- config eval
qq{    location /t {
        compression_dict_file html/a.dict $::badhex;
        return 200 "x";
    }\n}
--- must_die
--- error_log
conflicting sha256
--- no_error_log
[alert]



=== TEST 10: duplicate detection survives store growth (WRINKLES 14)
# six dictionaries force the pointer array past its initial capacity;
# re-declaring the FIRST afterwards must still be caught — the
# value-array store silently accepted this after growth relocated the
# entries out from under the list's aliases
--- user_files eval
[ map { [ "g$_.dict" => $::growth[$_ - 1] ] } 1..6 ]
--- http_config
    compression_dict_file html/g1.dict;
    compression_dict_file html/g2.dict;
    compression_dict_file html/g3.dict;
    compression_dict_file html/g4.dict;
    compression_dict_file html/g5.dict;
    compression_dict_file html/g6.dict;
    compression_dict_file html/g1.dict;
--- config
    location /t { return 200 "x"; }
--- must_die
--- error_log
duplicate dictionary
--- no_error_log
[alert]



=== TEST 11: an empty dictionary file is a config error
--- user_files eval
[ [ "empty.dict" => "" ] ]
--- http_config
    compression_dict_file html/empty.dict;
--- config
    location /t { return 200 "x"; }
--- must_die
--- error_log
empty or unreadable
--- no_error_log
[alert]



=== TEST 12: a 63-character hash is rejected (one under valid)
--- user_files eval
[ [ "a.dict" => $::dict_a ] ]
--- http_config eval
qq{    compression_dict_file html/a.dict } . ("0" x 63) . qq{;\n}
--- config
    location /t { return 200 "x"; }
--- must_die
--- error_log
invalid dictionary hash
--- no_error_log
[alert]



=== TEST 13: a 65-character hash is rejected (one over valid)
--- user_files eval
[ [ "a.dict" => $::dict_a ] ]
--- http_config eval
qq{    compression_dict_file html/a.dict } . ("0" x 65) . qq{;\n}
--- config
    location /t { return 200 "x"; }
--- must_die
--- error_log
invalid dictionary hash
--- no_error_log
[alert]


=== TEST 14: a dictionary above the 8 MB browser window warns at load
# parent parity: content beyond the window cannot reference the far
# end of the dictionary; loading proceeds, the operator is told
--- user_files eval
[ [ "big.dict" => ("x" x 8388609) ] ]
--- http_config
    compression_dict_file html/big.dict;
--- config
    location /t {
        compression on;
        default_type text/html;
        gzip_vary on;
        return 200 "oversized dictionary fixture body long enough\n";
    }
--- request
GET /t
--- error_log
larger than the 8 MB window browsers enforce


=== TEST 15: a MISSING optional dictionary warns and the server starts
# the operator-insistence demotion (intentional RFC deviation): a
# botched deploy must not take the site down — clients holding the
# absent dictionary degrade to the base coding
--- config
    location /t {
        compression on;
        compression_dict_file html/does-not-exist.dict optional;
        default_type text/html;
        gzip_vary on;
        return 200 "optional-missing fixture body long enough here\n";
    }
--- request
GET /t
--- error_code: 200
--- error_log
skipping optional dictionary


=== TEST 16: a missing dictionary WITHOUT optional still refuses to start
--- config
    location /t {
        compression on;
        compression_dict_file html/does-not-exist.dict;
        default_type text/html;
        return 200 "strict-missing fixture body long enough here\n";
    }
--- must_die
--- error_log
open() dictionary


=== TEST 17: an EMPTY optional dictionary warns and the server starts
--- user_files eval
[ [ "empty.dict" => "" ] ]
--- config
    location /t {
        compression on;
        compression_dict_file html/empty.dict optional;
        default_type text/html;
        gzip_vary on;
        return 200 "optional-empty fixture body long enough here\n";
    }
--- request
GET /t
--- error_code: 200
--- error_log
skipping optional dictionary


=== TEST 18: same-hash different-path with optional aliases and warns
--- user_files eval
[ [ "a.dict" => ("alias fixture dictionary content\n" x 20) ],
  [ "b.dict" => ("alias fixture dictionary content\n" x 20) ] ]
--- config
    location /t {
        compression on;
        compression_dict_file html/a.dict;
        compression_dict_file html/b.dict optional;
        default_type text/html;
        gzip_vary on;
        return 200 "alias fixture body long enough to compress here\n";
    }
--- request
GET /t
--- error_code: 200
--- error_log
using the existing entry


=== TEST 19: a duplicate optional line in one list warns and skips
--- user_files eval
[ [ "a.dict" => ("dup fixture dictionary content\n" x 20) ] ]
--- config
    location /t {
        compression on;
        compression_dict_file html/a.dict optional;
        compression_dict_file html/a.dict optional;
        default_type text/html;
        gzip_vary on;
        return 200 "dup fixture body long enough to compress here\n";
    }
--- request
GET /t
--- error_code: 200
--- error_log
skipping the duplicate


=== TEST 20: garbage where the hash belongs stays FATAL even with optional
# a typo is a config bug to fix once, not a deploy race to ride out
--- user_files eval
[ [ "a.dict" => ("typo fixture dictionary content\n" x 20) ] ]
--- config
    location /t {
        compression_dict_file html/a.dict zzzz optional;
    }
--- must_die
--- error_log
invalid dictionary hash "zzzz"
