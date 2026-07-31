use Test::Nginx::Socket;
use File::Basename;
use Digest::SHA qw(sha256);
use MIME::Base64 qw(encode_base64);
use lib 'lib';

my $dirname = dirname(__FILE__);
$ENV{'TEST_NGINX_PERL_PATH'}="$ENV{'PWD'}/$dirname";

my @dynamic_modules;
if (defined $ENV{'TEST_NGINX_BINARY'}) {
    my $nginx_dir = dirname($ENV{'TEST_NGINX_BINARY'});
    for my $module_name (qw(ngx_http_brotli_filter_module.so ngx_http_brotli_static_module.so)) {
        my $module_path = "$nginx_dir/$module_name";
        push @dynamic_modules, $module_path if -f $module_path;
    }
}

add_block_preprocessor(sub {
    my $block = shift;
    return if !@dynamic_modules;

    my $main_config = join "\n", map { "load_module $_;" } @dynamic_modules;
    $block->set_value("main_config", $main_config);
});

# The negotiation key is the SHA-256 of the dictionary fixture, computed
# here rather than hardcoded so a fixture edit cannot silently
# desynchronize the suite. hello.js doubles as the dictionary; hello.js.br
# is unrelated to dcb (static-module fixture) but its SOURCE works fine
# as a second, different-content dictionary for the override test.
my $dict_raw = do {
    local $/;
    open my $fh, '<', "$dirname/suite/hello.js" or die "hello.js: $!";
    binmode $fh;
    <$fh>;
};
our $dict_b64 = encode_base64(sha256($dict_raw), "");
our $bad_b64  = encode_base64("\x01" x 32, "");

no_long_string();
log_level 'warn';
repeat_each(1);
plan 'no_plan';
run_tests();

__DATA__


=== TEST 1: dcb negotiated when hash matches and dcb is accepted
# Wire-format/byte-exactness assertions live in tools/test_dcb.py; this
# suite pins the negotiation contract.
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js;
        default_type text/html;
        return 200 "dcb negotiation body: hello widget compute render text\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: br, dcb\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: dcb
Vary: Available-Dictionary
--- no_error_log
[error]



=== TEST 2: no Available-Dictionary falls back to br, Vary still set
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js;
        default_type text/html;
        return 200 "dcb negotiation body: hello widget compute render text\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br, dcb
--- response_headers
Content-Encoding: br
Vary: Available-Dictionary
--- no_error_log
[error]



=== TEST 3: unknown dictionary hash falls back to br
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js;
        default_type text/html;
        return 200 "dcb negotiation body: hello widget compute render text\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: br, dcb\nAvailable-Dictionary: :$::bad_b64:"
--- response_headers
Content-Encoding: br
--- no_error_log
[error]



=== TEST 4: Available-Dictionary without dcb in Accept-Encoding
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js;
        default_type text/html;
        return 200 "dcb negotiation body: hello widget compute render text\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: br\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: br
--- no_error_log
[error]



=== TEST 5: dcb;q=0 is an explicit refusal
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js;
        default_type text/html;
        return 200 "dcb negotiation body: hello widget compute render text\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: br, dcb;q=0\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: br
--- no_error_log
[error]



=== TEST 6: the "*" wildcard does not enable dcb
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js;
        default_type text/html;
        return 200 "dcb negotiation body: hello widget compute render text\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: br, *\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: br
--- no_error_log
[error]



=== TEST 7: Sec-Fetch-Site cross-site is refused
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js;
        default_type text/html;
        return 200 "dcb negotiation body: hello widget compute render text\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: br, dcb\nAvailable-Dictionary: :$::dict_b64:\nSec-Fetch-Site: cross-site"
--- response_headers
Content-Encoding: br
--- no_error_log
[error]



=== TEST 8: Sec-Fetch-Site same-origin is allowed
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js;
        default_type text/html;
        return 200 "dcb negotiation body: hello widget compute render text\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: br, dcb\nAvailable-Dictionary: :$::dict_b64:\nSec-Fetch-Site: same-origin"
--- response_headers
Content-Encoding: dcb
--- no_error_log
[error]



=== TEST 9: malformed Available-Dictionary (not a byte sequence)
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js;
        default_type text/html;
        return 200 "dcb negotiation body: hello widget compute render text\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br, dcb
Available-Dictionary: not-a-structured-field
--- response_headers
Content-Encoding: br
--- no_error_log
[error]



=== TEST 10: Available-Dictionary decoding to the wrong length
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js;
        default_type text/html;
        return 200 "dcb negotiation body: hello widget compute render text\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: br, dcb
Available-Dictionary: :aGk=:
--- response_headers
Content-Encoding: br
--- no_error_log
[error]



=== TEST 11: identity fallback still varies on Available-Dictionary
# A client sending "Accept-Encoding: dcb" (no br) with a hash we do not
# hold gets identity — but the SAME client holding a dictionary we DO
# hold would get dcb, so the identity variant is not invariant in
# Available-Dictionary. Guards the Vary push sitting above the
# acceptance gate (the dcz review finding, baked in from the start).
--- config
    location /t {
        brotli on;
        brotli_min_length 8;
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js;
        default_type text/html;
        return 200 "dcb negotiation body: hello widget compute render text\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: dcb\nAvailable-Dictionary: :$::bad_b64:"
--- response_headers
!Content-Encoding
Vary: Available-Dictionary
--- no_error_log
[error]



=== TEST 12: a location's own dictionary list replaces the inherited one
--- config
    brotli on;
    brotli_min_length 8;
    brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js;

    location /inherited {
        default_type text/html;
        return 200 "dcb negotiation body: hello widget compute render text\n";
    }

    location /own {
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js.br;
        default_type text/html;
        return 200 "dcb negotiation body: hello widget compute render text\n";
    }
--- request eval
["GET /inherited", "GET /own"]
--- more_headers eval
[
    "Accept-Encoding: br, dcb\nAvailable-Dictionary: :$::dict_b64:",
    "Accept-Encoding: br, dcb\nAvailable-Dictionary: :$::dict_b64:",
]
--- response_headers eval
[
    "Content-Encoding: dcb",
    "Content-Encoding: br",
]
--- no_error_log
[error]



=== TEST 13: an empty dictionary file is a config-load error
--- config
    location /t {
        brotli on;
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/dcb-empty;
        default_type text/html;
        return 200 "unreachable\n";
    }
--- request
GET /t
--- must_die
--- error_log
is empty
--- no_error_log
[alert]



=== TEST 14: two dictionaries with identical content are a config-load error
--- config
    location /t {
        brotli on;
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js;
        brotli_dcb_dict_file $TEST_NGINX_PERL_PATH/suite/hello.js;
        default_type text/html;
        return 200 "unreachable\n";
    }
--- request
GET /t
--- must_die
--- error_log
has the same content as
--- no_error_log
[alert]
