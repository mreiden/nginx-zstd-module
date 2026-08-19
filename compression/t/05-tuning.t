use Test::Nginx::Socket;
use Test::More;
use Digest::SHA qw(sha256_hex);
use File::Temp qw(tempdir);

# Phase-3 tuning directives: compression_level <coding> <n> and
# compression_window <coding> <size>, keyed by coding against
# backend-declared bounds. The deterministic witness is the header
# filter's debug line ("compression: create <coding> level <n>
# window_bits <b>"), which pins exactly what reached the encoder --
# ratio-based assertions would be fragile, the applied-parameter line
# is not. Tuned blocks additionally decode through the reference CLIs
# so "the tuned stream is still a valid stream" is proven, not
# assumed (the parent's negative-level lesson).

my $tmp = tempdir(CLEANUP => 1);

our $src = "tuning fixture body: compressible repeated text line\n" x 40;

sub spew { open my $h, '>', $_[0] or die "$_[0]: $!"; binmode $h; print $h $_[1]; close $h }
sub slurp { open my $h, '<', $_[0] or die "$_[0]: $!"; binmode $h; local $/; <$h> }

sub cli_decode {
    my ($cmd, $data) = @_;
    spew("$tmp/in", $data);
    system("$cmd < $tmp/in > $tmp/out 2>/dev/null") == 0 or return undef;
    return slurp("$tmp/out");
}

our %decoders = (
    zstd => sub { cli_decode("zstd -dq -c", $_[0]) },
    br   => sub { cli_decode("brotli -d -c", $_[0]) },
);

add_response_body_check(sub {
    my ($block, $body, $req_idx, $rep_idx, $dry) = @_;
    return if $dry;

    my $how = $block->decode_with or return;
    chomp $how;

    my $dec = $decoders{$how} ? $decoders{$how}->($body) : undef;

    Test::More::is(
        defined $dec ? sha256_hex($dec) : "(decode failed)",
        sha256_hex($src),
        $block->name . " - $how roundtrip decodes byte-exact"
    );
});

no_long_string();
log_level 'warn';
repeat_each(1);
plan 'no_plan';
run_tests();

__DATA__


=== TEST 1: unknown coding in compression_level is a config error
--- config
    location / {
        compression_level lzma 5;
    }
--- must_die
--- error_log
unknown coding "lzma" in "compression_level"


=== TEST 2: the gzip token is rejected with a pointer at the core directive
# defer means the core gzip filter compresses under its OWN rule set --
# its tuning lives in gzip_comp_level, and silently accepting the token
# here would configure nothing
--- config
    location / {
        compression_level gzip 5;
    }
--- must_die
--- error_log
tune it with the core "gzip_comp_level" directive


=== TEST 3: dict codings are tuned through their base coding
# a prepared brotli dictionary bakes in the quality; there is no
# separate dcz/dcb knob by design
--- config
    location / {
        compression_level dcz 5;
    }
--- must_die
--- error_log
"dcz" is tuned through its base coding


=== TEST 4: zstd level above the declared max is a config error
--- config
    location / {
        compression_level zstd 23;
    }
--- must_die
--- error_log
compression level for "zstd" must be between


=== TEST 5: brotli quality above 11 is a config error
--- config
    location / {
        compression_level br 12;
    }
--- must_die
--- error_log
compression level for "br" must be between 0 and 11


=== TEST 6: brotli quality below 0 is a config error
--- config
    location / {
        compression_level br -1;
    }
--- must_die
--- error_log
compression level for "br" must be between 0 and 11


=== TEST 7: a non-numeric level is a config error
--- config
    location / {
        compression_level zstd abc;
    }
--- must_die
--- error_log
invalid level "abc" in "compression_level"


=== TEST 8: duplicate compression_level for one coding is a config error
--- config
    location / {
        compression_level zstd 5;
        compression_level zstd 6;
    }
--- must_die
--- error_log
is duplicate


=== TEST 9: a non-power-of-two window is a config error
--- config
    location / {
        compression_window zstd 100k;
    }
--- must_die
--- error_log
compression window "100k" for "zstd" must be a power-of-two size


=== TEST 10: a window above brotli's 16m format ceiling is a config error
--- config
    location / {
        compression_window br 32m;
    }
--- must_die
--- error_log
compression window "32m" for "br" must be a power-of-two size (one of: 1k, 2k, 4k, 8k, 16k, 32k, 64k, 128k, 256k, 512k, 1m, 2m, 4m, 8m, 16m)


=== TEST 11: a window below the 1k floor is a config error
--- config
    location / {
        compression_window zstd 512;
    }
--- must_die
--- error_log
compression window "512" for "zstd" must be a power-of-two size


=== TEST 12: tuned zstd reaches the encoder and still decodes
--- log_level: debug
--- user_files eval
[ [ "t/body.txt" => $::src ] ]
--- config
    location /t/ {
        compression on;
        compression_level zstd 19;
        compression_window zstd 8m;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /t/body.txt
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- decode_with
zstd
--- error_log eval
qr/compression: create zstd level 19 window_bits 23/


=== TEST 13: a negative zstd level produces a valid stream (parent parity)
--- log_level: debug
--- user_files eval
[ [ "t/body.txt" => $::src ] ]
--- config
    location /t/ {
        compression on;
        compression_level zstd -5;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /t/body.txt
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- decode_with
zstd
--- error_log eval
qr/compression: create zstd level -5 window_bits 0/


=== TEST 14: tuned brotli reaches the encoder and still decodes
--- log_level: debug
--- user_files eval
[ [ "t/body.txt" => $::src ] ]
--- config
    location /t/ {
        compression on;
        compression_order br;
        compression_level br 11;
        compression_window br 1m;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /t/body.txt
--- more_headers
Accept-Encoding: br
--- response_headers
Content-Encoding: br
--- decode_with
br
--- error_log eval
qr/compression: create br level 11 window_bits 20/


=== TEST 15: zstd defaults -- level 3, window left to the library
--- log_level: debug
--- user_files eval
[ [ "t/body.txt" => $::src ] ]
--- config
    location /t/ {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /t/body.txt
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- decode_with
zstd
--- error_log eval
qr/compression: create zstd level 3 window_bits 0/


=== TEST 16: brotli defaults -- quality 6, lg_win 19 (parent parity)
# pins the declared default: the phase-0 shim said 5, ngx_brotli's
# brotli_comp_level default is 6 -- the vtable declaration corrects
# the drift and this block keeps it corrected
--- log_level: debug
--- user_files eval
[ [ "t/body.txt" => $::src ] ]
--- config
    location /t/ {
        compression on;
        compression_order br;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /t/body.txt
--- more_headers
Accept-Encoding: br
--- response_headers
Content-Encoding: br
--- decode_with
br
--- error_log eval
qr/compression: create br level 6 window_bits 19/


=== TEST 17: http-level tuning is inherited by locations
--- log_level: debug
--- http_config
    compression_level zstd 12;
--- user_files eval
[ [ "t/body.txt" => $::src ] ]
--- config
    location /t/ {
        compression on;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /t/body.txt
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- decode_with
zstd
--- error_log eval
qr/compression: create zstd level 12 window_bits 0/


=== TEST 18: a location override beats the inherited http-level value
--- log_level: debug
--- http_config
    compression_level zstd 12;
--- user_files eval
[ [ "t/body.txt" => $::src ] ]
--- config
    location /t/ {
        compression on;
        compression_level zstd 1;
        compression_min_length 1;
        compression_types text/plain;
        default_type text/plain;
        gzip_vary on;
        root html;
    }
--- request
GET /t/body.txt
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- decode_with
zstd
--- error_log eval
qr/compression: create zstd level 1 window_bits 0/
