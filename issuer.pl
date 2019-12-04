#!/usr/bin/env perl

use strict;
use warnings;
use feature 'say';
use Crypt::JWT qw(encode_jwt);
use Perl6::Slurp qw(slurp);

sub encode {
  my $private_key = slurp('<:utf8', './keys/private-key.pem');
  return encode_jwt(
    payload => { uid => 123 },
    key => \$private_key,
    alg => 'RS256',
    enc => 'A256CBC-HS512',
  );
}

say encode();
