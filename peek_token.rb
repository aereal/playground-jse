#!/usr/bin/env ruby

require 'base64'
require 'pp'

token = ARGF.read.strip
header, payload, sig = *token.split(?.).map {|t| Base64.urlsafe_decode64(t) }
pp(header: header, payload: payload, sig: sig)
