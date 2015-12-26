# About oauthlib [![Build Status](https://travis-ci.org/knq/oauthlib.svg)](https://travis-ci.org/knq/oauthlib) [![Coverage Status](https://coveralls.io/repos/knq/oauthlib/badge  .svg?branch=master&service=github)](https://coveralls.io/github/knq/oauthlib?branch=master) #

Package oauthlib is a [Golang](https://golang.org/project) oauth2 server
library. The library attempts to follow as many Go idioms as possible, and be
compliant with the Oauth2.0 spec as specified in [RFC 6749](http://tools.ietf.org/html/rfc6749) 
and in the [IETF specs](http://tools.ietf.org/html/draft-ietf-oauth-v2-10).

The library handles the majority of the specification, such as authorization
token endpoints, authorization codes, access grants such as implicit, and
client credentials. Please see the [GoDoc](https://godoc.org/github.com/knq/oauthlib) 
for a full API reference.

oauthlib is a substanial rewrite from the original [osin](https://github.com/RangelReale/osin) 
package. oauthlib aims to vastly simplify the original API, to better alighn
the implementation with standard Go idioms, and to make better use of the Go
standard library where possible.

## Installation ##

Install the package via the following:
  
    go get -u github.com/knq/oauthmw

## Example ##

Currently the rewrite is a work in progress. Please see the [examples](./examples) 
directory for the currently availaible examples.
