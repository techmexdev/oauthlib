# NOTE -- 

Project has been abandoned as it was decided to completely write a new, more
secure and correct OAuth2.0 implementation for Golang from scratch. This is
here as a reference for others, and for myself.

Please see [github.com/knq/oauth](https://github.com/knq/oauth) for a
significantly better implementation and was written from the ground up.

# About oauthlib [![Build Status](https://travis-ci.org/kenshaw/oauthlib.svg)](https://travis-ci.org/kenshaw/oauthlib) [![Coverage Status](https://coveralls.io/repos/kenshaw/oauthlib/badge.svg?branch=master&service=github)](https://coveralls.io/github/kenshaw/oauthlib?branch=master) #

Package oauthlib is a [Golang](https://golang.org/project) oauth2 server
library. The library attempts to follow as many Go idioms as possible, and be
compliant with the OAuth2.0 spec as specified in [RFC 6749](http://tools.ietf.org/html/rfc6749).

The library handles the majority of the specification, such as authorization
token endpoints, authorization codes, access grants such as implicit, and
client credentials. Please see the [GoDoc](https://godoc.org/github.com/kenshaw/oauthlib) 
for a full API reference.

oauthlib is a substanial rewrite from the original [osin](https://github.com/RangelReale/osin) 
package. oauthlib aims to vastly simplify the original API, to better alighn
the implementation with standard Go idioms, and to make better use of the Go
standard library where possible.

## Installation ##

Install the package via the following:
  
    go get -u github.com/kenshaw/oauthmw

## Example ##

Currently the rewrite is a work in progress. Please see the [examples](./examples) 
directory for the currently availaible examples.

## Warning ##

This is a substanial rewrite, and as of now the API is vastly in flux. Things
may break at any given point in time, as oauthlib does not intend to remain
static.
