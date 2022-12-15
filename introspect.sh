#!/bin/bash

#
# A utility script to introspect access tokens
#
curl -k -s -X POST https://localhost:8443/oauth/v2/oauth-introspect \
    -u "introspect-client:Password1" \
    -H "Accept: application/jwt" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "token=$ACCESS_TOKEN"