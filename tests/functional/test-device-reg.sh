#!/bin/bash
if [ -z "$1" ]; then
    echo "Usage: $0 <b64_crt_token>"
    exit
fi
#to be executed from the build directory, where all binaries and these scripts are moved
./certifierUtilLegacy get-cert -f -T $1
