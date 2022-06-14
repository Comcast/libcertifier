#!/bin/bash
if [ -z "$4" ]; then
    echo "Usage: $0 <token> <crt_type> <PKCS12 Path> <PKCS12 Password>"
    exit
fi
#to be executed from the build directory, where all binaries and these scripts are moved
./certifierUtil get-crt-token -S $1 -X $2 -k $3 -p $4
