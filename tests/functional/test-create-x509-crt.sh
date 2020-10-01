#!/bin/bash
if [ -z "$2" ]; then
    echo "Usage: $0 <PKCS12 Path> <PKCS12 Password>"
    exit
fi
#to be executed from the build directory, where all binaries and these scripts are moved
./certifierUtil -m 128 -X X509 -k $1 -p $2

