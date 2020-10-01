#!/bin/bash
if [ -z "$2" ]; then
    echo "Usage: $0 <token> <crt_type>"
    exit
fi
#to be executed from the build directory, where all binaries and these scripts are moved
./certifierUtil -m 128 -S $1 -X $2

