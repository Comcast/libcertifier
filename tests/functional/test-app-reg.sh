#!/bin/bash
if [ -z "$1" ]; then
    echo "Usage: $0 <auth_token>"
    exit
fi
#to be executed from the build directory, where all binaries and these scripts are moved
./certifierUtil -c -f -S $1
