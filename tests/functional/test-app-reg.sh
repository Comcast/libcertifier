#!/bin/bash
if [ -z "$1" ]; then
    echo "Usage: $0 <auth_token>"
    exit
fi
CWD=$(pwd)
[[ -z "${LIBCERTIFIER_HOME_DIR}" ]] && LIBCERTIFIER_HOME_DIR='../../build' || LIBCERTIFIER_HOME_DIR="${LIBCERTIFIER_HOME_DIR}"
cd ${LIBCERTIFIER_HOME_DIR}
./certifierUtil -c -f -S $1
cd ${CWD}
