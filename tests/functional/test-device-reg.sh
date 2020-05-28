#!/bin/bash
if [ -z "$1" ]; then
    echo "Usage: $0 <b64_crt_token>"
    exit
fi
CWD=$(pwd)
[[ -z "${LIBCERTIFIER_HOME_DIR}" ]] && LIBCERTIFIER_HOME_DIR='../../build' || LIBCERTIFIER_HOME_DIR="${LIBCERTIFIER_HOME_DIR}"
cd ${LIBCERTIFIER_HOME_DIR}
./certifierUtil -f -T $1
cd ${CWD}
