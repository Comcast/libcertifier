#!/bin/bash
if [ -z "$2" ]; then
    echo "Usage: $0 <token> <crt_type>"
    exit
fi
CWD=$(pwd)
[[ -z "${LIBCERTIFIER_HOME_DIR}" ]] && LIBCERTIFIER_HOME_DIR='../../build' || LIBCERTIFIER_HOME_DIR="${LIBCERTIFIER_HOME_DIR}"
cd ${LIBCERTIFIER_HOME_DIR}
./certifierUtil -m 128 -S $1 -X $2
cd ${CWD}

