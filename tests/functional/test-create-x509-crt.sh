#!/bin/bash
if [ -z "$2" ]; then
    echo "Usage: $0 <PKCS12 Path> <PKCS12 Password>"
    exit
fi
CWD=$(pwd)
[[ -z "${LIBCERTIFIER_HOME_DIR}" ]] && LIBCERTIFIER_HOME_DIR='../../build' || LIBCERTIFIER_HOME_DIR="${LIBCERTIFIER_HOME_DIR}"
${LIBCERTIFIER_HOME_DIR}/certifierUtil -m 128 -X X509 -k $1 -p $2
cd ${CWD}

