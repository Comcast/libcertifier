#!/bin/bash
CWD=$(pwd)
[[ -z "${LIBCERTIFIER_HOME_DIR}" ]] && LIBCERTIFIER_HOME_DIR='../../build' || LIBCERTIFIER_HOME_DIR="${LIBCERTIFIER_HOME_DIR}"
cd ${LIBCERTIFIER_HOME_DIR}
./certifierUtil -m 32 -O "Please Transform Me!"
cd ${CWD}

