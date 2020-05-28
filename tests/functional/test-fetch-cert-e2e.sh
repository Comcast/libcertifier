#!/bin/bash
if [ -z "$2" ]; then
    echo "Usage: $0 <PKCS12 Path> <PKCS12 Password>"
    exit
fi

if [[ "$(python3 -V)" =~ "Python 3" ]]
then
  echo "Python3 found."
else
  echo "Please install Python3." >&2
  exit 1
fi

export TEST_CREATE_X509_CRT_SCRIPT="./test-create-x509-crt.sh"
export TEST_DEVICE_REG_SCRIPT="./test-device-reg.sh"

if [ ! -f ${TEST_CREATE_X509_CRT_SCRIPT} ]; then
    echo "${TEST_CREATE_X509_CRT_SCRIPT} not found!"
    exit 2
fi

if [ ! -f ${TEST_DEVICE_REG_SCRIPT} ]; then
    echo "${TEST_DEVICE_REG_SCRIPT} not found!"
    exit 3
fi

if [ ! -x ${TEST_CREATE_X509_CRT_SCRIPT} ]; then
    echo "${TEST_CREATE_X509_CRT_SCRIPT} not executable!"
    exit 4
fi

if [ ! -x ${TEST_DEVICE_REG_SCRIPT} ]; then
    echo "${TEST_DEVICE_REG_SCRIPT} not executable!"
    exit 5
fi

X509_CRT="`${TEST_CREATE_X509_CRT_SCRIPT} $1 $2 | python3 -c "import sys, json; print(json.load(sys.stdin)['output'])"`"
if [ $? -eq 0 ]
then
  echo "./test-create-x509-crt.sh invocation was successful."
  ${TEST_DEVICE_REG_SCRIPT} ${X509_CRT}
else
  echo "./test-create-x509-crt.sh invocation failed." >&2
  exit 6
fi
