#!/bin/bash

git submodule update --init
pushd .
cd ./matter_plugin/matter-sdk
git submodule update --init
source ./scripts/activate.sh
popd
source ./matter_plugin/matter-sdk/scripts/bootstrap.sh

mkdir -p build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/ -DENABLE_CMAKE_VERBOSE_MAKEFILE=ON -DENABLE_CMOCKA=OFF -DENABLE_MBEDTLS=OFF -DENABLE_TESTS=ON -DCMAKE_BUILD_TYPE=Debug -DENABLE_MATTER_EXAMPLES=ON -DSYSTEMV_DAEMON=OFF
make
cd ..
cp build/libcertifier.a matter_plugin

pushd .

cd build
./certifierUtil get-cert -f -k seed.p12 -p changeit -o dac-commissioner.p12 --product-id 1101 --profile-name XFN_AS_PAI_1
./certifierUtil get-cert -f -k seed.p12 -p changeit -o dac-commissionee.p12 --product-id 1101 --profile-name XFN_AS_PAI_1
rm -f ../resources/dac-commissioner.p12
rm -f ../resources/dac-commissionee.p12
cp dac-commissioner.p12 ../resources
cp dac-commissionee.p12 ../resources

cd ../matter_plugin
gn gen --check out/build
ninja -C out/build

cd ./out/build
cp certifier-tool ../../../build

cd ../../../certifier-all-clusters-app
gn gen --check out/build
ninja -C out/build

cd ./out/build
cp certifier-all-clusters-app ../../../build

cd ../..
cp trafficlight ../build

cd ../resources
rm -f dac-commissioner.p12 dac-commissionee.p12

popd
