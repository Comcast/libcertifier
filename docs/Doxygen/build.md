\page docs/Doxygen/build.md Build
[Back to Manual](docs/Doxygen/libcertifier.md)

Build
=====

Prerequisites
-------------

\htmlonly

<table>
<colgroup>
<col width="33%" />
<col width="33%" />
<col width="33%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p><strong>Component</strong></p></td>
<td><p><strong>Version</strong></p></td>
<td><p><strong>Notes</strong></p></td>
</tr>
<tr class="even">
<td><p>C Compiler</p></td>
<td><p>TBD</p></td>
<td><p>Ubuntu 19.x - Consider using <code>sudo apt-get install build-essential</code></p></td>
</tr>
<tr class="odd">
<td><p>OpenSSL</p></td>
<td><p>3.5 (or higher)</p></td>
<td><p>Ubuntu 19.x - Consider using <code>sudo apt-get install libssl-dev</code></p></td>
</tr>
<tr class="even">
<td><p>CMake</p></td>
<td><p>3.12 (or higher)</p></td>
<td><p>Ubuntu 19.x - Consider using <code>sudo apt-get install cmake</code></p></td>
</tr>
<tr class="odd">
<td><p>cURL</p></td>
<td><p>7.65 (or higher)</p></td>
<td><p>Ubuntu 19.x - Consider using <code>sudo apt-get install libcurl4-openssl-dev</code></p></td>
</tr>
<tr class="even">
<td><p>zLib</p></td>
<td><p>1.2.11 (or higher)</p></td>
<td><p>Ubuntu 19.x - Consider using <code>sudo apt install zlib1g-dev</code></p></td>
</tr>
<tr class="odd">
<td><p>cMocka</p></td>
<td><p>1.1</p></td>
<td><p><a href="https://cmocka.org/" class="uri">https://cmocka.org/</a> Ubuntu 19.x - Consider using <code>sudo apt-get install libcmocka-dev</code></p></td>
</tr>
<tr class="even">
<td><p>mbedTLS</p></td>
<td><p>Optional</p></td>
<td><p>Ubuntu 19.x - Consider using <code>sudo apt-get install -y libmbedtls-dev</code><br />
cURL has to be compiled with mbedTLS. Please see - <code>+https://tls.mbed.org/kb/how-to/compile-curl-with-mbedtls+</code></p></td>
</tr>
<tr class="odd">
<td><p>Valgrind</p></td>
<td><p>Optional</p></td>
<td><p>Ubuntu 18.x - Consider using <code>sudo apt-get install -y valgrind</code></p></td>
</tr>
</tbody>
</table>

\endhtmlonly

Build types
-----------

The project supports following build configurations (to be used as an
argument for option `-DCMAKE_BUILD_TYPE=`):

-   Release - build project with compiler optimization and without debug
    information

-   Debug - build project with debug information

-   asan - build with Address Sanitizer features for real-time address
    checking

-   lsan - build with Address Sanitizer features for real-time memory
    leaks checking

-   ubsan - build with Address Sanitizer features for real-time checking
    for undefined behavior

The default build type is `Debug`.

Examples
--------

Cmake can be run from any directory, it requires only path (relative or
absolute) to the source directory and makes a build directory with all
executables where it runs.

With `OpenSSL` & Tests & Valgrind ready & Debug configuration

    mkdir -p Debug
    cd Debug
    cmake .. -DENABLE_CMAKE_VERBOSE_MAKEFILE=ON -DENABLE_CMOCKA=OFF -DENABLE_MBEDTLS=OFF -DENABLE_TESTS=ON -DCMAKE_BUILD_TYPE=Debug

With `mbedTLS` & Tests & ASAN configuration

    mkdir -p asan
    cd asan
    cmake .. -DENABLE_CMAKE_VERBOSE_MAKEFILE=ON -DENABLE_CMOCKA=OFF -DENABLE_MBEDTLS=ON -DENABLE_TESTS=ON -DCMAKE_BUILD_TYPE=asan

From the build directory (if -DENABLE\_TESTS=ON)

1.  Type in `cmake --build . --target clean` or `make clean`

2.  Type in `cmake --build .` or `make`

3.  Type in `./certifierTests` to run the unit tests

Now, run the functional test. This attempts to read in the device
attestation certificate, creates an X509 token from it (for
authentication) and makes an HTTPS call to certifier and creates a
PKCS12 file with a public/private keypair and an X509 certificate.

`./test-fetch-cert-e2e.sh ./device-attestation-certificate.p12 changeit`
. There should be an `lrg` file in the build directory. This is the
created PKCS12 file.

Build Options
-------------

\htmlonly

<table>
<colgroup>
<col width="33%" />
<col width="33%" />
<col width="33%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p><strong>Name</strong></p></td>
<td><p><strong>Default Value</strong></p></td>
<td><p><strong>Description</strong></p></td>
</tr>
<tr class="even">
<td><p>ENABLE_MBEDTLS</p></td>
<td><p>OFF</p></td>
<td><p>Enables mbedTLS as the crypto provider. Otherwise, OpenSSL is the default.</p></td>
</tr>
<tr class="odd">
<td><p>ENABLE_TESTS</p></td>
<td><p>OFF</p></td>
<td><p>Build unit tests (requires CMocka or Unit to be used)</p></td>
</tr>
<tr class="even">
<td><p>ENABLE_CMOCKA</p></td>
<td><p>OFF</p></td>
<td><p>Unit testing framework to use. If OFF, Unit (self-contained is used)</p></td>
</tr>
<tr class="odd">
<td><p>ENABLE_CMAKE_VERBOSE_MAKEFILE</p></td>
<td><p>OFF</p></td>
<td><p>Enable verbose nakefiles for debugging</p></td>
</tr>
</tbody>
</table>

\endhtmlonly

Sanitizers
----------

Address Sanitizer works in runtime always if `CMAKE_BUILD_TYPE=asan` is
chosen. Similar for Leakage Sanitizer (`lsan`) and Undefined Behavior
sanitizer (`ubsan`). Normally Sanitizer produces list of errors after
the program finishes, but all these errors have been fixed and there are
no messages after that. Remember that project built with
`CMAKE_BUILD_TYPE=asan` fails Valgrind tests invoked with the command
`ctest -T memcheck`.

Valgrind
--------

Valgrind checks can be run on any tests added to `CMakeLists.txt` and
runnable with `ctest` by the command

    ctest -T memcheck

OSX
---

Building/running on OSX is a bit tricky.

### OpenSSL 3.5

libcertifier requires OpenSSL 3.5 or higher. If it is not already
available on macOS, build and install OpenSSL 3.5.0 as follows:

    cd ~
    curl --remote-name https://www.openssl.org/source/openssl-3.5.0.tar.gz
    tar -xzvf openssl-3.5.0.tar.gz
    cd openssl-3.5.0
    ./Configure darwin64-x86_64-cc shared enable-default-thread-pool --prefix=/usr/local/mac-dev-env/openssl-3.5.0 --openssldir=/usr/local/mac-dev-env/openssl-3.5.0
    make
    sudo make install

OpenSSL 3.5 includes support for the PQC algorithms ML-KEM, ML-DSA, and
SLH-DSA. Set `OPENSSL_ROOT_DIR` to this installation when configuring
libcertifier.

### cURL 7.69.1

If you already have `curl` version 7.69.1 or higher, you can skip this
section.

Just like OpenSSL, I prefer to compile and install cURL on OSX myself.
Here is what I did, and may have be tuned for your particular env -

Step 1 - Get the source code for cURL 7.69.1 -

    cd ~
    curl --remote-name https://curl.haxx.se/download/curl-7.69.1.tar.gz

Step 2 - Extract the archive and move into the folder -

    tar -xzvf curl-7.69.1.tar.gz
    cd curl-7.69.1

Step 3 - Configure, compile and install into
`/usr/local/mac-dev-env/curl-7.69.1`

    ./configure --with-darwinssl --prefix=/usr/local/mac-dev-env/curl-7.69.1
    make
    sudo make install

Notice the `--with-darwinssl` flag. This uses OSX’s built-in OpenSSL
version and not the one we just built. I prefer doing this, because it’s
easier.

If you have OpenSSL installed somewhere else (for example, /opt/OpenSSL)
and you have pkg-config installed, set the pkg-config path first, like
this:

    env PKG_CONFIG_PATH=/opt/OpenSSL/lib/pkgconfig ./configure --with-ssl

Without pkg-config installed, use this:

    ./configure --with-ssl=/opt/OpenSSL

Step 5 - Now cURL should be installed.

Step 6 - Type the following command to see build output as shown below.
Make sure output successfully finds openssl, curl and zlib

    cmake .
    -- Found OpenSSL: /usr/local/lib/libcrypto.dylib (found suitable version "3.5.0", minimum required is "3.5")
    -- Found ZLIB: /usr/lib/libz.dylib (found suitable version "1.2.11", minimum required is "1.2.11")
    -- Found CURL: /usr/lib/libcurl.dylib (found suitable version "7.64.1", minimum required is "7.60")
    -- Performing Test HAS_SSP
    -- Performing Test HAS_SSP - Success
    -- Stack smashing protection enabled
    -- AddressSanitizer enabled (debug builds)
    -- buildType:
    -- extra cflags:  -Wall  -std=c99 -fstack-protector-strong --param=ssp-buffer-size=4 -g -fsanitize=address,undefined
    -- Configuring done
    -- Generating done
    -- Build files have been written to: /Users/ahaque201/Github/libcertifier

If the steps above fail, you can create a file, called `build.sh` with
the following contents -

    #!/bin/bash
    export CC=/usr/bin/clang
    export OPENSSL_ROOT_DIR=/usr/local/mac-dev-env/openssl-3.5.0
    export CURL_ROOT_DIR=/usr/local/mac-dev-env/curl-7.69.1
    export CURL_INCLUDE_DIR=${CURL_ROOT_DIR}/include
    export CURL_LIBRARY_RELEASE=${CURL_ROOT_DIR}/lib/libcurl.dylib
    cmake . -DENABLE_MBEDTLS=OFF -DENABLE_CMAKE_VERBOSE_MAKEFILE=ON -DENABLE_CMOCKA=OFF -DENABLE_TESTS=ON -DOPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR} -DOPENSSL_INCLUDE_DIR=${OPENSSL_ROOT_DIR}/include -DCURL_INCLUDE_DIR=${CURL_INCLUDE_DIR} -DCURL_LIBRARY_RELEASE=${CURL_LIBRARY_RELEASE}

Please make sure the file is marked as executable
`chmod 755 ./build.sh`.

Reference -

    https://github.com/Kitware/CMake/blob/300979e7889b34d61803675c560fe450c7404447/Modules/FindOpenSSL.cmake

    https://github.com/Kitware/CMake/blob/300979e7889b34d61803675c560fe450c7404447/Modules/FindCURL.cmake

Then you can run it via `./build.sh` and then

     make clean

followed by -

    make

If you get symbols that cannot be referenced, check that CMake is using
the intended OpenSSL 3.5 headers and libraries rather than conflicting
include files (for example, under `/opt/local/include/openssl/`).

\#\# cURL (alternative) An alternative to building cURL is running the
following -

    brew install curl-openssl

\#\# mbedTLS mbedTLS is more straightforward.

You could use `brew install mbedtls` to install.
