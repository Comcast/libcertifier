\page docs/Doxygen/development_quality.md Development quality
[Back to Manual](docs/Doxygen/libcertifier.md) 

Unit tests have the option of using cMocka or Unity. All unit tests are
located under the tests/folder. To enable unit testing, the following
build flag should be used when compiling libLedger() -

    -DENABLE_TESTS=ON

To enable CMocka -

    -DENABLE_CMOCKA=ON

To enable Unity -

    -DENABLE_CMOCKA=OFF

To run the unit tests after compiling, run `./certifierTests`. Sample
output below -

    [==========] Running 18 test(s).
    [ RUN      ] test_base64
    [       OK ] test_base64
    [ RUN      ] test_base58
    [       OK ] test_base58
    [ RUN      ] test_file_utils
    [       OK ] test_file_utils
    [ RUN      ] test_util_execute
    [       OK ] test_util_execute
    [ RUN      ] test_random_val
    [       OK ] test_random_val
    [ RUN      ] test_str_utils
    [       OK ] test_str_utils
    [ RUN      ] test_set_curl_error
    [       OK ] test_set_curl_error
    [ RUN      ] test_sha256_ripemd_b58
    [       OK ] test_sha256_ripemd_b58
    [ RUN      ] test_ecc_key
    [       OK ] test_ecc_key
    [ RUN      ] test_verify_signature_1
    [       OK ] test_verify_signature_1
    [ RUN      ] test_verify_signature_2
    [       OK ] test_verify_signature_2
    [ RUN      ] test_x509_cert
    [       OK ] test_x509_cert
    [ RUN      ] test_pkcs12
    [       OK ] test_pkcs12
    [ RUN      ] test_certifier_client_requests
    [       OK ] test_certifier_client_requests
    [ RUN      ] test_certifier_create_crt1
    [       OK ] test_certifier_create_crt1
    [ RUN      ] test_certifier_create_node_address
    [       OK ] test_certifier_create_node_address
    [ RUN      ] test_certifier_get_version
    [       OK ] test_certifier_get_version
    [ RUN      ] test_options
    [       OK ] test_options
    [==========] 18 test(s) run.
    [  PASSED  ] 18 test(s).
    [==========] Running 3 test(s).
    [ RUN      ] test_api_easy
    [       OK ] test_api_easy
    [ RUN      ] test_api_easy_create_tokens
    [       OK ] test_api_easy_create_tokens
    [ RUN      ] test_api_easy_cmdline
    [       OK ] test_api_easy_cmdline
    [==========] 3 test(s) run.
    [  PASSED  ] 3 test(s).

Functional tests are in the form of shell scripts. All functional tests
are located under the tests/functional folder. The functional tests are
based on certifierUtil ([CLI Usage](docs/Doxygen/cli_usage.md)). The structure of
the functional tests are below -

\htmlonly

<table>
<colgroup>
<col width="33%" />
<col width="33%" />
<col width="33%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p><strong>Script</strong></p></td>
<td><p><strong>Prerequisites</strong></p></td>
<td><p><strong>Notes</strong></p></td>
</tr>
<tr class="even">
<td><p><code>test-app-reg.sh</code></p></td>
<td></td>
<td></td>
</tr>
<tr class="odd">
<td><p><code>test-create-node-address.sh</code></p></td>
<td></td>
<td></td>
</tr>
<tr class="even">
<td><p><code>test-create-crt.sh</code></p></td>
<td></td>
<td></td>
</tr>
<tr class="odd">
<td><p><code>test-create-x509-crt.sh</code></p></td>
<td></td>
<td></td>
</tr>
<tr class="even">
<td><p><code>test-device-reg.sh</code></p></td>
<td></td>
<td></td>
</tr>
</tbody>
</table>

\endhtmlonly

The following script could be used (or customized, as needed) to run
Coverity against the source code -

    export COV_HOME=/Applications/cov-analysis-macosx-2019.06
    export PATH=$PATH:$COV_HOME/bin
    export COV_DIR=./tmp_coverity
    rm -Rf $COV_DIR
    mkdir $COV_DIR
    make clean
    rm -Rf ./CMakeCache.txt
    export CC=/usr/bin/clang
    cmake . -DENABLE_SSP=OFF -DENABLE_TESTS=OFF
    cov-build --dir $COV_DIR make
    cov-analyze --dir $COV_DIR --all --aggressiveness-level high --model-file ./coverity_models/__errno_location.xmldb
    cov-format-errors --dir $COV_DIR --html-output $COV_DIR/errors

The following build flag can be used to turn on Sanitizers

\htmlonly

<table>
<colgroup>
<col width="50%" />
<col width="50%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>-DCMAKE_BUILD_TYPE=asan</p></td>
<td><p>Address Sanitizer</p></td>
</tr>
<tr class="even">
<td><p>-DCMAKE_BUILD_TYPE=lsan</p></td>
<td><p>LeakSanitizer</p></td>
</tr>
<tr class="odd">
<td><p>-DCMAKE_BUILD_TYPE=ubsan</p></td>
<td><p>Undefined Behavior Sanitizer</p></td>
</tr>
</tbody>
</table>

\endhtmlonly

On our developer’s desktop, we utilize Valgrind for memory leak
detection. We run it with the following syntax -

    valgrind --tool=memcheck --track-origins=yes --leak-check=full --show-leak-kinds=all $1

Alternatively, Valgrind can be invoked for tests by the follwing command
(when not used together with Sanitizer build types) -

    ctest -T memcheck
