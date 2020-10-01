\page docs/Doxygen/error_codes.md Error Codes
[Back to Manual](docs/Doxygen/libcertifier.md) 

Error Codes
===========

libcertifier error codes can be found in
[/certifier/error.h](../internal_headers/certifier/error.h)

certifierUtil
=============

All errors in the [command-line interface (CLI)](docs/Doxygen/cli_usage.md) are in
JSON format and printed out to stderr. Example -

    {
        "return_code": 112422,
        "application_error_code": 22,
        "application_error_message": {
            "method": "certifierclient_request_x509_certificate",
            "error_message": "HTTP response code said error",
            "file": "\/Volumes\/comcast-development\/xh\/libcertifier\/src\/certifierclient.c",
            "line": 121,
            "http_code": 401,
            "curl_code": 22
        },
        "library_error_code": 0
    }

Library Error Codes
===================

The `library_error_code` returns the error code from an underlying
library, such as mbedTLS, OpenSSL, etc. The `library_error_message`,
when available, is the libraries error message for that error code. For
example, in mbedTLS, `library_error_message` is the equivalent of
calling the mbedTLS `strerror` tool.

Application Error Codes
=======================

mbedtls.c
---------

\htmlonly

<table>
<colgroup>
<col width="33%" />
<col width="33%" />
<col width="33%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p><strong>Error Code</strong></p></td>
<td><p><strong>Function(s)</strong></p></td>
<td><p><strong>Notes</strong></p></td>
</tr>
<tr class="even">
<td><p>-2000</p></td>
<td><p>security_init</p></td>
<td><p><code>mbedtls_ctr_drbg_seed()</code> failed in security_init()</p></td>
</tr>
<tr class="odd">
<td><p>-3000</p></td>
<td><p>ber_to_der</p></td>
<td><p>ASN parsing error, invalid input</p></td>
</tr>
<tr class="even">
<td><p>-3001</p></td>
<td><p>ber_to_der</p></td>
<td><p>out of memory error</p></td>
</tr>
<tr class="odd">
<td><p>-3002</p></td>
<td><p>ber_to_der</p></td>
<td><p>output buffer too small or input too large</p></td>
</tr>
<tr class="even">
<td><p>-3003</p></td>
<td><p>ber_to_der</p></td>
<td><p>Bad function argument provided</p></td>
</tr>
<tr class="odd">
<td><p>-3004</p></td>
<td><p>ber_to_der</p></td>
<td><p>Returning output length only</p></td>
</tr>
<tr class="even">
<td><p>-4000</p></td>
<td><p>persist_pkcs12</p></td>
<td><p><code>mbedtls_md_setup()</code> failed</p></td>
</tr>
<tr class="odd">
<td><p>-4001</p></td>
<td><p>persist_pkcs12</p></td>
<td><p>could not allocate enough memory for u16_pwd</p></td>
</tr>
<tr class="even">
<td><p>-4002</p></td>
<td><p>persist_pkcs12</p></td>
<td><p>could not allocate enough memory for buf</p></td>
</tr>
<tr class="odd">
<td><p>-4003</p></td>
<td><p>persist_pkcs12</p></td>
<td><p>could not allocate enough memory for cert_bag</p></td>
</tr>
<tr class="even">
<td><p>-4004</p></td>
<td><p>persist_pkcs12</p></td>
<td><p>could not allocate enough memory for key bag</p></td>
</tr>
<tr class="odd">
<td><p>-4005</p></td>
<td><p>persist_pkcs12</p></td>
<td><p>could not allocate enough memory for encrypted cert bag</p></td>
</tr>
<tr class="even">
<td><p>-4006</p></td>
<td><p>persist_pkcs12</p></td>
<td><p>could not allocate enough memory for encrypted key bag</p></td>
</tr>
<tr class="odd">
<td><p>-4007</p></td>
<td><p>persist_pkcs12</p></td>
<td><p><code>security_get_random_bytes()</code> call failed.</p></td>
</tr>
<tr class="even">
<td><p>-4008</p></td>
<td><p>persist_pkcs12</p></td>
<td><p><code>security_get_random_bytes()</code> call failed.</p></td>
</tr>
<tr class="odd">
<td><p>-4009</p></td>
<td><p>persist_pkcs12</p></td>
<td><p><code>security_get_random_bytes()</code> call failed.</p></td>
</tr>
<tr class="even">
<td><p>-4010</p></td>
<td><p>persist_pkcs12</p></td>
<td><p><code>security_get_random_bytes()</code> call failed.</p></td>
</tr>
<tr class="odd">
<td><p>-4011</p></td>
<td><p>persist_pkcs12</p></td>
<td><p><code>security_get_random_bytes()</code> call failed.</p></td>
</tr>
<tr class="even">
<td><p>-4012</p></td>
<td><p>persist_pkcs12</p></td>
<td><p><code>serialize_cert_bag()</code> len &lt;= 0</p></td>
</tr>
<tr class="odd">
<td><p>-4013</p></td>
<td><p>persist_pkcs12</p></td>
<td><p><code>encrypted_cert_bag_len</code> == 0</p></td>
</tr>
<tr class="even">
<td><p>-4014</p></td>
<td><p>persist_pkcs12</p></td>
<td><p><code>pkcs8_key_len</code> &lt;= 0</p></td>
</tr>
<tr class="odd">
<td><p>-4015</p></td>
<td><p>persist_pkcs12</p></td>
<td><p><code>mbedtls_mpi_add_int()</code> failed</p></td>
</tr>
<tr class="even">
<td><p>-4016</p></td>
<td><p>persist_pkcs12</p></td>
<td><p><code>mbedtls_md_hmac_starts()</code> failed</p></td>
</tr>
<tr class="odd">
<td><p>-4017</p></td>
<td><p>persist_pkcs12</p></td>
<td><p><code>mbedtls_md_hmac_update()</code> failed</p></td>
</tr>
<tr class="even">
<td><p>-4018</p></td>
<td><p>persist_pkcs12</p></td>
<td><p><code>mbedtls_md_hmac_finish()</code> failed</p></td>
</tr>
<tr class="odd">
<td><p>-5000</p></td>
<td><p>parse_certificate_list</p></td>
<td><p><code>mbedtls_asn1_get_tag()</code> in 1 failure</p></td>
</tr>
<tr class="even">
<td><p>-5001</p></td>
<td><p>parse_certificate_list</p></td>
<td><p><code>asn1_confirm_oid()</code> in 1 failure</p></td>
</tr>
<tr class="odd">
<td><p>-5002</p></td>
<td><p>parse_certificate_list</p></td>
<td><p><code>mbedtls_asn1_get_tag()</code> in 2 failure</p></td>
</tr>
<tr class="even">
<td><p>-5003</p></td>
<td><p>parse_certificate_list</p></td>
<td><p><code>mbedtls_asn1_get_tag()</code> in 3 failure</p></td>
</tr>
<tr class="odd">
<td><p>-5004</p></td>
<td><p>parse_certificate_list</p></td>
<td><p><code>asn1_confirm_oid()</code> in 2 failure</p></td>
</tr>
<tr class="even">
<td><p>-5005</p></td>
<td><p>parse_certificate_list</p></td>
<td><p><code>mbedtls_asn1_get_tag()</code> in 4 failure</p></td>
</tr>
<tr class="odd">
<td><p>-5006</p></td>
<td><p>parse_certificate_list</p></td>
<td><p><code>mbedtls_asn1_get_tag()</code> in 5 failure</p></td>
</tr>
<tr class="even">
<td><p>-6000</p></td>
<td><p>parse_pkcs12</p></td>
<td><p>null pkcs12 file</p></td>
</tr>
<tr class="odd">
<td><p>-6001</p></td>
<td><p>parse_pkcs12</p></td>
<td><p>file length of pkcs 12 file &lt; 0</p></td>
</tr>
<tr class="even">
<td><p>-6002</p></td>
<td><p>parse_pkcs12</p></td>
<td><p>could not allocate enough memory for pkcs12_data</p></td>
</tr>
<tr class="odd">
<td><p>-6003</p></td>
<td><p>parse_pkcs12</p></td>
<td><p>got != file_len during fread of pkcs12</p></td>
</tr>
<tr class="even">
<td><p>-6004</p></td>
<td><p>parse_pkcs12</p></td>
<td><p><code>mbedtls_asn1_get_tag()</code> failure</p></td>
</tr>
<tr class="odd">
<td><p>-6005</p></td>
<td><p>parse_pkcs12</p></td>
<td><p><code>mbedtls_asn1_get_int()</code> failure on pkcs7 version</p></td>
</tr>
<tr class="even">
<td><p>-6006</p></td>
<td><p>parse_pkcs12</p></td>
<td><p>pkcs7 version was not 3</p></td>
</tr>
<tr class="odd">
<td><p>-6007</p></td>
<td><p>parse_pkcs12</p></td>
<td><p><code>mbedtls_asn1_get_tag()</code> failure</p></td>
</tr>
<tr class="even">
<td><p>-6008</p></td>
<td><p>parse_pkcs12</p></td>
<td><p><code>asn1_confirm_oid()</code> failure</p></td>
</tr>
<tr class="odd">
<td><p>-6009</p></td>
<td><p>parse_pkcs12</p></td>
<td><p><code>mbedtls_asn1_get_tag()</code> failure</p></td>
</tr>
<tr class="even">
<td><p>-6010</p></td>
<td><p>parse_pkcs12</p></td>
<td><p><code>mbedtls_asn1_get_tag()</code> failure</p></td>
</tr>
<tr class="odd">
<td><p>-6011</p></td>
<td><p>parse_pkcs12</p></td>
<td><p><code>mbedtls_asn1_get_tag()</code> failure</p></td>
</tr>
<tr class="even">
<td><p>-6012</p></td>
<td><p>parse_pkcs12</p></td>
<td><p><code>mbedtls_asn1_get_tag()</code> failure</p></td>
</tr>
<tr class="odd">
<td><p>-6013</p></td>
<td><p>parse_pkcs12</p></td>
<td><p><code>asn1_confirm_oid()</code> failure</p></td>
</tr>
<tr class="even">
<td><p>-6014</p></td>
<td><p>parse_pkcs12</p></td>
<td><p><code>mbedtls_asn1_get_tag()</code> failure</p></td>
</tr>
<tr class="odd">
<td><p>-6015</p></td>
<td><p>parse_pkcs12</p></td>
<td><p><code>mbedtls_asn1_get_tag()</code> failure</p></td>
</tr>
<tr class="even">
<td><p>-6016</p></td>
<td><p>parse_pkcs12</p></td>
<td><p><code>mbedtls_asn1_get_int()</code> failure on pkcs7 version</p></td>
</tr>
<tr class="odd">
<td><p>-6017</p></td>
<td><p>parse_pkcs12</p></td>
<td><p>pkcs7 version was not zero</p></td>
</tr>
<tr class="even">
<td><p>-6018</p></td>
<td><p>parse_pkcs12</p></td>
<td><p><code>mbedtls_asn1_get_tag()</code> failure</p></td>
</tr>
<tr class="odd">
<td><p>-6019</p></td>
<td><p>parse_pkcs12</p></td>
<td><p><code>asn1_confirm_oid()</code> failure</p></td>
</tr>
<tr class="even">
<td><p>-6020</p></td>
<td><p>parse_pkcs12</p></td>
<td><p><code>mbedtls_asn1_get_alg()</code> failure</p></td>
</tr>
<tr class="odd">
<td><p>-6021</p></td>
<td><p>parse_pkcs12</p></td>
<td><p><code>MBEDTLS_OID_CMP</code> failure</p></td>
</tr>
<tr class="even">
<td><p>-6022</p></td>
<td><p>parse_pkcs12</p></td>
<td><p><code>mbedtls_asn1_get_tag()</code> failure</p></td>
</tr>
<tr class="odd">
<td><p>-6023</p></td>
<td><p>parse_pkcs12</p></td>
<td><p><code>test_pkcs5_pbes2()</code> failure</p></td>
</tr>
<tr class="even">
<td><p>-6024</p></td>
<td><p>parse_pkcs12</p></td>
<td><p><code>mbedtls_asn1_get_tag()</code> failure</p></td>
</tr>
<tr class="odd">
<td><p>-6025</p></td>
<td><p>parse_pkcs12</p></td>
<td><p><code>asn1_confirm_oid()</code> failure</p></td>
</tr>
<tr class="even">
<td><p>-6026</p></td>
<td><p>parse_pkcs12</p></td>
<td><p><code>mbedtls_asn1_get_tag()</code> failure</p></td>
</tr>
<tr class="odd">
<td><p>-6027</p></td>
<td><p>parse_pkcs12</p></td>
<td><p><code>mbedtls_asn1_get_tag()</code> failure</p></td>
</tr>
<tr class="even">
<td><p>-6028</p></td>
<td><p>parse_pkcs12</p></td>
<td><p><code>parse_shrouded_pkcs12_key()</code> failure</p></td>
</tr>
<tr class="odd">
<td><p>-7000</p></td>
<td><p>load_certs_from_pkcs7</p></td>
<td><p>X509 list passed in was null</p></td>
</tr>
<tr class="even">
<td><p>-7001</p></td>
<td><p>load_certs_from_pkcs7</p></td>
<td><p><code>mbedtls_pem_read_buffer()</code> returned non zero</p></td>
</tr>
<tr class="odd">
<td><p>-7002</p></td>
<td><p>load_certs_from_pkcs7</p></td>
<td><p>Could not allocate enough memory for der</p></td>
</tr>
<tr class="even">
<td><p>-7003</p></td>
<td><p>load_certs_from_pkcs7</p></td>
<td><p><code>mbedtls_asn1_get_tag()</code> failed</p></td>
</tr>
<tr class="odd">
<td><p>-7004</p></td>
<td><p>load_certs_from_pkcs7</p></td>
<td><p><code>mbedtls_asn1_get_tag()</code> failed</p></td>
</tr>
<tr class="even">
<td><p>-7005</p></td>
<td><p>load_certs_from_pkcs7</p></td>
<td><p><code>mbedtls_asn1_get_tag()</code> failed</p></td>
</tr>
<tr class="odd">
<td><p>-7006</p></td>
<td><p>load_certs_from_pkcs7</p></td>
<td><p><code>mbedtls_asn1_get_tag()</code> failed</p></td>
</tr>
<tr class="even">
<td><p>-7007</p></td>
<td><p>load_certs_from_pkcs7</p></td>
<td><p><code>mbedtls_asn1_get_int()</code> failed</p></td>
</tr>
<tr class="odd">
<td><p>-7008</p></td>
<td><p>load_certs_from_pkcs7</p></td>
<td><p><code>pkcs7_version</code> != 1</p></td>
</tr>
<tr class="even">
<td><p>-7009</p></td>
<td><p>load_certs_from_pkcs7</p></td>
<td><p><code>mbedtls_asn1_get_tag()</code> failed</p></td>
</tr>
<tr class="odd">
<td><p>-7010</p></td>
<td><p>load_certs_from_pkcs7</p></td>
<td><p><code>mbedtls_asn1_get_tag()</code> failed</p></td>
</tr>
<tr class="even">
<td><p>-7011</p></td>
<td><p>load_certs_from_pkcs7</p></td>
<td><p><code>asn1_confirm_oid()</code> failed</p></td>
</tr>
<tr class="odd">
<td><p>-7012</p></td>
<td><p>load_certs_from_pkcs7</p></td>
<td><p>Could not allocate enough memory for certs</p></td>
</tr>
<tr class="even">
<td><p>-7013</p></td>
<td><p>load_certs_from_pkcs7</p></td>
<td><p><code>mbedtls_asn1_get_tag()</code> failed</p></td>
</tr>
<tr class="odd">
<td><p>-7014</p></td>
<td><p>load_certs_from_pkcs7</p></td>
<td><p><code>mbedtls_x509_crt_parse_der()</code> failed</p></td>
</tr>
<tr class="even">
<td><p>-8000</p></td>
<td><p>load_certs_from_certificate</p></td>
<td><p>x509 list passed in was null</p></td>
</tr>
<tr class="odd">
<td><p>-8001</p></td>
<td><p>load_certs_from_certificate</p></td>
<td><p><code>mbedtls_pem_read_buffer()</code> returned non zero</p></td>
</tr>
<tr class="even">
<td><p>-8002</p></td>
<td><p>load_certs_from_certificate</p></td>
<td><p>could not allocate enough memory for certs</p></td>
</tr>
<tr class="odd">
<td><p>-8003</p></td>
<td><p>load_certs_from_certificate</p></td>
<td><p><code>mbedtls_x509_crt_parse_der()</code> returned non zero</p></td>
</tr>
<tr class="even">
<td><p>-9000</p></td>
<td><p>check_x509_valid_range</p></td>
<td><p><code>+sim_time_len &lt;= 0 || sim_time_len &gt; 17+</code></p></td>
</tr>
<tr class="odd">
<td><p>-9001</p></td>
<td><p>check_x509_valid_range</p></td>
<td><p><code>read_sim_time()</code> failure</p></td>
</tr>
<tr class="even">
<td><p>-9002</p></td>
<td><p>check_x509_valid_range</p></td>
<td><p><code>x509_time_cmp_timet()</code> failure</p></td>
</tr>
<tr class="odd">
<td><p>-9003</p></td>
<td><p>check_x509_valid_range</p></td>
<td><p><code>x509_time_cmp_timet()</code> failure</p></td>
</tr>
<tr class="even">
<td><p>-9004</p></td>
<td><p>check_x509_valid_range</p></td>
<td><p><code>read_sim_time()</code> failure</p></td>
</tr>
<tr class="odd">
<td><p>-9005</p></td>
<td><p>check_x509_valid_range</p></td>
<td><p><code>x509_time_cmp_timet()</code> failure</p></td>
</tr>
<tr class="even">
<td><p>-9006</p></td>
<td><p>check_x509_valid_range</p></td>
<td><p><code>x509_time_cmp_timet()</code> failure</p></td>
</tr>
<tr class="odd">
<td><p>-9007</p></td>
<td><p>check_x509_valid_range</p></td>
<td><p><code>diff_day * SECS_IN_DAY + diff_sec) &lt; min_secs_left</code></p></td>
</tr>
<tr class="even">
<td><p>-9008</p></td>
<td><p>check_x509_valid_range</p></td>
<td><p><code>+(sim_time_len &lt;= 0 || sim_time_len &gt; 17)+</code></p></td>
</tr>
<tr class="odd">
<td><p>-10000</p></td>
<td><p>read_sim_time</p></td>
<td><p><code>mbedtls_x509_get_time()</code> failure</p></td>
</tr>
<tr class="even">
<td><p>-10001</p></td>
<td><p>read_sim_time</p></td>
<td><p><code>mbedtls_x509_get_time()</code> failure</p></td>
</tr>
</tbody>
</table>

\endhtmlonly

certifier.c
-----------

Function - certifier_init
--------------------------

\htmlonly

<table>
<colgroup>
<col width="33%" />
<col width="33%" />
<col width="33%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p><strong>Error Code</strong></p></td>
<td><p><strong>Function(s)</strong></p></td>
<td><p><strong>Notes</strong></p></td>
</tr>
<tr class="even">
<td><p>0</p></td>
<td><p>certifier_init</p></td>
<td><p>No Error. The operation completed successfully.</p></td>
</tr>
<tr class="odd">
<td><p>1000X</p></td>
<td><p>certifier_init</p></td>
<td><p>These series of errors have to do with problems initializing the certifier client, most likely with libcurl.</p></td>
</tr>
<tr class="even">
<td><p>3000X</p></td>
<td><p>certifier_init</p></td>
<td><p>These series of errors have to do with problems initializing the security impl (Open SSL).</p></td>
</tr>
<tr class="odd">
<td><p>4000X</p></td>
<td><p>certifier_init</p></td>
<td><p>These series of errors have to do with problems initializing the camera client.</p></td>
</tr>
<tr class="even">
<td><p>4500X</p></td>
<td><p>certifier_init</p></td>
<td><p>These series of errors have to do with problems initializing the default properties.</p></td>
</tr>
</tbody>
</table>

\endhtmlonly

Function - certifier_destroy
-----------------------------

\htmlonly

<table>
<colgroup>
<col width="33%" />
<col width="33%" />
<col width="33%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p><strong>Error Code</strong></p></td>
<td><p><strong>Function(s)</strong></p></td>
<td><p><strong>Notes</strong></p></td>
</tr>
<tr class="even">
<td><p>0</p></td>
<td><p>certifier_destroy</p></td>
<td><p>No Error. The operation completed successfully.</p></td>
</tr>
<tr class="odd">
<td><p>5000X</p></td>
<td><p>certifier_destroy</p></td>
<td><p>These series of errors have to do with problems uninitializing the certifier client, most likely with libcurl.</p></td>
</tr>
<tr class="even">
<td><p>7000X</p></td>
<td><p>certifier_destroy</p></td>
<td><p>These series of errors have to do with problems uninitializing the security impl (Open SSL).</p></td>
</tr>
<tr class="odd">
<td><p>7500X</p></td>
<td><p>certifier_destroy</p></td>
<td><p>These series of errors have to do with problems uninitializing the camera client.</p></td>
</tr>
<tr class="even">
<td><p>7800X</p></td>
<td><p>certifier_destroy</p></td>
<td><p>These series of errors have to do with problems uninitializing the log impl.</p></td>
</tr>
</tbody>
</table>

\endhtmlonly

Functions - certifier_set_property, certifier_set_property_int, certifier_set_default_properties_from_cfg_file
-------------------------------------------------------------------------------------------------------------------------

\htmlonly

<table>
<colgroup>
<col width="33%" />
<col width="33%" />
<col width="33%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p><strong>Error Code</strong></p></td>
<td><p><strong>Function(s)</strong></p></td>
<td><p><strong>Notes</strong></p></td>
</tr>
<tr class="even">
<td><p>0</p></td>
<td><p>certifier_set_property, certifier_set_property_int, certifier_set_default_properties_from_cfg_file</p></td>
<td><p>No Error. The operation completed successfully.</p></td>
</tr>
<tr class="odd">
<td><p>27001</p></td>
<td><p>certifier_set_property, certifier_set_property_int, certifier_set_default_properties_from_cfg_file</p></td>
<td><p>Property value is empty.</p></td>
</tr>
<tr class="even">
<td><p>27002</p></td>
<td><p>certifier_set_property, certifier_set_property_int, certifier_set_default_properties_from_cfg_file</p></td>
<td><p>Property Name is &lt;= 0.</p></td>
</tr>
<tr class="odd">
<td><p>27003</p></td>
<td><p>certifier_set_property, certifier_set_property_int, certifier_set_default_properties_from_cfg_file</p></td>
<td><p>String length of property value &gt;= property buffer size.</p></td>
</tr>
<tr class="even">
<td><p>27004</p></td>
<td><p>certifier_set_property, certifier_set_property_int, certifier_set_default_properties_from_cfg_file</p></td>
<td><p>Property integer value &lt; 0.</p></td>
</tr>
<tr class="odd">
<td><p>27005</p></td>
<td><p>certifier_set_property, certifier_set_property_int, certifier_set_default_properties_from_cfg_file</p></td>
<td><p>Unrecognized Property name in property_set_int (1).</p></td>
</tr>
<tr class="even">
<td><p>27006</p></td>
<td><p>certifier_set_property, certifier_set_property_int, certifier_set_default_properties_from_cfg_file</p></td>
<td><p>Unrecognized Property name in property_set_int (1).</p></td>
</tr>
<tr class="odd">
<td><p>27007</p></td>
<td><p>certifier_set_property, certifier_set_property_int, certifier_set_default_properties_from_cfg_file</p></td>
<td><p>https:// is only supported for LEDGER_OPT_CERTIFIER_URL.</p></td>
</tr>
<tr class="even">
<td><p>27009</p></td>
<td><p>certifier_set_property, certifier_set_property_int, certifier_set_default_properties_from_cfg_file</p></td>
<td><p>Log File could not be opened for append mode.</p></td>
</tr>
<tr class="odd">
<td><p>27010</p></td>
<td><p>certifier_set_property, certifier_set_property_int, certifier_set_default_properties_from_cfg_file</p></td>
<td><p>Unrecognized Property name in property_set (1).</p></td>
</tr>
<tr class="even">
<td><p>27011</p></td>
<td><p>certifier_set_property, certifier_set_property_int, certifier_set_default_properties_from_cfg_file</p></td>
<td><p>Error setting file pointer to log.</p></td>
</tr>
</tbody>
</table>

\endhtmlonly

#  Function - certifier_register

\htmlonly

<table>
<colgroup>
<col width="33%" />
<col width="33%" />
<col width="33%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p><strong>Error Code</strong></p></td>
<td><p><strong>Function</strong></p></td>
<td><p><strong>Notes</strong></p></td>
</tr>
<tr class="even">
<td><p>0</p></td>
<td><p>certifier_register</p></td>
<td><p>No Error. The operation completed successfully.</p></td>
</tr>
<tr class="odd">
<td><p>3</p></td>
<td><p>certifier_register</p></td>
<td><p>Occurs when it could not extract the certifier_id from the x509.</p></td>
</tr>
<tr class="even">
<td><p>9000</p></td>
<td><p>certifier_register</p></td>
<td><p>Occurs when there was trouble generating a CSR.</p></td>
</tr>
<tr class="odd">
<td><p>9001</p></td>
<td><p>certifier_register</p></td>
<td><p>Occurs when trying to parse a PKCS 7 to get a list of certificates, but cannot for some reason.</p></td>
</tr>
<tr class="even">
<td><p>9003</p></td>
<td><p>certifier_register</p></td>
<td><p>Occurs when there is trouble persisting the .p12 file to disk.</p></td>
</tr>
<tr class="odd">
<td><p>9004</p></td>
<td><p>certifier_register</p></td>
<td><p>Occurs when there is already a .p12 file, and trying to delete this file in the case of a rename operation (like force registration).</p></td>
</tr>
<tr class="even">
<td><p>9005</p></td>
<td><p>certifier_register</p></td>
<td><p>Occurs when there is already a .p12 file, and trying to rename this file in the case of a rename operation (like force registration).</p></td>
</tr>
<tr class="odd">
<td><p>9006</p></td>
<td><p>certifier_register</p></td>
<td><p>Occurs when there is already a .p12 file, and trying to delete this file in the case of a rename operation (like force registration).</p></td>
</tr>
<tr class="even">
<td><p>9007</p></td>
<td><p>certifier_register</p></td>
<td><p>Occurs when there is already a .p12 file, and trying to rename this file in the case of a rename operation (like force registration).</p></td>
</tr>
<tr class="odd">
<td><p>11001</p></td>
<td><p>certifier_register</p></td>
<td><p>Occurs when calling certifier_private_setup_keys function and trouble opening up the .p12 (perhaps different password).</p></td>
</tr>
<tr class="even">
<td><p>11003</p></td>
<td><p>certifier_register</p></td>
<td><p>Occurs when calling certifier_private_setup_keys function and trouble generating a node address.</p></td>
</tr>
<tr class="odd">
<td><p>11004</p></td>
<td><p>certifier_register</p></td>
<td><p>Occurs when calling certifier_private_setup_keys function and when p12 filename is empty.</p></td>
</tr>
<tr class="even">
<td><p>11005</p></td>
<td><p>certifier_register</p></td>
<td><p>Occurs when calling certifier_private_setup_keys function and when p12 password is empty.</p></td>
</tr>
<tr class="odd">
<td><p>11006</p></td>
<td><p>certifier_register</p></td>
<td><p>Occurs when calling certifier_private_setup_keys function and when ecc curve name is empty.</p></td>
</tr>
<tr class="even">
<td><p>12003</p></td>
<td><p>certifier_register</p></td>
<td><p>Trouble with HTTPS call to Certifier - the URL was not properly formatted for certifier.url?</p></td>
</tr>
<tr class="odd">
<td><p>12004</p></td>
<td><p>certifier_register</p></td>
<td><p>Trouble with HTTPS call to Certifier - A requested feature, protocol or option was not found built-in in this libcurl due to a build-time decision. This means that a feature or option was not enabled or explicitly disabled when libcurl was built and in order to get it to function you have to get a rebuilt libcurl.</p></td>
</tr>
<tr class="even">
<td><p>12006</p></td>
<td><p>certifier_register</p></td>
<td><p>Trouble with HTTPS call to Certifier - Couldn’t resolve host. The given remote host was not resolved.</p></td>
</tr>
<tr class="odd">
<td><p>12007</p></td>
<td><p>certifier_register</p></td>
<td><p>Trouble with HTTPS call to Certifier - Failed to connect to host</p></td>
</tr>
<tr class="even">
<td><p>12010</p></td>
<td><p>certifier_register</p></td>
<td><p>Could not generate milliseconds</p></td>
</tr>
<tr class="odd">
<td><p>12022</p></td>
<td><p>certifier_register</p></td>
<td><p>Trouble with HTTPS call to Certifier - this occurs when an HTTP response code &gt;=400 occurs.</p></td>
</tr>
<tr class="even">
<td><p>12023</p></td>
<td><p>certifier_register</p></td>
<td><p>Trouble with HTTPS call to Certifier - An error occurred when writing received data to a local file, or an error was returned to libcurl from a write callback.</p></td>
</tr>
<tr class="odd">
<td><p>12026</p></td>
<td><p>certifier_register</p></td>
<td><p>Trouble with HTTPS call to Certifier - There was a problem reading a local file or an error returned by the read callback.</p></td>
</tr>
<tr class="even">
<td><p>12027</p></td>
<td><p>certifier_register</p></td>
<td><p>Trouble with HTTPS call to Certifier - A memory allocation request failed. This is serious badness and things are severely screwed up if this ever occurs.</p></td>
</tr>
<tr class="odd">
<td><p>12028</p></td>
<td><p>certifier_register</p></td>
<td><p>Trouble with HTTPS call to Certifier - Operation timeout. The specified time-out period was reached according to the conditions.</p></td>
</tr>
<tr class="even">
<td><p>12033</p></td>
<td><p>certifier_register</p></td>
<td><p>Trouble with HTTPS call to Certifier - The server does not support or accept range requests.</p></td>
</tr>
<tr class="odd">
<td><p>12034</p></td>
<td><p>certifier_register</p></td>
<td><p>Trouble with HTTPS call to Certifier - This is an odd error that mainly occurs due to internal confusion.</p></td>
</tr>
<tr class="even">
<td><p>12035</p></td>
<td><p>certifier_register</p></td>
<td><p>Trouble with HTTPS call to Certifier - A problem occurred somewhere in the SSL/TLS handshake. You really want the error buffer and read the message there as it pinpoints the problem slightly more. Could be certificates (file formats, paths, permissions), passwords, and others.</p></td>
</tr>
<tr class="odd">
<td><p>12051</p></td>
<td><p>certifier_register</p></td>
<td><p>Trouble with HTTPS call to Certifier - The remote server’s SSL certificate or SSH md5 fingerprint was deemed not OK.</p></td>
</tr>
<tr class="even">
<td><p>12053</p></td>
<td><p>certifier_register</p></td>
<td><p>Trouble with HTTPS call to Certifier - The specified crypto engine wasn’t found.</p></td>
</tr>
<tr class="odd">
<td><p>12054</p></td>
<td><p>certifier_register</p></td>
<td><p>Trouble with HTTPS call to Certifier - Failed setting the selected SSL crypto engine as default!</p></td>
</tr>
<tr class="even">
<td><p>12055</p></td>
<td><p>certifier_register</p></td>
<td><p>Trouble with HTTPS call to Certifier - Failed sending network data.</p></td>
</tr>
<tr class="odd">
<td><p>12056</p></td>
<td><p>certifier_register</p></td>
<td><p>Trouble with HTTPS call to Certifier - Failed receiving network data.</p></td>
</tr>
<tr class="even">
<td><p>12058</p></td>
<td><p>certifier_register</p></td>
<td><p>Trouble with HTTPS call to Certifier - problem with the local client certificate.</p></td>
</tr>
<tr class="odd">
<td><p>12059</p></td>
<td><p>certifier_register</p></td>
<td><p>Trouble with HTTPS call to Certifier - Couldn’t use specified cipher.</p></td>
</tr>
<tr class="even">
<td><p>12060</p></td>
<td><p>certifier_register</p></td>
<td><p>Trouble with HTTPS call to Certifier - Peer certificate cannot be authenticated with known CA certificates.</p></td>
</tr>
<tr class="odd">
<td><p>12061</p></td>
<td><p>certifier_register</p></td>
<td><p>Trouble with HTTPS call to Certifier - Unrecognized transfer encoding.</p></td>
</tr>
<tr class="even">
<td><p>12063</p></td>
<td><p>certifier_register</p></td>
<td><p>Trouble with HTTPS call to Certifier - Maximum file size exceeded.</p></td>
</tr>
<tr class="odd">
<td><p>12065</p></td>
<td><p>certifier_register</p></td>
<td><p>Trouble with HTTPS call to Certifier - When doing a send operation curl had to rewind the data to retransmit, but the rewinding operation failed.</p></td>
</tr>
<tr class="even">
<td><p>12066</p></td>
<td><p>certifier_register</p></td>
<td><p>Trouble with HTTPS call to Certifier - Initiating the SSL Engine failed.</p></td>
</tr>
<tr class="odd">
<td><p>12077</p></td>
<td><p>certifier_register</p></td>
<td><p>Trouble with HTTPS call to Certifier - Problem with reading the SSL CA cert (path? access rights?).</p></td>
</tr>
<tr class="even">
<td><p>12080</p></td>
<td><p>certifier_register</p></td>
<td><p>Trouble with HTTPS call to Certifier - Failed to shut down the SSL connection.</p></td>
</tr>
<tr class="odd">
<td><p>12082</p></td>
<td><p>certifier_register</p></td>
<td><p>Trouble with HTTPS call to Certifier - Failed to load CRL file.</p></td>
</tr>
<tr class="even">
<td><p>12083</p></td>
<td><p>certifier_register</p></td>
<td><p>Trouble with HTTPS call to Certifier - Issuer check failed.</p></td>
</tr>
<tr class="odd">
<td><p>14001</p></td>
<td><p>certifier_register</p></td>
<td><p>Trouble when calling security_generate_x509_crt and generating CRT nonce</p></td>
</tr>
</tbody>
</table>

\endhtmlonly
