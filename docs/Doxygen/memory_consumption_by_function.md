\page docs/Doxygen/memory_consumption_by_function.md Memory consumption by function
[Back to Manual](docs/Doxygen/libcertifier.md) 

The table below was the total heap memory allocated by function. This
did not include the local stack storage and did not include the code
size. The code size was static and that could be figured out from the
object files, or from the compiled binary.

We measured incremental heap memory usage by intercepting calls to
malloc() using LD\_PRELOAD.

This was tested on Linux on an x86 architecture with version
`0.1-052220 (opensource)` of libcertifier.

\htmlonly

<table style="width:100%;">
<colgroup>
<col width="14%" />
<col width="14%" />
<col width="14%" />
<col width="14%" />
<col width="14%" />
<col width="14%" />
<col width="14%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p><strong>Source File</strong></p></td>
<td><p><strong>Function</strong></p></td>
<td><p><strong>Function Description</strong></p></td>
<td><p><strong>Bytes</strong></p></td>
<td><p><strong>Kb</strong></p></td>
<td><p><strong>Arch</strong></p></td>
<td><p><strong>Notes</strong></p></td>
</tr>
<tr class="even">
<td><p>openssl.c</p></td>
<td><p><code>load_certs_from_pkcs7</code></p></td>
<td><p>This function takes in a PKCS7 PEM (from Certifier) and returns an X509_LIST structure (3 elements). The code parses the certificate.</p></td>
<td><p>45996</p></td>
<td><p>46</p></td>
<td><p>x86</p></td>
<td></td>
</tr>
<tr class="odd">
<td><p>openssl.c</p></td>
<td><p><code>security_find_or_create_keys</code></p></td>
<td><p>Generates an ECC keypair</p></td>
<td><p>8340</p></td>
<td><p>8</p></td>
<td><p>x86</p></td>
<td></td>
</tr>
<tr class="even">
<td><p>openssl.c</p></td>
<td><p><code>security_persist_pkcs_12_file</code></p></td>
<td><p>Persists PKCS12 file</p></td>
<td><p>28554</p></td>
<td><p>28.554</p></td>
<td><p>x86</p></td>
<td></td>
</tr>
<tr class="odd">
<td><p>security.c</p></td>
<td><p><code>security_generate_certificate_signing_request</code></p></td>
<td><p>Generates the certificate signing request (CSR). The output is a base64 encoded string.</p></td>
<td><p>4780</p></td>
<td><p>5</p></td>
<td><p>x86</p></td>
<td><p>OpenSSL</p></td>
</tr>
<tr class="even">
<td><p>certifierclient.c</p></td>
<td><p><code>certifierclient_request_x509_certificate</code></p></td>
<td><p>Makes an HTTPS call to Certifier for requesting an X509 certificate. Parameters are a b64 encoded CSR, node address, certifier id and other parameters. This returns the X509 PEM certificate.</p></td>
<td><p>3328618</p></td>
<td><p>3328.618</p></td>
<td><p>x86</p></td>
<td><p>OpenSSL</p></td>
</tr>
</tbody>
</table>

\endhtmlonly

