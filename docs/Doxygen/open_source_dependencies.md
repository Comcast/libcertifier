\page docs/Doxygen/open_source_dependencies.md Open source dependencies
[Back to Manual](docs/Doxygen/libcertifier.md) 

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
<td><p><strong>3rd Party Library</strong></p></td>
<td><p><strong>URL</strong></p></td>
<td><p><strong>Version</strong></p></td>
<td><p><strong>License</strong></p></td>
<td><p><strong>Integration</strong></p></td>
<td><p><strong>Notes</strong></p></td>
<td><p><strong>Source File(s)</strong></p></td>
</tr>
<tr class="even">
<td><p>Open SSL</p></td>
<td><p><a href="https://www.openssl.org/" class="uri">https://www.openssl.org/</a></p></td>
<td><p>1.0.2 - 1.1.x</p></td>
<td><p>Apache License 2.0</p></td>
<td><p>Dynamic Link</p></td>
<td><p>Mutually exclusive with mbedTLS</p></td>
<td><p>N/A</p></td>
</tr>
<tr class="odd">
<td><p>mbedTLS</p></td>
<td><p><a href="https://tls.mbed.org/" class="uri">https://tls.mbed.org/</a></p></td>
<td><p>&gt;= 2.16.6</p></td>
<td><p>Dual-licensed with the Apache License version 2.0 (with GPLv2 also available).</p></td>
<td><p>Dynamic Link</p></td>
<td><p>Mutually exclusive with OpenSSL</p></td>
<td><p>N/A</p></td>
</tr>
<tr class="even">
<td><p>libCurl</p></td>
<td><p><a href="https://curl.haxx.se/" class="uri">https://curl.haxx.se/</a></p></td>
<td><p>&gt;= 76.0</p></td>
<td><p>Custom. Inspired by MIT/X</p></td>
<td><p>Dynamic Link</p></td>
<td></td>
<td><p>N/A</p></td>
</tr>
<tr class="odd">
<td><p>zLib</p></td>
<td><p><a href="https://www.zlib.net/" class="uri">https://www.zlib.net/</a></p></td>
<td></td>
<td><p>Custom. Is a permissive free software license which defines the terms under which the zlib software library can be distributed</p></td>
<td><p>Dynamic Link</p></td>
<td></td>
<td><p>N/A</p></td>
</tr>
<tr class="even">
<td><p>base58</p></td>
<td><p><a href="https://github.com/luke-jr/libbase58" class="uri">https://github.com/luke-jr/libbase58</a></p></td>
<td></td>
<td><p>MIT License</p></td>
<td><p>Embedded in source</p></td>
<td></td>
<td><p>base58.c</p></td>
</tr>
<tr class="odd">
<td><p>base64</p></td>
<td><p><a href="https://opensource.apple.com/source/QuickTimeStreamingServer/QuickTimeStreamingServer-452/CommonUtilitiesLib/base64.c" class="uri">https://opensource.apple.com/source/QuickTimeStreamingServer/QuickTimeStreamingServer-452/CommonUtilitiesLib/base64.c</a></p></td>
<td></td>
<td><p>Apple Public Source License 2.0</p></td>
<td><p>Embedded in source</p></td>
<td></td>
<td><p>base64.c</p></td>
</tr>
<tr class="even">
<td><p>rxi</p></td>
<td><p><a href="https://github.com/rxi/log.c" class="uri">https://github.com/rxi/log.c</a></p></td>
<td></td>
<td><p>MIT License</p></td>
<td><p>Embedded in source</p></td>
<td></td>
<td><p>log.c</p></td>
</tr>
<tr class="odd">
<td><p>parson</p></td>
<td><p><a href="http://kgabis.github.com/parson/" class="uri">http://kgabis.github.com/parson/</a></p></td>
<td></td>
<td><p>MIT License</p></td>
<td><p>Embedded in source</p></td>
<td></td>
<td><p>parson.c</p></td>
</tr>
<tr class="even">
<td><p>ripemd160</p></td>
<td><p><a href="https://github.com/trezor/trezor-crypto" class="uri">https://github.com/trezor/trezor-crypto</a></p></td>
<td></td>
<td><p>Apache License 2.0</p></td>
<td><p>Embedded in source</p></td>
<td></td>
<td><p>ripemd160.c</p></td>
</tr>
<tr class="odd">
<td><p>unity</p></td>
<td><p><a href="http://www.throwtheswitch.org/unity" class="uri">http://www.throwtheswitch.org/unity</a></p></td>
<td></td>
<td><p>MIT License</p></td>
<td><p>Embedded in source</p></td>
<td></td>
<td><p>tests.c</p></td>
</tr>
<tr class="even">
<td><p>cmocka</p></td>
<td><p><a href="https://cmocka.org/" class="uri">https://cmocka.org/</a></p></td>
<td><p>1.1</p></td>
<td><p>Apache License 2.0</p></td>
<td><p>Embedded in source</p></td>
<td></td>
<td><p>tests.c</p></td>
</tr>
</tbody>
</table>

\endhtmlonly

