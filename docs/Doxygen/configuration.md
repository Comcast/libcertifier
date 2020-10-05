\page docs/Doxygen/configuration.md Configuration
[Back to Manual](docs/Doxygen/libcertifier.md)

Configuration
=============

\htmlonly

<table>
<colgroup>
<col width="33%" />
<col width="33%" />
<col width="33%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p><strong>Property Name</strong></p></td>
<td><p><strong>Default Value</strong></p></td>
<td><p><strong>Description</strong></p></td>
</tr>
<tr class="even">
<td><p>libcertifier.cert.min_time_left_s</p></td>
<td><p>604800</p></td>
<td></td>
</tr>
<tr class="odd">
<td><p>libcertifier.certifier.url</p></td>
<td><p><a href="https://certifier.xpki.io/v1/certifier/certificate" class="uri">https://certifier.xpki.io/v1/certifier/certificate</a></p></td>
<td></td>
</tr>
<tr class="even">
<td><p>libcertifier.num.days</p></td>
<td><p>365</p></td>
<td></td>
</tr>
<tr class="odd">
<td><p>libcertifier.disable.auto.renewal</p></td>
<td><p>0</p></td>
<td></td>
</tr>
<tr class="even">
<td><p>libcertifier.ecc.curve.id</p></td>
<td><p>prime256v1</p></td>
<td></td>
</tr>
<tr class="odd">
<td><p>libcertifier.http.connect.timeout</p></td>
<td><p>10</p></td>
<td></td>
</tr>
<tr class="even">
<td><p>libcertifier.http.timeout</p></td>
<td><p>10</p></td>
<td></td>
</tr>
<tr class="odd">
<td><p>libcertifier.http.trace</p></td>
<td><p>0</p></td>
<td></td>
</tr>
<tr class="even">
<td><p>libcertifier.int.ca</p></td>
<td><p>prime256v1</p></td>
<td></td>
</tr>
<tr class="odd">
<td><p>libcertifier.ecc.curve.id</p></td>
<td><p><code>-----BEGIN CERTIFICATE-----\nMIIBvDCCAWKgAwIBAgIILYozPqRVXXwwCgYIKoZIzj0EAwIwMDEuMCwGA1UEAwwl\nWGZpbml0eSBTdWJzY3JpYmVyIEVDQyBDbGFzcyBJSUkgUm9vdDAeFw0xOTA0MDQx\nNzA5NDlaFw00NDAzMjgxNzA5NDlaMDAxLjAsBgNVBAMMJVhmaW5pdHkgU3Vic2Ny\naWJlciBFQ0MgQ2xhc3MgSUlJIFJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC\nAAT+6HxsHxMJleLuNhlbC8QImb0rN3/1imQQrNAvRz6L5Cr9ELkXmmC+4fopTk+K\nKgmEsmZ19Eb7I1ZtUDQGEHomo2YwZDASBgNVHRMBAf8ECDAGAQH/AgEBMB8GA1Ud\nIwQYMBaAFEKPSE8KFTbOPJRbagklXxMZoVRoMB0GA1UdDgQWBBRCj0hPChU2zjyU\nW2oJJV8TGaFUaDAOBgNVHQ8BAf8EBAMCAYYwCgYIKoZIzj0EAwIDSAAwRQIhAKMr\nI0kLwf8cZab2aCXk25NQdOKhczQa8bbiplWsbdODAiBkJv+nhWCxiC3WWS6bHz/1\nqhgaI6GMwrYxrvkX1OL0BA==\n-----END CERTIFICATE-----\n</code></p></td>
<td></td>
</tr>
<tr class="even">
<td><p>libcertifier.keystore</p></td>
<td><p>lrg</p></td>
<td></td>
</tr>
<tr class="odd">
<td><p>libcertifier.log.file</p></td>
<td><p>/tmp/libcertifier.log</p></td>
<td></td>
</tr>
<tr class="even">
<td><p>libcertifier.log.level</p></td>
<td><p>0</p></td>
<td></td>
</tr>
<tr class="odd">
<td><p>libcertifier.log.max.size</p></td>
<td><p>5000000</p></td>
<td></td>
</tr>
<tr class="even">
<td><p>libcertifier.measure.performance</p></td>
<td><p>0</p></td>
<td></td>
</tr>
<tr class="odd">
<td><p>libcertifier.password</p></td>
<td><p>changeit</p></td>
<td></td>
</tr>
<tr class="even">
<td><p>libcertifier.root.ca</p></td>
<td><p><code>-----BEGIN CERTIFICATE-----\nMIIBtDCCAVqgAwIBAgIUYvPZjjnyEEDek8yWYoM2GMIgnMUwCgYIKoZIzj0EAwIw\nJjEkMCIGA1UEAwwbWGZpbml0eSBTdWJzY3JpYmVyIEVDQyBSb290MB4XDTE5MTAw\nNzE4MzIwOFoXDTQ0MDkzMDE4MzIwOFowJjEkMCIGA1UEAwwbWGZpbml0eSBTdWJz\nY3JpYmVyIEVDQyBSb290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZuTzvLrO\n+7G2+Ylr4O2PHMibVq1qVJMzKvQtJ8JAe1DL0HkJXRnliWT1QC5iqJuaA4Ngh31T\nj2T1tOJcYr6B36NmMGQwEgYDVR0TAQH/BAgwBgEB/wIBATAfBgNVHSMEGDAWgBSV\nn8KUP9J2ueLExe2EjezHdq/fpzAdBgNVHQ4EFgQUlZ/ClD/SdrnixMXthI3sx3av\n36cwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMCA0gAMEUCICpOBWu6UWgEIigH\n35DeYeNyAZHsGRv6/enBvbmQUzGFAiEAgR4Dhur1nQO1NSDwkHQeUsz3HV5Ahpgn\n5eHkhyAn2S0=\n-----END CERTIFICATE-----\n</code></p></td>
<td></td>
</tr>
<tr class="odd">
<td><p>libcertifier.source.name</p></td>
<td><p>libcertifier-opensource</p></td>
<td></td>
</tr>
<tr class="even">
<td><p>libcertifier.system.id</p></td>
<td><p>default_system_id</p></td>
<td></td>
</tr>
<tr class="odd">
<td><p>libcertifier.tls.insecure.host</p></td>
<td><p>0</p></td>
<td></td>
</tr>
<tr class="even">
<td><p>libcertifier.tls.insecure.peer</p></td>
<td><p>0</p></td>
<td></td>
</tr>
<tr class="odd">
<td><p>libcertifier.ext.key.usage</p></td>
<td><p>clientAuth,serverAuth</p></td>
<td><p>(See notes below)</p></td>
</tr>
</tbody>
</table>

\endhtmlonly

Extended Key Usage values:
==========================

This field can be populated with a list of values, indicating purposes
for which the certificate public key can be used for.

The following text names, and their intended meaning, are shown below:

\htmlonly

<table>
<colgroup>
<col width="50%" />
<col width="50%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p><strong>Value</strong></p></td>
<td><p><strong>Meaning</strong></p></td>
</tr>
<tr class="even">
<td><p>serverAuth</p></td>
<td><p>SSL/TLS Web Server Authentication</p></td>
</tr>
<tr class="odd">
<td><p>clientAuth</p></td>
<td><p>SSL/TLS Web Client Authentication</p></td>
</tr>
<tr class="even">
<td><p>codeSigning</p></td>
<td><p>Code signing</p></td>
</tr>
<tr class="odd">
<td><p>emailProtection</p></td>
<td><p>E-mail Protection (S/MIME)</p></td>
</tr>
<tr class="even">
<td><p>timeStamping</p></td>
<td><p>Trusted Timestamping</p></td>
</tr>
<tr class="odd">
<td><p>OCSPSigning</p></td>
<td><p>OCSP Signing</p></td>
</tr>
<tr class="even">
<td><p>ipsecIKE</p></td>
<td><p>ipsec Internet Key Exchange</p></td>
</tr>
</tbody>
</table>

\endhtmlonly

The following command is quite useful to put a root/intermediate cert
into a single line for libcertifier.cfg in the root.ca and/or int.ca
entries:

    awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' {custom-cert.pem}
