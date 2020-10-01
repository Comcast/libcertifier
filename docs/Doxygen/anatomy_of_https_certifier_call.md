\page docs/Doxygen/anatomy_of_https_certifier_call.md Anatomy of HTTPS call
[Back to Manual](docs/Doxygen/libcertifier.md)

Anatomy of an HTTPS Request to Certifier
========================================

Requesting a new X509 certificate for the very first time -

    POST /v1/certifier/certificate HTTP/1.1
    Host: certifier.xpki.io
    Accept-Encoding: deflate, gzip
    Accept: application/json
    Content-Type: application/json; charset=utf-8
    Authorization: Bearer ewogICAgInRva2VuVHlwZSI6ICJYNTA5IiwKICAgICJjZXJ0aWZpY2F0ZSI6ICJNSUlDWFRDQ0FnU2dBd0lCQWdJVWJuZlVVZmxJOUZTNEdHREV4REtqWnJUa0JOY3dDZ1lJS29aSXpqMEVBd0l3T0RFMk1EUUdBMVVFQXd3dFEyOXRZMkZ6ZENCSmJuUmxaM0poZEdsdmJpQlVaWE4wYVc1bklFVkRReUJEYkdGemN5QkpTVWtnU1VOQk1CNFhEVEl3TURVeE9ESXdNak0xTWxvWERUSXlNRFF6TURJeU
    1qTTFNbG93Y2pFVk1CTUdBMVVFQnd3TVVHaHBiR0ZrWld4d2FHbGhNUXN3Q1FZRFZRUUlEQUpRUVRFTE1Ba0dBMVVFQmhNQ1ZWTXhHVEFYQmdOVkJBTU1FRzV2WkdVdVpYaGhiWEJzWlM1amIyMHhEekFOQmdOVkJBc01CbFJsYzNSUFZURVRNQkVHQTFVRUNnd0tUM0JsYmxOdmRYSmpaVEJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCT25TNEpTakYxRVljN1l6ZzgybVBXWVJtZzUwbjlpU1pkQmNueWttWkhrMk
    RNdTFaUFJQajZHNklPOTZmbmZydjNTdUY5RzhUXC9BXC9Jb0pva2p1UnJxK2pnYkV3Z2E0d0RBWURWUjBUQVFIXC9CQUl3QURBZkJnTlZIU01FR0RBV2dCUnRFZldFUVRhQTU1dHg3NUVcLzRPRHJSUnBpWlRBdkJnZ3JCZ0VGQlFjQkFRUWpNQ0V3SHdZSUt3WUJCUVVITUFHR0UyaDBkSEE2THk5dlkzTndMbmh3YTJrdWFXOHdIUVlEVlIwbEJCWXdGQVlJS3dZQkJRVUhBd0lHQ0NzR0FRVUZCd01CTUIwR0ExVWREZ1FXQkJRMU
    s3eWt6SUxOaUJDSVRydGRtTTJ2WXJNK2V6QU9CZ05WSFE4QkFmOEVCQU1DQmFBd0NnWUlLb1pJemowRUF3SURSd0F3UkFJaEFOVkREQkRTc1RcL2w4aENseTZVYlAzdHorMk8raXRSY3FLYk1kQmVuWjhtZ0FoOFVwOEJ6RkZvKzBKNnRQS1pnYjBVTUVPamJ6V3VzOWw3WkVwdkxSclZTIiwKICAgICJ0aW1lc3RhbXAiOiAiMTU5MDE3MTU4MTA1MiIsCiAgICAibm9uY2UiOiAiM2tuWFQzdndxMDlpakJ6YiIsCiAgICAic2lnbm
    F0dXJlIjogIk1FWUNJUUM4dDVjeUMyNnVHNnZMdmE0c0ZLOHRTUW94VFo4dDFjVEw5dmIyZ0JtVjZ3SWhBTG5vazVNRURmZ3pOY3h4TVB0bXVSdVF6Z3R0THR1bThjNWgwVXRTRzlLOCIKfQ==
    x-xpki-tracking-id: WHdIheGhwTJITdve
    x-xpki-source: libcertifier-opensource
    Content-Length: 357


    {"csr": "MIG6MGICAQAwADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOQzbD746JPOQ8yiou\/I4JxMINbxaYw8+ylLqlotC6JjWeXEX+UmxfvZBRasMqAprV39hT3DxcYU4cZURJrMN8KgADAKBggqhkjOPQQDAgNIADBFAiEAqiVsTg977DyfCfzXeAMhaQLdEWB6VqeD0Upgg2mxZmgCIB5hrYbIDbddaywZwc7NEMTb92Qn2UCmdCpHtkXUpSWy","nodeAddress": "1yRXmk9dQBHFQshcgWwuvdEyGVqphFZeq","certificateLite": "true"}

Server response -

    HTTP/1.1 200 OK
    Date: Fri, 22 May 2020 18:19:44 GMT
    Content-Type: application/json
    Content-Length: 2788
    Connection: keep-alive
    x-amzn-RequestId: 4294204e-da85-4b6a-bfeb-0ac5ae0113bb
    Access-Control-Allow-Origin: *
    Access-Control-Allow-Headers: Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,X-Amz-User-Agent,x-xpki-source,x-xpki-tracking-id
    x-amz-apigw-id: M8il7HfeIAMFnww=
    Access-Control-Allow-Methods: GET, POST, OPTIONS
    X-Amzn-Trace-Id: Root=1-5ec817bf-2448851c86b2471cb66330ec;Sampled=0
    {"certificateId":"4d2a6be29b540cf43c4f224721d882fe91adbccd","certificateChain":"-----BEGIN PKCS7-----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-----END PKCS7-----"}

Prior to making this HTTPS call, libcertifier -

1.  Created a public/private ECC keypair and stored that in memory.

2.  Created an Authorization HTTP header. This was based on a
    preexisting PKCS12 file. Using the CLI as per below, a valid
    Authorization HTTP header was created -

<!-- -->

    ./certifierUtil -m 128 -X <crt_type>

Base64 decoded, the Authorization HTTP header was JSON -

    {
        "tokenType": "X509",
        "certificate": "MIICXTCCAgSgAwIBAgIUbnfUUflI9FS4GGDExDKjZrTkBNcwCgYIKoZIzj0EAwIwODE2MDQGA1UEAwwtQ29tY2FzdCBJbnRlZ3JhdGlvbiBUZXN0aW5nIEVDQyBDbGFzcyBJSUkgSUNBMB4XDTIwMDUxODIwMjM1MloXDTIyMDQzMDIyMjM1MlowcjEVMBMGA1UEBwwMUGhpbGFkZWxwaGlhMQswCQYDVQQIDAJQQTELMAkGA1UEBhMCVVMxGTAXBgNVBAMMEG5vZGUuZXhhbXBsZS5jb20xDzANBgNVBAsMBlRlc3RPVTETMBEGA1UECgwKT3BlblNvdXJjZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOnS4JSjF1EYc7Yzg82mPWYRmg50n9iSZdBcnykmZHk2DMu1ZPRPj6G6IO96fnfrv3SuF9G8T\/A\/IoJokjuRrq+jgbEwga4wDAYDVR0TAQH\/BAIwADAfBgNVHSMEGDAWgBRtEfWEQTaA55tx75E\/4ODrRRpiZTAvBggrBgEFBQcBAQQjMCEwHwYIKwYBBQUHMAGGE2h0dHA6Ly9vY3NwLnhwa2kuaW8wHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMB0GA1UdDgQWBBQ1K7ykzILNiBCITrtdmM2vYrM+ezAOBgNVHQ8BAf8EBAMCBaAwCgYIKoZIzj0EAwIDRwAwRAIhANVDDBDSsT\/l8hCly6UbP3tz+2O+itRcqKbMdBenZ8mgAh8Up8BzFFo+0J6tPKZgb0UMEOjbzWus9l7ZEpvLRrVS",
        "timestamp": "1590171581052",
        "nonce": "3knXT3vwq09ijBzb",
        "signature": "MEYCIQC8t5cyC26uG6vLva4sFK8tSQoxTZ8t1cTL9vb2gBmV6wIhALnok5MEDfgzNcxxMPtmuRuQzgttLtum8c5h0UtSG9K8"
    }

The `tokenType` JSON element told the server what type of authentication
to use. In this case, we used `X509` authentication, which was based on
the public key of a preexisting PKCS 12 file.

The `certificate` JSON field, decoded using Open SSL (or from
<https://redkestrel.co.uk/products/decoder/>), which was from the
preexisting PKCS12 file -

    Certificate:
        Data:
            Version: 3 (0x2)
            Serial Number:
                6e:77:d4:51:f9:48:f4:54:b8:18:60:c4:c4:32:a3:66:b4:e4:04:d7
            Signature Algorithm: ecdsa-with-SHA256
            Issuer: CN=Comcast Integration Testing ECC Class III ICA
            Validity
                Not Before: May 18 20:23:52 2020 GMT
                Not After : Apr 30 22:23:52 2022 GMT
            Subject: L=Philadelphia, ST=PA, C=US, CN=node.example.com, OU=TestOU, O=OpenSource
            Subject Public Key Info:
                Public Key Algorithm: id-ecPublicKey
                    Public-Key: (256 bit)
                    pub:
                        04:e9:d2:e0:94:a3:17:51:18:73:b6:33:83:cd:a6:
                        3d:66:11:9a:0e:74:9f:d8:92:65:d0:5c:9f:29:26:
                        64:79:36:0c:cb:b5:64:f4:4f:8f:a1:ba:20:ef:7a:
                        7e:77:eb:bf:74:ae:17:d1:bc:4f:f0:3f:22:82:68:
                        92:3b:91:ae:af
                    ASN1 OID: prime256v1
                    NIST CURVE: P-256
            X509v3 extensions:
                X509v3 Basic Constraints: critical
                    CA:FALSE
                X509v3 Authority Key Identifier:
                    keyid:6D:11:F5:84:41:36:80:E7:9B:71:EF:91:3F:E0:E0:EB:45:1A:62:65

                Authority Information Access:
                    OCSP - URI:http://ocsp.xpki.io

                X509v3 Extended Key Usage:
                    TLS Web Client Authentication, TLS Web Server Authentication
                X509v3 Subject Key Identifier:
                    35:2B:BC:A4:CC:82:CD:88:10:88:4E:BB:5D:98:CD:AF:62:B3:3E:7B
                X509v3 Key Usage: critical
                    Digital Signature, Key Encipherment
        Signature Algorithm: ecdsa-with-SHA256
             30:44:02:21:00:d5:43:0c:10:d2:b1:3f:e5:f2:10:a5:cb:a5:
             1b:3f:7b:73:fb:63:be:8a:d4:5c:a8:a6:cc:74:17:a7:67:c9:
             a0:02:1f:14:a7:c0:73:14:5a:3e:d0:9e:ad:3c:a6:60:6f:45:
             0c:10:e8:db:cd:6b:ac:f6:5e:d9:12:9b:cb:46:b5:52

The `CSR` JSON field from the HTTP POST parameters, decoded using Open
SSL (or <https://redkestrel.co.uk/products/decoder/>) -

    Certificate Request:
        Data:
            Version: 1 (0x0)
            Subject:
            Subject Public Key Info:
                Public Key Algorithm: id-ecPublicKey
                    Public-Key: (256 bit)
                    pub:
                        04:e4:33:6c:3e:f8:e8:93:ce:43:cc:a2:a2:ef:c8:
                        e0:9c:4c:20:d6:f1:69:8c:3c:fb:29:4b:aa:5a:2d:
                        0b:a2:63:59:e5:c4:5f:e5:26:c5:fb:d9:05:16:ac:
                        32:a0:29:ad:5d:fd:85:3d:c3:c5:c6:14:e1:c6:54:
                        44:9a:cc:37:c2
                    ASN1 OID: prime256v1
                    NIST CURVE: P-256
            Attributes:
                a0:00
        Signature Algorithm: ecdsa-with-SHA256
             30:45:02:21:00:aa:25:6c:4e:0f:7b:ec:3c:9f:09:fc:d7:78:
             03:21:69:02:dd:11:60:7a:56:a7:83:d1:4a:60:83:69:b1:66:
             68:02:20:1e:61:ad:86:c8:0d:b7:5d:6b:2c:19:c1:ce:cd:10:
             c4:db:f7:64:27:d9:40:a6:74:2a:47:b6:45:d4:a5:25:b2

This CSR was blank and signed by the newly generated private key that
was stored in memory. ECC (Eliptical Curve Cryptography) was used.
libcertifier does not support other crypto, like RSA.

The public keys between the `CSR` and the `certificate` JSON fields were
different. `certificate` had the same public key as the preexisting
PKCS12 file. `CSR` had the public key from the one in memory (newly
created). It was clear that the baked PKCS12 is a single point of
failure. It had to be heavily guarded, otherwise anyone who had access
to it, could start issuing requests for new certificates! Other
authentication methods, were supported by Certifier.

Certifier authenticated this request by -

1.  Computing the signature of the public key and plain text and
    verifying that signature using the `SHA256withECDSA` algorithm.

2.  Verifying the X509. Checks included, but were not limited to,
    verification of Organization Name, subject domains, node address. It
    also ensured that the certificate had not expired, signatures were
    in place for public signed only, and verified the chain (root and
    intermediaries). Finally, OSCP was also validated.

Once authentication succeeded, a PKCS7 was returned as part of the
`certificateChain` JSON attribute, and decoded using OpenSSL (or
<https://redkestrel.co.uk/products/decoder/>) -

    Certificate:
        Data:
            Version: 3 (0x2)
            Serial Number:
                6e:57:50:73:c5:ee:91:80:f3:ca:ef:a9:8c:e1:9d:ab:c9:2c:be:79
            Signature Algorithm: ecdsa-with-SHA256
            Issuer: CN=Comcast Integration Testing ECC Class III ICA
            Validity
                Not Before: May 22 16:19:44 2020 GMT
                Not After : May 22 18:19:44 2021 GMT
            Subject: L=Philadelphia, ST=PA, C=US, CN=1yRXmk9dQBHFQshcgWwuvdEyGVqphFZeq, OU=TestOU, O=OpenSource
            Subject Public Key Info:
                Public Key Algorithm: id-ecPublicKey
                    Public-Key: (256 bit)
                    pub:
                        04:e4:33:6c:3e:f8:e8:93:ce:43:cc:a2:a2:ef:c8:
                        e0:9c:4c:20:d6:f1:69:8c:3c:fb:29:4b:aa:5a:2d:
                        0b:a2:63:59:e5:c4:5f:e5:26:c5:fb:d9:05:16:ac:
                        32:a0:29:ad:5d:fd:85:3d:c3:c5:c6:14:e1:c6:54:
                        44:9a:cc:37:c2
                    ASN1 OID: prime256v1
                    NIST CURVE: P-256
            X509v3 extensions:
                X509v3 Basic Constraints: critical
                    CA:FALSE
                X509v3 Authority Key Identifier:
                    keyid:6D:11:F5:84:41:36:80:E7:9B:71:EF:91:3F:E0:E0:EB:45:1A:62:65

                Authority Information Access:
                    OCSP - URI:http://ocsp.xpki.io

                X509v3 Extended Key Usage:
                    TLS Web Client Authentication, TLS Web Server Authentication
                X509v3 Subject Key Identifier:
                    40:25:6F:24:85:E8:C5:C2:48:1E:0C:94:9B:5F:9C:83:D6:8D:6E:1C
                X509v3 Key Usage: critical
                    Digital Signature, Key Encipherment
        Signature Algorithm: ecdsa-with-SHA256
             30:45:02:20:08:99:a0:1d:fe:81:1a:ea:2c:61:07:63:b4:01:
             18:c6:3a:f3:fc:b9:ae:e4:79:8b:9e:82:ff:e5:7d:72:f5:ff:
             02:21:00:fe:03:63:75:2c:c0:ba:11:e5:be:48:29:ea:21:9d:
             84:d2:6f:a1:ed:79:41:50:ba:c5:ed:c5:ae:5c:19:9f:43
    -----BEGIN CERTIFICATE-----
    MIICcDCCAhagAwIBAgIUbldQc8XukYDzyu+pjOGdq8ksvnkwCgYIKoZIzj0EAwIw
    ODE2MDQGA1UEAwwtQ29tY2FzdCBJbnRlZ3JhdGlvbiBUZXN0aW5nIEVDQyBDbGFz
    cyBJSUkgSUNBMB4XDTIwMDUyMjE2MTk0NFoXDTIxMDUyMjE4MTk0NFowgYMxFTAT
    BgNVBAcMDFBoaWxhZGVscGhpYTELMAkGA1UECAwCUEExCzAJBgNVBAYTAlVTMSow
    KAYDVQQDDCExeVJYbWs5ZFFCSEZRc2hjZ1d3dXZkRXlHVnFwaEZaZXExDzANBgNV
    BAsMBlRlc3RPVTETMBEGA1UECgwKT3BlblNvdXJjZTBZMBMGByqGSM49AgEGCCqG
    SM49AwEHA0IABOQzbD746JPOQ8yiou/I4JxMINbxaYw8+ylLqlotC6JjWeXEX+Um
    xfvZBRasMqAprV39hT3DxcYU4cZURJrMN8KjgbEwga4wDAYDVR0TAQH/BAIwADAf
    BgNVHSMEGDAWgBRtEfWEQTaA55tx75E/4ODrRRpiZTAvBggrBgEFBQcBAQQjMCEw
    HwYIKwYBBQUHMAGGE2h0dHA6Ly9vY3NwLnhwa2kuaW8wHQYDVR0lBBYwFAYIKwYB
    BQUHAwIGCCsGAQUFBwMBMB0GA1UdDgQWBBRAJW8khejFwkgeDJSbX5yD1o1uHDAO
    BgNVHQ8BAf8EBAMCBaAwCgYIKoZIzj0EAwIDSAAwRQIgCJmgHf6BGuosYQdjtAEY
    xjrz/Lmu5HmLnoL/5X1y9f8CIQD+A2N1LMC6EeW+SCnqIZ2E0m+h7XlBULrF7cWu
    XBmfQw==
    -----END CERTIFICATE-----

    Certificate:
        Data:
            Version: 3 (0x2)
            Serial Number:
                11:0a:d4:c1:b6:74:53:18:97:5c:4d:4c:f6:30:f6:27:5a:71:93:f4
            Signature Algorithm: ecdsa-with-SHA256
            Issuer: CN=Comcast Integration Testing ECC Class III Root
            Validity
                Not Before: May 11 23:15:11 2020 GMT
                Not After : May  5 23:11:38 2045 GMT
            Subject: CN=Comcast Integration Testing ECC Class III ICA
            Subject Public Key Info:
                Public Key Algorithm: id-ecPublicKey
                    Public-Key: (256 bit)
                    pub:
                        04:fe:89:42:19:ce:0b:3d:19:61:d5:a3:ed:c3:e3:
                        12:8e:74:5b:e8:a5:57:37:17:45:e7:c9:13:46:2b:
                        6b:b5:93:24:fa:00:41:cc:5c:e5:ee:f1:5d:d9:3e:
                        c6:d1:41:01:7f:27:a0:fe:e3:e6:9d:39:da:61:3b:
                        bb:3a:21:05:f9
                    ASN1 OID: prime256v1
                    NIST CURVE: P-256
            X509v3 extensions:
                X509v3 Basic Constraints: critical
                    CA:TRUE, pathlen:0
                X509v3 Authority Key Identifier:
                    keyid:36:F4:0A:A5:0A:F4:2B:CE:4E:57:D4:CC:7F:B0:32:AC:AA:CB:D8:B5

                X509v3 Subject Key Identifier:
                    6D:11:F5:84:41:36:80:E7:9B:71:EF:91:3F:E0:E0:EB:45:1A:62:65
                X509v3 Key Usage: critical
                    Digital Signature, Certificate Sign, CRL Sign
        Signature Algorithm: ecdsa-with-SHA256
             30:46:02:21:00:87:1a:89:a6:fe:74:d9:eb:1e:d0:4f:03:95:
             f9:64:87:4e:54:ea:e1:00:7a:80:2a:30:b6:8f:24:61:66:6c:
             10:02:21:00:a3:38:75:d8:63:7a:b2:fd:2c:89:34:59:82:2b:
             38:1f:bb:60:a8:5c:0c:b9:47:7e:04:6f:9c:0d:b5:f5:eb:2c
    -----BEGIN CERTIFICATE-----
    MIIB2jCCAX+gAwIBAgIUEQrUwbZ0UxiXXE1M9jD2J1pxk/QwCgYIKoZIzj0EAwIw
    OTE3MDUGA1UEAwwuQ29tY2FzdCBJbnRlZ3JhdGlvbiBUZXN0aW5nIEVDQyBDbGFz
    cyBJSUkgUm9vdDAeFw0yMDA1MTEyMzE1MTFaFw00NTA1MDUyMzExMzhaMDgxNjA0
    BgNVBAMMLUNvbWNhc3QgSW50ZWdyYXRpb24gVGVzdGluZyBFQ0MgQ2xhc3MgSUlJ
    IElDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABP6JQhnOCz0ZYdWj7cPjEo50
    W+ilVzcXRefJE0Yra7WTJPoAQcxc5e7xXdk+xtFBAX8noP7j5p052mE7uzohBfmj
    ZjBkMBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUNvQKpQr0K85OV9TM
    f7AyrKrL2LUwHQYDVR0OBBYEFG0R9YRBNoDnm3HvkT/g4OtFGmJlMA4GA1UdDwEB
    /wQEAwIBhjAKBggqhkjOPQQDAgNJADBGAiEAhxqJpv502ese0E8Dlflkh05U6uEA
    eoAqMLaPJGFmbBACIQCjOHXYY3qy/SyJNFmCKzgfu2CoXAy5R34Eb5wNtfXrLA==
    -----END CERTIFICATE-----

    Certificate:
        Data:
            Version: 3 (0x2)
            Serial Number:
                4a:9c:38:34:38:23:a5:27:9f:63:c7:c3:7e:71:15:c3:7a:51:89:32
            Signature Algorithm: ecdsa-with-SHA256
            Issuer: CN=Comcast Integration Testing ECC Class III Root
            Validity
                Not Before: May 11 23:11:38 2020 GMT
                Not After : May  5 23:11:38 2045 GMT
            Subject: CN=Comcast Integration Testing ECC Class III Root
            Subject Public Key Info:
                Public Key Algorithm: id-ecPublicKey
                    Public-Key: (256 bit)
                    pub:
                        04:1e:1e:f4:36:e2:67:6c:e0:79:12:91:9b:4c:72:
                        ec:f2:40:ee:70:49:62:10:31:17:ce:43:87:d7:cf:
                        e8:b5:d4:0f:dc:78:9f:1f:69:ce:23:e1:ae:76:bc:
                        3f:25:9b:fd:4f:98:78:3e:17:1f:15:48:15:7d:0e:
                        2b:26:83:a4:8f
                    ASN1 OID: prime256v1
                    NIST CURVE: P-256
            X509v3 extensions:
                X509v3 Basic Constraints: critical
                    CA:TRUE, pathlen:1
                X509v3 Authority Key Identifier:
                    keyid:36:F4:0A:A5:0A:F4:2B:CE:4E:57:D4:CC:7F:B0:32:AC:AA:CB:D8:B5

                X509v3 Subject Key Identifier:
                    36:F4:0A:A5:0A:F4:2B:CE:4E:57:D4:CC:7F:B0:32:AC:AA:CB:D8:B5
                X509v3 Key Usage: critical
                    Digital Signature, Certificate Sign, CRL Sign
        Signature Algorithm: ecdsa-with-SHA256
             30:45:02:21:00:93:58:2c:17:ec:c7:4f:89:16:58:9c:62:5d:
             41:64:47:24:81:16:b3:9d:d7:57:02:c3:30:ef:e5:d0:36:8d:
             cf:02:20:29:be:43:64:91:32:64:e1:c0:31:b9:0a:6d:5b:c3:
             bf:a2:ff:7d:0b:79:dc:f5:da:de:3c:1b:e8:d9:10:3c:66
    -----BEGIN CERTIFICATE-----
    MIIB2jCCAYCgAwIBAgIUSpw4NDgjpSefY8fDfnEVw3pRiTIwCgYIKoZIzj0EAwIw
    OTE3MDUGA1UEAwwuQ29tY2FzdCBJbnRlZ3JhdGlvbiBUZXN0aW5nIEVDQyBDbGFz
    cyBJSUkgUm9vdDAeFw0yMDA1MTEyMzExMzhaFw00NTA1MDUyMzExMzhaMDkxNzA1
    BgNVBAMMLkNvbWNhc3QgSW50ZWdyYXRpb24gVGVzdGluZyBFQ0MgQ2xhc3MgSUlJ
    IFJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQeHvQ24mds4HkSkZtMcuzy
    QO5wSWIQMRfOQ4fXz+i11A/ceJ8fac4j4a52vD8lm/1PmHg+Fx8VSBV9Dismg6SP
    o2YwZDASBgNVHRMBAf8ECDAGAQH/AgEBMB8GA1UdIwQYMBaAFDb0CqUK9CvOTlfU
    zH+wMqyqy9i1MB0GA1UdDgQWBBQ29AqlCvQrzk5X1Mx/sDKsqsvYtTAOBgNVHQ8B
    Af8EBAMCAYYwCgYIKoZIzj0EAwIDSAAwRQIhAJNYLBfsx0+JFlicYl1BZEckgRaz
    nddXAsMw7+XQNo3PAiApvkNkkTJk4cAxuQptW8O/ov99C3nc9drePBvo2RA8Zg==
    -----END CERTIFICATE-----

The PKCS7 data was in BER format and contained the main certificate,
it’s intermediate and it’s root certificates.

The final step was creating a new PKCS12 file containing the in-memory
public/private key pair and the certificate chain and persisting it to
disk.
