xref:libcertifier.adoc[*Back to Manual*]

============
Command Line Examples
=====

*Create X509 CRT*

The command below assumes there is a file called `seed.p12`, which is the pre-existing PKCS12 with a password of `changeit` without the single quotes.

----
./certifierUtil get-crt-token -X X509 -k ./seed.p12 -p changeit
----

This command could also be invoked from `./tests/functional/create_x509_crt.sh`.  Example -

----
cd ./tests/functional
./test-create-x509-crt.sh ../../seed.p12 changeit
----

*Fetch a new certificate*

The command below , passes in the contents of the `base64_data` from the command above (create x509 crt).   This command will make an HTTPS call to certifier and will create a brand new password-protected PKCS12 file that contains the certificate chain returned and public/private key pair. `libcertifier.cfg` must be present and have valid values - See last Section of this page to learn how the configuration file works.

----
./certifierUtil get-cert -f -T <base64_data>
----

This command could also be invoked from `./tests/functional/test-device-reg.sh`. Example:

----
cd ./tests/functional
./test-device-reg.sh <base64_data>
----

*Fetch an X509 cert end-to-end*

The command below combines both examples above into a single call.

----
./certifierUtil get-cert -f -k ./seed.p12 -p changeit
----

*Fetch a Matter Device Attestation Certificate*

The command below fetches a Device Attestation Certificate with a desired Product-ID (16-bit hex). VendorID will always be fixed to 0xFFF4

----
./certifierUtil get-cert -k ./seed.p12 -p changeit -o matter_dac.p12 --product-id 1101 -P XFN_DL_PAI_1_Class_3
----

*Fetch a Matter Operational Certificate*

The command below fetches a Matter-compliant Operational Certificate with a desired NodeID (64-bit hex).

----
./certifierUtil get-cert -k ./seed.p12 -p changeit -o matter_opcert.p12 --node-id AAAABBBBCCCCDDDD -P XFN_Matter_OP_Class_3_ICA
----

== *Other Examples*

*Get Certificate Status*

----
./certifierUtil get-cert-status -k <pkcs12-file-path>
----

*Revoke Certificate*

----
./certifierUtil revoke [-k <pkcs12-file-path>]
----

*Renew Certificate*

----
./certifierUtil renew-cert [-k <pkcs12-file-path>]
----

*Print Certificate*

----
./certifierUtil print-cert -k <pkcs12-file-path>
----

== *certifierUtil commands*

|===
| *Command* | *Description*

| help
| Display this summary

| version
| Display version info

| get-cert
| Fetch Certificate from PKI

| get-crt-token
| Generate Base64 CRT Token

| get-cert-status
| Check validity of certificate

| renew-cert
| Renew certificate's validity period if expired

| print-cert
| Display leaf certificate's PEM Base64 data

| revoke
| Revoke Certificate
|===

== *certifierUtil get-cert options*

|===
| *Long Option* | *Short Option* | *Examples* | *Description*

| help
| h
| --help +
-h
| Display this summary

| pkcs12-path
| k
| --pkcs12-path <file-path> +
-k <file-path>
| Path to the PKCS12 File

| pkcs12-password
| p
| --pkcs12-password <value> +
-p <value> +
(Defaults to 'changeit' if not supplied)
| Password to decrypt input P12 File

| config-path
| L
| --config-path <file-path> +
-L <file-path> +
(Defaults to 'libcertifier.cfg' if not supplied)
| Pass in custom set of configurations for commandline utility

| verbose
| v
| --verbose +
-v
| Enable verbose log output mode. +
Disabled by default - Only error messages are shown.

| crt-type
| X
| --crt-type <crt-type> +
-X <crt-type>
| Select Output CRT Type (X509 or other values)

| auth-token
| S
| --auth-token <value> +
 +
-S <value>
| Pass in App Authentication Token. +
Only valid and mandatory when client option is also passed in.

| crt
| T
| --crt <crt> +
-T <crt>
| Input CRT (Base64). +
It is an optional parameter, but will take precedence (against auth token) if used

| overwrite-p12-file
| f
| --overwrite-p12-file +
-f
| Overwrite P12 File

| profile-name
| P
| --profile-name <value> +
-P <value>
| Choose type of Certificate to be fetched from PKI (Either DAC Certificate - XFN_DL_PAI_1_Class_3 - or Matter Operational Certificate - XFN_Matter_OP_Class_3_ICA)

| output-p12-file
| o
| --output-p12-file <value> +
-o <value>
| Choose pathname of the resulting file that will store the P12 Chain that will include the generated certificate

| output-p12-pass
| w
| --output-12-pass <value> +
-w <value>
| Password to encrypt the output p12 file

| product-id
| i
| --product-id <id> +
 +
-n <id>
| Choose NodeID (64-bit integer) to be assigned to the resulting certificate

| node-id
| n
| --node-id <id> +
 +
-n <id>
| Choose NodeID (64-bit integer) to be assigned to the resulting certificate

| fabric-id
| F
| --fabric-id <id> +
-F <id>
| Choose FabricID (64-bit integer) to be assigned to the resulting certificate

| case-auth-tag
| a
| --case-auth-tag <id> +
-a <id>
| Choose CASE Authentication Tag (32-bit integer) to be assigned to the resulting certificate

| validity-days
| v
| --validity-days <days> +
-v <days>
| Choose number of validity days that a certificate is issued with

|===

== *certifierUtil get-crt-token options*

|===
| *Long Option* | *Short Option* | *Examples* | *Description*

| help
| h
| --help +
-h
| Display this summary

| pkcs12-path
| k
| --pkcs12-path <file-path> +
-k <file-path>
| Path to the PKCS12 File

| pkcs12-password
| p
| --pkcs12-password <value> +
-p <value> +
(Defaults to 'changeit' if not supplied)
| Password to decrypt input P12 File

| config-path
| L
| --config-path <file-path> +
-L <file-path> +
(Defaults to 'libcertifier.cfg' if not supplied)
| Pass in custom set of configurations for commandline utility

| verbose
| v
| --verbose +
-v
| Enable verbose log output mode. +
Disabled by default - Only error messages are shown.

| crt-type
| X
| --crt-type <crt-type> +
-X <crt-type>
| Select Output CRT Type (X509 or other values)

| auth-token
| S
| --auth-token <value> +
 +
-S <value>
| Pass in App Authentication Token

|===

== *certifierUtil get-cert-status options*

|===
| *Long Option* | *Short Option* | *Examples* | *Description*

| help
| h
| --help +
-h
| Display this summary

| pkcs12-path
| k
| --pkcs12-path <file-path> +
-k <file-path>
| Path to the PKCS12 File

| pkcs12-password
| p
| --pkcs12-password <value> +
-p <value> +
(Defaults to 'changeit' if not supplied)
| Password to decrypt input P12 File

| config
| L
| --config <value> +
-L <value> +
(Defaults to 'libcertifier.cfg' if not supplied)
| Pass in custom set of configurations for commandline utility

| verbose
| v
| --verbose +
-v
| Enable verbose log output mode. +
Disabled by default - Only error messages are shown.

|===

== *certifierUtil renew-cert options*

|===
| *Long Option* | *Short Option* | *Examples* | *Description*

| help
| h
| --help +
-h
| Display this summary

| pkcs12-path
| k
| --pkcs12-path <file-path> +
-k <file-path>
| Path to the PKCS12 File

| pkcs12-password
| p
| --pkcs12-password <value> +
-p <value> +
(Defaults to 'changeit' if not supplied)
| Password to decrypt input P12 File

| config
| L
| --config <value> +
-L <value> +
(Defaults to 'libcertifier.cfg' if not supplied)
| Pass in custom set of configurations for commandline utility

| verbose
| v
| --verbose +
-v
| Enable verbose log output mode. +
Disabled by default - Only error messages are shown.

| validity-days
| t
| --validity-days <days> +
-t <days>
| Choose number of validity days that a certificate is issued with

|===

== *certifierUtil print-cert options*

|===
| *Long Option* | *Short Option* | *Examples* | *Description*

| help
| h
| --help +
-h
| Display this summary

| pkcs12-path
| k
| --pkcs12-path <value> +
-k <value>
| Path to the PKCS12 File


| pkcs12-password
| p
| --pkcs12-password <value> +
-p <value> +
(Defaults to 'changeit' if not supplied)
| Password to decrypt input P12 File

| config
| L
| --config <value> +
-L <value> +
(Defaults to 'libcertifier.cfg' if not supplied)
| Pass in custom set of configurations for commandline utility

| verbose
| v
| --verbose +
-v
| Enable verbose log output mode. +
Disabled by default - Only error messages are shown.

|===

== *certifierUtil revoke options*

|===
| *Long Option* | *Short Option* | *Examples* | *Description*

| help
| h
| --help +
-h
| Display this summary

| pkcs12-path
| k
| --pkcs12-path <value> +
-k <value>
| Path to the PKCS12 File

| pkcs12-password
| p
| --pkcs12-password <value> +
-p <value> +
(Defaults to 'changeit' if not supplied)
| Password to decrypt input P12 File

| config
| L
| --config <value> +
-L <value> +
(Defaults to 'libcertifier.cfg' if not supplied)
| Pass in custom set of configurations for commandline utility

| verbose
| v
| --verbose +
-v
| Enable verbose log output mode. +
Disabled by default - Only error messages are shown.

|===

*Configuration File*

Configuration File is a file used to specify internal certifier util parameters such as timeouts, ecc curve types and other miscellaneous items. This file follows the JSON Format and can be manually editted from the `libcertifier.cfg.sample` template file present in the root directory.

Here are the details for every valid entry that can be added to the Configuration File:

|===
| *Entry Name* | *Default Value* | *Description*

| libcertifier.cert.min_time_left_s
| 604800
| Set the minimum time that the certificate must remain valid before CLI tool will consider the certificate is nearly expired. +
Note: value type = `int`

| libcertifier.certifier.url
| "https://certifier.xpki.io/v1/certifier"
| xPKI URL

| libcertifier.profile.name
| "XFN_Matter_OP_Class_3_ICA"
| Set Profile name for the desired certificate to fetch (Defaults to Matter Operational Certificate)

| libcertifier.num.days
| 365
| Set the number of validity days of the issuing certificate

| libcertifier.crt.type
| "X509"
| Choose CRT input type

| libcertifier.disable.auto.renewal
| 0
| Enable automatic certificate renewal. +
Note: value type = `bool`

| libcertifier.ecc.curve.id
| "prime256v1"
| Select ECC Curve ID for the issuing certificate

| libcertifier.http.connect.timeout
| 10
| Set HTTP Connection Timeout

| libcertifier.http.timeout
| 10
| Set HTTP Timeout

| libcertifier.http.trace
| 0
| Enable Debug/Trace output during HTTP exchange

| libcertifier.int.ca
| <default-PEM-CA-Certificate>
| Store device's Intermediate CA Certificate

| libcertifier.keystore
| "lrg"
| Set Path to the input PKCS#12 File containing a keypair and client certificate

| libcertifier.log.file
| "/tmp/libcertifier.log"
| Set file to store all logs of the xPKI transaction

| libcertifier.log.level
| 0
| Choose verbosity level of the logs

| libcertifier.log.max.size
| 5000000
| Set max size (in bytes) to write in the log file

| libcertifier.measure.performance
| 0
| Enable performance logs. +
Note: value type = `bool`

| libcertifier.password
| "changeit"
| Set password of the keystore/PKCS#12 file

| libcertifier.root.ca
| <default-PEM-ROOT-Certificate>
| Store device's Root Certificate

| libcertifier.source.name
| "libcertifier-opensource"
| Set the request source name

| libcertifier.tls.insecure.host
| 0
| Mark TLS insecure host. +
Note: value type = `bool`

| libcertifier.tls.insecure.peer
| 0
| Mark TLS insecure peer. +
Note: value type = `bool`

| libcertifier.certificate.lite
| 1
| Mark request for a lite certificate. +
Note: value type = `bool`

| libcertifier.system.id
| "BBBBBBBBBBBBBBBB"
| Set System ID value in the Subject Field of the Certificates in the Chain.

| libcertifier.fabric.id
| "DDDDDDDDDDDDDDDD"
| Set Fabric ID value in the Subject Field of the Matter Operational Certificate in the Chain. +
Note: 64-bit hex integer expected as input.

| libcertifier.product.id
| "1101"
| Set Product ID value in the Subject Field of the Certificates in the Chain. +
Note: 16-bit hex integer expected as input.

| libcertifier.cn.name
| "AAAAAAAA"
| Set CN Field value in the Subject Field of the Leaf Certificate. +
Note: Maximum number of characters is 8 due to certificate size constraints.

| libcertifier.node.id
| "CCCCCCCCCCCCCCCC"
| Set Node ID OID Field value in the Subject Field of the Matter Operational Certificate. +
Note: 64-bit hex integer expected as input.

| libcertifier.ext.key.usage
| "critical,clientAuth,serverAuth"
| Mark request for a lite certificate. +
Note: value type = `bool`

|===
