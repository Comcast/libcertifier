# Copyright (C) Zigbee Alliance (2021). All rights reserved. This
# information within this document is the property of the Zigbee
# Alliance and its use and disclosure are restricted.

# Elements of Zigbee Alliance specifications may be subject to third
# party intellectual property rights, including without limitation,
# patent, copyright or trademark rights (such a third party may or may
# not be a member of the Zigbee Alliance). The Zigbee Alliance is not
# responsible and shall not be held responsible in any manner for
# identifying or failing to identify any or all such third party
# intellectual property rights.

# This document and the information contained herein are provided on an
# "AS IS" basis and the Zigbee Alliance DISCLAIMS ALL WARRANTIES EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO (A) ANY WARRANTY THAT THE USE
# OF THE INFORMATION HEREIN WILL NOT INFRINGE ANY RIGHTS OF THIRD
# PARTIES (INCLUDING WITHOUT LIMITATION ANY INTELLECTUAL PROPERTY RIGHTS
# INCLUDING PATENT, COPYRIGHT OR TRADEMARK RIGHTS) OR (B) ANY IMPLIED
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE
# OR NON-INFRINGEMENT. IN NO EVENT WILL THE ZIGBEE ALLIANCE BE LIABLE
# FOR ANY LOSS OF PROFITS, LOSS OF BUSINESS, LOSS OF USE OF DATA,
# INTERRUPTION OF BUSINESS, OR FOR ANY OTHER DIRECT, INDIRECT, SPECIAL
# OR EXEMPLARY, INCIDENTAL, PUNITIVE OR CONSEQUENTIAL DAMAGES OF ANY
# KIND, IN CONTRACT OR IN TORT, IN CONNECTION WITH THIS DOCUMENT OR THE
# INFORMATION CONTAINED HEREIN, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH LOSS OR DAMAGE.

# All company, brand and product names may be trademarks that are the
# sole property of their respective owners.

# This legal notice must be included on all copies of this document that
# are made.

# Zigbee Alliance
# 508 Second Street, Suite 206
# Davis, CA 95616, USA
# ------------------------------------------------------------------------

# Example sample key pairs

from crypto_primitives import bytes_from_hex

# NIST P-256 Attestation key pair used for NOCSR and device attestation test vectors
SAMPLE_ATTESTATION_PUBLIC_KEY = bytes_from_hex("04:ce:5c:f8:ef:b0:5d:4e:ee:79:0d:0a:71:d5:c0:11:bb:74:72:40:db:a2:14:58:84:5d:33:e3:4b:0a:f6:65:16:33:06:3a:80:4b:2f:f8:5d:ca:b2:01:9a:0a:b6:f5:59:57:75:fe:8d:85:fb:d7:a0:7c:8e:83:7d:a4:d5:a8:b9")
SAMPLE_ATTESTATION_PRIVATE_KEY = bytes_from_hex("38:f3:e0:a1:f1:45:ba:1b:f3:e4:4b:55:2d:ef:65:27:3d:1d:8e:27:6a:a3:14:ac:74:2e:b1:28:93:3b:a6:4b")

# CMS Certification Declaration Signing certificate and key pair for an examplary CSA certification CA
SAMPLE_CMS_CD_PEM_KEY = """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIK7zSEEW6UgexXvgRy30G/SZBk5QJK2GnspeiJgC1IB1oAoGCCqGSM49
AwEHoUQDQgAEPDmJIkUrVcrzicJb0bykZWlSzLkOiGkkmthHRlMBTL+V1oeWXgNr
UhxRA35rjO3vyh60QEZpT6CIgu7WUZ3sug==
-----END EC PRIVATE KEY-----"""
SAMPLE_CMS_CD_CERTIFICATE = """-----BEGIN CERTIFICATE-----
MIIBszCCAVqgAwIBAgIIRdrzneR6oI8wCgYIKoZIzj0EAwIwKzEpMCcGA1UEAwwg
TWF0dGVyIFRlc3QgQ0QgU2lnbmluZyBBdXRob3JpdHkwIBcNMjEwNjI4MTQyMzQz
WhgPOTk5OTEyMzEyMzU5NTlaMCsxKTAnBgNVBAMMIE1hdHRlciBUZXN0IENEIFNp
Z25pbmcgQXV0aG9yaXR5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPDmJIkUr
VcrzicJb0bykZWlSzLkOiGkkmthHRlMBTL+V1oeWXgNrUhxRA35rjO3vyh60QEZp
T6CIgu7WUZ3suqNmMGQwEgYDVR0TAQH/BAgwBgEB/wIBATAOBgNVHQ8BAf8EBAMC
AQYwHQYDVR0OBBYEFGL6gjNZrPqplj4c+hQK3fUE83FgMB8GA1UdIwQYMBaAFGL6
gjNZrPqplj4c+hQK3fUE83FgMAoGCCqGSM49BAMCA0cAMEQCICxUXOTkV9im8NnZ
u+vW7OHd/n+MbZps83UyH8b6xxOEAiBUB3jodDlyUn7t669YaGIgtUB48s1OYqdq
58u5L/VMiw==
-----END CERTIFICATE-----"""
