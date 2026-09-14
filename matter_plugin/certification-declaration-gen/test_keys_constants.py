# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

# Sample key pairs for Matter cryptographic test vector generation.
# These keys are for TESTING ONLY and must never be used in production.
#
#
#   # CD signing key and self-signed cert:
#   openssl ecparam -name prime256v1 -genkey -noout -out cd_signing_key.pem
#   openssl req -new -x509 -key cd_signing_key.pem \
#       -out cd_signing_cert.pem -days 36500 \
#       -subj "/CN=Matter Test CD Signing Authority"
#
#   # Attestation keypair (print as hex):
#   openssl ecparam -name prime256v1 -genkey -noout -out attestation_key.pem
#   openssl ec -in attestation_key.pem -text -noout
#   openssl ec -in attestation_key.pem -pubout -out attestation_pub.pem

from crypto_primitives import bytes_from_hex

# NIST P-256 Attestation key pair used for NOCSR and device attestation test vectors
SAMPLE_ATTESTATION_PUBLIC_KEY = bytes_from_hex(
    "04:89:3b:32:8c:c6:c4:59:14:aa:98:05:14:e6:23:"
    "96:20:9b:d9:c1:78:33:54:4d:5f:c2:d6:82:dc:fb:"
    "b4:88:d5:c1:20:2f:0b:df:52:39:4d:33:0e:bd:2f:"
    "9f:f6:5d:0d:6a:35:e2:b0:11:a3:86:f7:8a:2d:8f:"
    "62:54:ec:0e:70"
)

SAMPLE_ATTESTATION_PRIVATE_KEY = bytes_from_hex(
    "30:2c:25:7f:9b:aa:71:f3:5f:80:c8:21:d0:9b:52:"
    "21:22:11:d3:5b:36:4c:38:cd:90:b0:56:a1:e9:ab:"
    "41:42"
)

# CMS Certification Declaration signing certificate and key for an exemplary CSA certification CA.
# Self-signed, valid for test use only.
SAMPLE_CMS_CD_PEM_KEY = """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMDx5VizB2joqTWbDrBV05Hs7OqVh5ifM4MuoUlsYIsZoAoGCCqGSM49
AwEHoUQDQgAER1ZxVcn0tUjszGl+fg6CA2vUBgKV4f33ri3g0TWPoGbPttMQasFA
50aTSbdoL4lo4zwKwb43lFYqgi+p5CW7kw==
-----END EC PRIVATE KEY-----"""

SAMPLE_CMS_CD_CERTIFICATE = """-----BEGIN CERTIFICATE-----
MIIBrTCCAVOgAwIBAgIUfe6ej+B3z9b3yt3IrpQkEYY7iVcwCgYIKoZIzj0EAwIw
KzEpMCcGA1UEAwwgTWF0dGVyIFRlc3QgQ0QgU2lnbmluZyBBdXRob3JpdHkwIBcN
MjYwNjE1MDQyMTUwWhgPMjEyNjA1MjIwNDIxNTBaMCsxKTAnBgNVBAMMIE1hdHRl
ciBUZXN0IENEIFNpZ25pbmcgQXV0aG9yaXR5MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAER1ZxVcn0tUjszGl+fg6CA2vUBgKV4f33ri3g0TWPoGbPttMQasFA50aT
SbdoL4lo4zwKwb43lFYqgi+p5CW7k6NTMFEwHQYDVR0OBBYEFMymJm1MwbJOyjVc
wZMl1hCR2bxfMB8GA1UdIwQYMBaAFMymJm1MwbJOyjVcwZMl1hCR2bxfMA8GA1Ud
EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAKzDcXLFyoEO/dWXTm272Htx
jNkwu7aVV3g7K+3jWXtgAiAakZjzMZGci5eyHhzjkVbl7RgVMF1wi2zSuN8IQ/Im
8Q==
-----END CERTIFICATE-----"""