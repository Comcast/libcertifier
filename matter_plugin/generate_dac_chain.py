#!/usr/bin/python

from os import read
import sys

from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives import serialization
from cryptography import x509


def bytes_to_c_arr(data, lowercase=True):
    return [format(b, '#04x' if lowercase else '#04X') for b in data]


with open(str(sys.argv[1]), 'rb') as infile:
    private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
        infile.read(), b"changeit")

paa_certificate = additional_certificates[1].public_bytes(
    serialization.Encoding.DER)
pai_certificate = additional_certificates[0].public_bytes(
    serialization.Encoding.DER)
pai_certificate_pem = additional_certificates[0].public_bytes(
    serialization.Encoding.PEM)
device_manufacturer_certificate = certificate.public_bytes(
    serialization.Encoding.DER)
device_manufacturer_certificate_pem = certificate.public_bytes(
    serialization.Encoding.PEM)

private_key_bytes = private_key.private_bytes(
    serialization.Encoding.DER, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
public_key = private_key.public_key().public_bytes(
    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

skid = additional_certificates[1].extensions.get_extension_for_oid(
    x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest

# write header file
with open(str(sys.argv[2]), 'w') as f:
    f.write("constexpr uint8_t kPaaSkid[] = {{{}}};".format(
        ", ".join(bytes_to_c_arr(skid))))
    f.write('\n\n')
    f.write("constexpr uint8_t kPaaCertificate[] = {{{}}};".format(
        ", ".join(bytes_to_c_arr(paa_certificate))))
    f.write('\n\n')
    f.write("constexpr uint8_t kPaiCertificate[] = {{{}}};".format(
        ", ".join(bytes_to_c_arr(pai_certificate))))
    f.write('\n\n')
    f.write("constexpr uint8_t kDacCertificate[] = {{{}}};".format(
        ", ".join(bytes_to_c_arr(device_manufacturer_certificate))))
    f.write('\n\n')
    f.write("constexpr uint8_t kDacPrivateKey[] = {{{}}};".format(
        ", ".join(bytes_to_c_arr(private_key_bytes[7:7+32]))))
    f.write('\n\n')
    f.write("constexpr uint8_t kDacPublicKey[] = {{{}}};".format(
        ", ".join(bytes_to_c_arr(public_key[26:]))))
