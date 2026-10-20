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

# Test vector generator for Matter Certification Declarations.
#
# Generates a CMS SignedData blob wrapping a TLV-encoded Certification
# Declaration payload, using the sample keys in test_keys_constants.py.
#
# Usage:
#   python certification_declaration_test_vector.py

import sys
from typing import Optional

from MatterTLV import TLVWriter
from crypto_primitives import (
    bytes_from_hex,
    to_octet_string,
    print_large_hex_payload,
    CMS_Sign,
)
import test_keys_constants


# ---------------------------------------------------------------------------
# TLV encoding
# ---------------------------------------------------------------------------

def generate_certification_declaration_tlv(
    format_version: int,
    vendor_id: int,
    product_id_array,
    device_type_id: int,
    certificate_id: str,
    security_level: int,
    security_information: int,
    version_number: int,
    certification_type: int,
    dac_origin_vendor_id: Optional[int] = None,
    dac_origin_product_id: Optional[int] = None,
) -> bytes:
    """Encode a Certification Declaration as a Matter TLV structure.

    The resulting byte string is the *payload* that will be wrapped in a
    CMS SignedData envelope by :func:`CMS_Sign`.

    TLV schema (tag-ordered structure)::

        certification-elements => STRUCTURE [tag-order]
        {
            format_version          [0]  : UNSIGNED INTEGER [ 16-bit ]
            vendor_id               [1]  : UNSIGNED INTEGER [ 16-bit ]
            product_id_array        [2]  : ARRAY [1..100] OF UNSIGNED INTEGER [ 16-bit ]
            device_type_id          [3]  : UNSIGNED INTEGER [ 32-bit ]
            certificate_id          [4]  : STRING [ length 19 ]
            security_level          [5]  : UNSIGNED INTEGER [ 8-bit ]   (reserved, must be 0)
            security_information    [6]  : UNSIGNED INTEGER [ 16-bit ]  (reserved, must be 0)
            version_number          [7]  : UNSIGNED INTEGER [ 16-bit ]
            certification_type      [8]  : UNSIGNED INTEGER [ 8-bit ]   (0=provisional, 1=final, 2=dev)
            dac_origin_vendor_id    [9]  : UNSIGNED INTEGER [ 16-bit ]  (optional)
            dac_origin_product_id   [10] : UNSIGNED INTEGER [ 16-bit ]  (optional)
        }
    """
    # --- input validation ---------------------------------------------------
    assert format_version == 1, "Only format_version 1 is supported"
    assert 0 < vendor_id <= 0xFFFF

    assert 1 <= len(product_id_array) <= 100
    for pid in product_id_array:
        assert 0 < pid <= 0xFFFF

    assert 0 <= device_type_id < 0xFFFFFFFF
    assert len(certificate_id.encode("utf-8")) == 19, \
        "certificate_id must be exactly 19 bytes when UTF-8 encoded"

    # Security level and security_information are reserved in V1
    assert security_level == 0, "security_level must be 0 (reserved in V1)"
    assert security_information == 0, "security_information must be 0 (reserved in V1)"

    assert 0 <= version_number <= 0xFFFF
    assert 0 <= certification_type <= 2

    # dac_origin fields must either both be present or both be absent
    assert (dac_origin_vendor_id is None) == (dac_origin_product_id is None), \
        "dac_origin_vendor_id and dac_origin_product_id must both be set or both be absent"
    if dac_origin_vendor_id is not None:
        assert 0 < dac_origin_vendor_id <= 0xFFFF
        assert 0 < dac_origin_product_id <= 0xFFFF

    # --- TLV encoding -------------------------------------------------------
    writer = TLVWriter()

    writer.startStructure(None)
    writer.putUnsignedInt(tag=0, val=format_version)
    writer.putUnsignedInt(tag=1, val=vendor_id)

    writer.startArray(tag=2)
    for pid in product_id_array:
        writer.putUnsignedInt(None, val=pid)
    writer.endContainer()

    writer.putUnsignedInt(tag=3, val=device_type_id)
    writer.putString(tag=4, val=certificate_id)
    writer.putUnsignedInt(tag=5, val=security_level)
    writer.putUnsignedInt(tag=6, val=security_information)
    writer.putUnsignedInt(tag=7, val=version_number)
    writer.putUnsignedInt(tag=8, val=certification_type)

    if dac_origin_vendor_id is not None:
        writer.putUnsignedInt(tag=9, val=dac_origin_vendor_id)
    if dac_origin_product_id is not None:
        writer.putUnsignedInt(tag=10, val=dac_origin_product_id)

    writer.endContainer()

    return bytes(writer.encoding)


# ---------------------------------------------------------------------------
# Sample vector generation
# ---------------------------------------------------------------------------

#: Sample input vectors used by :func:`sample_certification_declaration`.
SAMPLE_VECTORS = [
    {
        "format_version": 1,
        "vendor_id": 0x111D,
        "product_id_array": [0x1101],
        "device_type_id": 0x1234,
        "certificate_id": "ZIG20141ZB330001-24",
        "security_level": 0,
        "security_information": 0,
        "version_number": 9876,
        "certification_type": 0,
        "dac_origin_vendor_id": None,
        "dac_origin_product_id": None,
        "cd_pem_key_bytes": test_keys_constants.SAMPLE_CMS_CD_PEM_KEY,
        "pem_certificate_bytes": test_keys_constants.SAMPLE_CMS_CD_CERTIFICATE,
        "out_file_name": "cd_cms_test_vector_01",
    },
    {
        "format_version": 1,
        "vendor_id": 0xFFF2,
        "product_id_array": [0x8001, 0x8002],
        "device_type_id": 0x1234,
        "certificate_id": "ZIG20142ZB330002-24",
        "security_level": 0,
        "security_information": 0,
        "version_number": 9876,
        "certification_type": 0,
        "dac_origin_vendor_id": 0xFFF1,
        "dac_origin_product_id": 0x8000,
        "cd_pem_key_bytes": test_keys_constants.SAMPLE_CMS_CD_PEM_KEY,
        "pem_certificate_bytes": test_keys_constants.SAMPLE_CMS_CD_CERTIFICATE,
        "out_file_name": "cd_cms_test_vector_02",
    },
]


def sample_certification_declaration(argv) -> bytes:
    """Generate all sample Certification Declaration test vectors and write them to disk."""
    last_der = b""

    for params in SAMPLE_VECTORS:
        format_version      = params["format_version"]
        vendor_id           = params["vendor_id"]
        product_id_array    = params["product_id_array"]
        device_type_id      = params["device_type_id"]
        certificate_id      = params["certificate_id"]
        security_level      = params["security_level"]
        security_information = params["security_information"]
        version_number      = params["version_number"]
        certification_type  = params["certification_type"]
        dac_origin_vendor_id  = params["dac_origin_vendor_id"]
        dac_origin_product_id = params["dac_origin_product_id"]
        cd_pem_key_bytes    = params["cd_pem_key_bytes"]
        pem_certificate_bytes = params["pem_certificate_bytes"]
        out_der = params["out_file_name"] + ".der"
        out_pem = params["out_file_name"] + ".pem"

        # -- inputs ----------------------------------------------------------
        print("********** Sample Certification Declaration Payload **********")
        print()
        print("===== Algorithm inputs =====")
        print("-> format_version = %d" % format_version)
        print("-> vendor_id = 0x%04X" % vendor_id)
        print("-> product_id_array = [ %s ]" % ", ".join("0x%04X" % p for p in product_id_array))
        print("-> device_type_id = 0x%04X" % device_type_id)
        print('-> certificate_id = "%s"' % certificate_id)
        print("-> security_level = %d" % security_level)
        print("-> security_information = %d" % security_information)
        print("-> version_number = 0x%04X" % version_number)
        print("-> certification_type = %d" % certification_type)

        if dac_origin_vendor_id is None:
            print("-> dac_origin_vendor_id is not present")
        else:
            print("-> dac_origin_vendor_id = 0x%04X" % dac_origin_vendor_id)

        if dac_origin_product_id is None:
            print("-> dac_origin_product_id is not present")
        else:
            print("-> dac_origin_product_id = 0x%04X" % dac_origin_product_id)

        print()
        print("-> Sample CSA CD Signing Certificate:\n%s" % pem_certificate_bytes)
        print()
        print("-> Sample CSA CD Signing Private Key:\n%s" % cd_pem_key_bytes)
        print()

        # -- intermediate output: TLV ----------------------------------------
        print("===== Intermediate outputs =====")
        tlv = generate_certification_declaration_tlv(
            format_version,
            vendor_id,
            product_id_array,
            device_type_id,
            certificate_id,
            security_level,
            security_information,
            version_number,
            certification_type,
            dac_origin_vendor_id,
            dac_origin_product_id,
        )
        print_large_hex_payload(
            label="-> Encoded TLV of sample Certification Declaration (%d bytes)" % len(tlv),
            payload=tlv,
            as_hex_dump=True,
        )
        print()

        # -- final output: CMS SignedData ------------------------------------
        print("===== Algorithm outputs =====")
        cd_der = CMS_Sign(
            payload=tlv,
            pem_certificate=pem_certificate_bytes,
            pem_key_bytes=cd_pem_key_bytes,
        )
        cd_pem = CMS_Sign(
            payload=tlv,
            pem_certificate=pem_certificate_bytes,
            pem_key_bytes=cd_pem_key_bytes,
            out_format="PEM",
        )

        print_large_hex_payload(
            label="-> Encoded CMS SignedData of Certification Declaration (%d bytes)" % len(cd_der),
            payload=cd_der,
            as_hex_dump=True,
        )

        with open(out_der, "wb") as f:
            f.write(cd_der)
        with open(out_pem, "w") as f:
            f.write(cd_pem if isinstance(cd_pem, str) else cd_pem.decode())

        last_der = cd_der

    return last_der


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv):
    sample_certification_declaration(argv)


if __name__ == "__main__":
    main(sys.argv[1:])