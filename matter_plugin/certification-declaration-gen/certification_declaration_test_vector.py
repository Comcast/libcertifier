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

# Test vector generator for Certification Declarations

# Generate test vectors with CMS Algorithm:
# $ python certification_declaration_test_vector.py

from MatterTLV import TLVWriter

from crypto_primitives import bytes_from_hex, to_octet_string, print_large_hex_payload
from crypto_primitives import CMS_Sign
import test_keys_constants

import sys
from typing import Optional


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
      dac_origin_product_id: Optional[int] = None) -> bytes:

  # certification-elements => STRUCTURE [tag-order]
  # {
  #     format_version [0]          : UNSIGNED INTEGER [ range 16-bits ]
  #     vendor_id [1]               : UNSIGNED INTEGER [ range 16-bits ]
  #     product_id_array [2]        : ARRAY [ length 1..100 ] OF UNSIGNED INTEGER [ range 16-bits ]
  #     device_type_id [3]          : UNSIGNED INTEGER [ range 32-bits ]
  #     certificate_id [4]          : STRING [ length 19 ]
  #     security_level [5]          : UNSIGNED INTEGER [ range 8-bits ]
  #     security_information [6]    : UNSIGNED INTEGER [ range 16-bits ]
  #     version_number [7]          : UNSIGNED INTEGER [ range 16-bits ]
  #     certification_type [8]      : UNSIGNED INTEGER [ range 8-bits]
  #     dac_origin_vendor_id [9, optional]   : UNSIGNED INTEGER [ range 16-bits ]
  #     dac_origin_product_id [10, optional] : UNSIGNED INTEGER [ range 16-bits ]
  # }

  assert(format_version == 1)
  assert(vendor_id > 0 and vendor_id <= 0xFFFF)

  for product_id in product_id_array:
    assert(product_id > 0 and product_id <= 0xFFFF)

  product_id_count = len(product_id_array)
  assert(product_id_count > 0 and product_id_count <= 100)

  assert(device_type_id >= 0 and device_type_id < 0xFFFFFFFF)

  assert(len(certificate_id.encode('utf-8')) == 19)

  # Security level and security_information are reserved in V1
  assert(security_level == 0)
  assert(security_information == 0)

  assert(version_number >= 0 and version_number <= 0xFFFF)
  assert(certification_type >= 0 and certification_type <= 2)
  if dac_origin_vendor_id is None:
    assert(dac_origin_product_id is None)
  else:
    assert(dac_origin_vendor_id > 0 and dac_origin_vendor_id <= 0xFFFF)

  if dac_origin_product_id is None:
    assert(dac_origin_vendor_id is None)
  else:
    assert(dac_origin_product_id > 0 and dac_origin_product_id <= 0xFFFF)

  writer = TLVWriter()

  # Outer structure is anonymous
  writer.startStructure(None)
  writer.putUnsignedInt(tag=0, val=format_version)
  writer.putUnsignedInt(tag=1, val=vendor_id)
  writer.startArray(tag=2)
  for product_id in product_id_array:
    writer.putUnsignedInt(None, val=product_id)
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

  encoded_cd_tlv = bytes(writer.encoding)

  return encoded_cd_tlv


def sample_certification_declaration(argv) -> bytes:
  SAMPLE_VECTORS = [
    {
      "format_version": 1,
      "vendor_id": 0x111D,
      "product_id_array": [ 0x1101 ],
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
      "product_id_array": [ 0x8001, 0x8002 ],
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

  for sample_params in SAMPLE_VECTORS:
    format_version = sample_params["format_version"]
    vendor_id = sample_params["vendor_id"]
    product_id_array = sample_params["product_id_array"]
    device_type_id = sample_params["device_type_id"]
    certificate_id = sample_params["certificate_id"]
    security_level = sample_params["security_level"]
    security_information = sample_params["security_information"]
    version_number = sample_params["version_number"]
    certification_type = sample_params["certification_type"]
    dac_origin_vendor_id = sample_params["dac_origin_vendor_id"]
    dac_origin_product_id = sample_params["dac_origin_product_id"]
    cd_pem_key_bytes = sample_params["cd_pem_key_bytes"]
    pem_certificate_bytes = sample_params["pem_certificate_bytes"]
    out_file_der = sample_params["out_file_name"] + ".der"
    out_file_pem = sample_params["out_file_name"] + ".pem"

    print("********** Sample Certification Declaration Payload **********")
    print()

    print("===== Algorithm inputs =====")
    print("-> format_version = %d" % format_version)
    print("-> vendor_id = 0x%04X" % vendor_id)
    print("-> product_id_array = [ %s ]" % ", ".join(["0x%04X" % pid for pid in product_id_array]))
    print("-> device_type_id = 0x%04X" % device_type_id)
    print("-> certificate_id = \"%s\"" % certificate_id)
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
    print('-> Sample CSA CD Signing Certificate:\n%s' % pem_certificate_bytes)
    print()
    print('-> Sample CSA CD Signing Private Key:\n%s' % cd_pem_key_bytes)
    print()

    print("===== Intermediate outputs =====")

    encoded_cd_tlv = generate_certification_declaration_tlv(
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
      dac_origin_product_id
    )

    print_large_hex_payload(
      label="-> Encoded TLV of sample Certification Declaration (%d bytes)" % len(encoded_cd_tlv),
      payload=encoded_cd_tlv,
      as_hex_dump=True)
    print()

    print("===== Algorithm outputs =====")

    cd_cms_der = CMS_Sign(
      payload=encoded_cd_tlv,
      pem_certificate=pem_certificate_bytes,
      pem_key_bytes=cd_pem_key_bytes
    )

    cd_cms_pem = CMS_Sign(
      payload=encoded_cd_tlv,
      pem_certificate=pem_certificate_bytes,
      pem_key_bytes=cd_pem_key_bytes,
      out_format="PEM"
    )

    print_large_hex_payload(
      label="-> Encoded CMS SignedData of Certification Declaration (%d bytes)" % len(cd_cms_der),
      payload=cd_cms_der,
      as_hex_dump=True)

    with open(out_file_der, "wb+") as outfile:
      outfile.write(cd_cms_der)

    with open(out_file_pem, "w+") as outfile:
      outfile.write(cd_cms_pem)

  return cd_cms_der

def main(argv):
  sample_certification_declaration(argv)

if __name__ == "__main__":
  main(sys.argv[1:])
