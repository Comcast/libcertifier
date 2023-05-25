from crypto_primitives import bytes_from_hex, to_octet_string, print_large_hex_payload
from crypto_primitives import CMS_Sign
import test_keys_constants

import click
import sys
from typing import Optional

from certification_declaration_test_vector import generate_certification_declaration_tlv


def bytes_to_c_arr(data, lowercase=True):
    return [format(b, '#04x' if lowercase else '#04X') for b in data]


def sample_certification_declaration(vendor_id, product_id, output_filename) -> bytes:
    SAMPLE_VECTORS = [
        {
            "format_version": 1,
            "vendor_id": vendor_id,
            "product_id_array": [product_id],
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
            "out_file_name": output_filename,
        }
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
        out_file_c = sample_params["out_file_name"] + ".array"

        print("********** Sample Certification Declaration Payload **********")
        print()

        print("===== Algorithm inputs =====")
        print("-> format_version = %d" % format_version)
        print("-> vendor_id = 0x%04X" % vendor_id)
        print("-> product_id_array = [ %s ]" %
              ", ".join(["0x%04X" % pid for pid in product_id_array]))
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
        print('-> Sample CSA CD Signing Certificate:\n%s' %
              pem_certificate_bytes)
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
            label="-> Encoded TLV of sample Certification Declaration (%d bytes)" % len(
                encoded_cd_tlv),
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
            label="-> Encoded CMS SignedData of Certification Declaration (%d bytes)" % len(
                cd_cms_der),
            payload=cd_cms_der,
            as_hex_dump=True)

        with open(out_file_der, "wb+") as outfile:
            outfile.write(cd_cms_der)

        with open(out_file_pem, "w+") as outfile:
            outfile.write(cd_cms_pem)

        with open(out_file_c, "w+") as outfile:
            outfile.write("{{{}}}".format(", ".join(bytes_to_c_arr(cd_cms_der)))[1:-1])

    return cd_cms_der


@click.command()
@click.help_option('-h', '--help')
@click.option('--vendor-id', type=int, default=0x111D, help='Set Vendor ID')
@click.option('--product-id', type=int, default=0x1101, help='Set Product ID')
@click.option('--output', type=str, default='sample_certifier_cd', metavar='PATH', help="Output filename for the resulting Certification Declaration.")
def main(vendor_id, product_id, output):
    sample_certification_declaration(vendor_id, product_id, output)


if __name__ == "__main__":
    main()
