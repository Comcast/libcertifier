/**
 * Copyright 2021 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "CertifierDACProvider.h"

#include <crypto/CHIPCryptoPAL.h>

#include <lib/core/CHIPError.h>
#include <lib/support/CodeUtils.h>
#include <lib/support/Span.h>

#include <certifier/security.h>

namespace chip {
namespace Credentials {
namespace Certifier {

CHIP_ERROR LoadKeypairFromRaw(ByteSpan private_key, ByteSpan public_key, Crypto::P256Keypair & keypair)
{
    Crypto::P256SerializedKeypair serialized_keypair;
    ReturnErrorOnFailure(serialized_keypair.SetLength(private_key.size() + public_key.size()));
    memcpy(serialized_keypair.Bytes(), public_key.data(), public_key.size());
    memcpy(serialized_keypair.Bytes() + public_key.size(), private_key.data(), private_key.size());
    return keypair.Deserialize(serialized_keypair);
}

CHIP_ERROR CertifierDACProvider::GetDeviceAttestationCert(MutableByteSpan & out_dac_buffer)
{
    X509_CERT * cert     = nullptr;
    CertifierError error = CERTIFIER_ERROR_INITIALIZER;

    error = security_get_X509_PKCS12_file(GetDACFilepath(), GetDACPassword(), nullptr, &cert, nullptr);
    VerifyOrReturnError(error.application_error_code == 0 && error.library_error_code == 0, CHIP_ERROR_INTERNAL);

    size_t der_len      = 0;
    unsigned char * der = security_X509_to_DER(cert, &der_len);
    VerifyOrReturnError(der != nullptr, CHIP_ERROR_INTERNAL);

    CopySpanToMutableSpan(ByteSpan(der, der_len), out_dac_buffer);

    XFREE(der);
    security_free_cert(cert);

    return CHIP_NO_ERROR;
}

CHIP_ERROR CertifierDACProvider::GetProductAttestationIntermediateCert(MutableByteSpan & out_pai_buffer)
{
    X509_LIST * certs    = nullptr;
    X509_CERT * cert     = nullptr;
    CertifierError error = CERTIFIER_ERROR_INITIALIZER;

    certs = security_new_cert_list();
    VerifyOrReturnError(certs != nullptr, CHIP_ERROR_INTERNAL);

    error = security_get_X509_PKCS12_file(GetDACFilepath(), GetDACPassword(), certs, nullptr, nullptr);
    VerifyOrReturnError(error.application_error_code == 0 && error.library_error_code == 0, CHIP_ERROR_INTERNAL);

    cert = security_cert_list_get(certs, 1);

    size_t der_len      = 0;
    unsigned char * der = security_X509_to_DER(cert, &der_len);
    VerifyOrReturnError(der != nullptr, CHIP_ERROR_INTERNAL);

    CopySpanToMutableSpan(ByteSpan(der, der_len), out_pai_buffer);

    XFREE(der);
    security_free_cert(cert);
    security_free_cert_list(certs);

    return CHIP_NO_ERROR;
}

CHIP_ERROR CertifierDACProvider::GetCertificationDeclaration(MutableByteSpan & out_cd_buffer)
{
    constexpr uint8_t kCertificationDeclaration[] = {
#include "sample_certifier_cd.array"
    };

    return CopySpanToMutableSpan(ByteSpan{ kCertificationDeclaration }, out_cd_buffer);
}

CHIP_ERROR CertifierDACProvider::GetFirmwareInformation(MutableByteSpan & out_firmware_info_buffer)
{
    // TODO: We need a real example FirmwareInformation to be populated.
    out_firmware_info_buffer.reduce_size(0);

    return CHIP_NO_ERROR;
}

CHIP_ERROR CertifierDACProvider::SignWithDeviceAttestationKey(const ByteSpan & message_to_sign,
                                                              MutableByteSpan & out_signature_buffer)
{
    Crypto::P256ECDSASignature signature;
    Crypto::P256Keypair keypair;

    VerifyOrReturnError(IsSpanUsable(out_signature_buffer), CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(IsSpanUsable(message_to_sign), CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(out_signature_buffer.size() >= signature.Capacity(), CHIP_ERROR_BUFFER_TOO_SMALL);

    X509_CERT * cert     = nullptr;
    ECC_KEY * key        = nullptr;
    CertifierError error = CERTIFIER_ERROR_INITIALIZER;

    error = security_get_X509_PKCS12_file(GetDACFilepath(), GetDACPassword(), nullptr, &cert, &key);
    VerifyOrReturnError(error.application_error_code == 0 && error.library_error_code == 0, CHIP_ERROR_INTERNAL);

    uint8_t raw_public_key[65]  = { 0 };
    uint8_t raw_private_key[32] = { 0 };
    size_t raw_public_key_len   = security_serialize_raw_public_key(key, raw_public_key, sizeof(raw_public_key));
    size_t raw_private_key_len  = security_serialize_raw_private_key(key, raw_private_key, sizeof(raw_private_key));
    VerifyOrReturnError(raw_public_key_len == sizeof(raw_public_key), CHIP_ERROR_INTERNAL);
    VerifyOrReturnError(raw_private_key_len == sizeof(raw_private_key), CHIP_ERROR_INTERNAL);

    ReturnErrorOnFailure(LoadKeypairFromRaw(ByteSpan{ raw_private_key, raw_private_key_len },
                                            ByteSpan{ raw_public_key, raw_public_key_len }, keypair));

    security_free_eckey(key);
    security_free_cert(cert);

    ReturnErrorOnFailure(keypair.ECDSA_sign_msg(message_to_sign.data(), message_to_sign.size(), signature));

    return CopySpanToMutableSpan(ByteSpan{ signature.ConstBytes(), signature.Length() }, out_signature_buffer);
}

CHIP_ERROR CertifierDACProvider::SetDACFilepath(const char * dac_filepath, size_t len)
{
    VerifyOrReturnError(len < sizeof(m_dac_filepath), CHIP_ERROR_INVALID_ARGUMENT);
    strncpy(m_dac_filepath, dac_filepath, len);
    return CHIP_NO_ERROR;
}

CHIP_ERROR CertifierDACProvider::SetDACPassword(const char * dac_password, size_t len)
{
    VerifyOrReturnError(len < sizeof(m_dac_password), CHIP_ERROR_INVALID_ARGUMENT);
    strncpy(m_dac_password, dac_password, len);
    return CHIP_NO_ERROR;
}

const char * CertifierDACProvider::GetDACFilepath()
{
    return m_certifier_tool_dac_filepath ? m_certifier_tool_dac_filepath->ValueOr(m_dac_filepath) : m_dac_filepath;
}

const char * CertifierDACProvider::GetDACPassword()
{
    return m_certifier_tool_dac_password ? m_certifier_tool_dac_password->ValueOr(m_dac_password) : m_dac_password;
}

DeviceAttestationCredentialsProvider * GetDACProvider()
{
    static CertifierDACProvider certifierDacProvider;

    return &certifierDacProvider;
}

} // namespace Certifier
} // namespace Credentials
} // namespace chip
