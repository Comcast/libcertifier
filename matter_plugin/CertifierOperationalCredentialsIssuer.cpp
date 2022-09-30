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

#include <CertifierOperationalCredentialsIssuer.h>

#include <stddef.h>

#include <controller/CommissioneeDeviceProxy.h>
#include <credentials/DeviceAttestationCredsProvider.h>
#include <lib/asn1/ASN1.h>
#include <lib/asn1/ASN1Macros.h>
#include <lib/core/CHIPTLV.h>
#include <lib/support/CHIPMem.h>
#include <lib/support/CodeUtils.h>
#include <lib/support/ScopedBuffer.h>
#include <lib/support/TestGroupData.h>

#include <chrono>
#include <memory>

#include <certifier/base64.h>
#include <certifier/certifier_api_easy.h>
#include <certifier/certifier_internal.h>
#include <certifier/http.h>
#include <certifier/parson.h>
#include <certifier/util.h>
#include <certifier/security.h>
#include <certifier/types.h>

#include <openssl/bn.h>
#include <openssl/ecdsa.h>

namespace {

constexpr char cert_id[] = "X509";

}

namespace chip {
namespace Controller {

using namespace Credentials;
using namespace Crypto;
using namespace ASN1;
using namespace TLV;

CHIP_ERROR CertifierOperationalCredentialsIssuer::GenerateNOCChainAfterValidation(NodeId nodeId, FabricId fabricId,
                                                                                  const ByteSpan & dac, const ByteSpan & csr,
                                                                                  const ByteSpan & nonce, MutableByteSpan & rcac,
                                                                                  MutableByteSpan & icac, MutableByteSpan & noc)
{
    CHIP_ERROR error = CHIP_NO_ERROR;
    X509_LIST * certs;
    X509_CERT * cert = nullptr;
    unsigned char * rawCert = nullptr;
    size_t rawCertLength = 0;
    uint8_t OpCertificateChain[4096];
    MutableByteSpan OpCertificateChainSpan(OpCertificateChain);

    SuccessOrExit(error = ObtainOpCert(dac, csr, nonce, OpCertificateChainSpan, nodeId));

    OpCertificateChain[OpCertificateChainSpan.size()] = 0;
    util_trim(reinterpret_cast<char *>(OpCertificateChain));

    security_load_certs_from_pem(reinterpret_cast<const char *>(OpCertificateChain), &certs);

    cert = security_cert_list_get(certs, 0);
    VerifyOrExit(cert != nullptr, error = CHIP_ERROR_INTERNAL);
    rawCert = security_X509_to_DER(cert, &rawCertLength);
    VerifyOrExit(rawCert != nullptr, error = CHIP_ERROR_INTERNAL);
    SuccessOrExit(error = CopySpanToMutableSpan(ByteSpan(rawCert, rawCertLength), noc));
    XFREE(rawCert);

    cert = security_cert_list_get(certs, 1);
    VerifyOrExit(cert != nullptr, error = CHIP_ERROR_INTERNAL);
    rawCert = security_X509_to_DER(cert, &rawCertLength);
    VerifyOrExit(rawCert != nullptr, error = CHIP_ERROR_INTERNAL);
    SuccessOrExit(error = CopySpanToMutableSpan(ByteSpan(rawCert, rawCertLength), icac));
    XFREE(rawCert);

    cert = security_cert_list_get(certs, 2);
    VerifyOrExit(cert != nullptr, error = CHIP_ERROR_INTERNAL);
    rawCert = security_X509_to_DER(cert, &rawCertLength);
    VerifyOrExit(rawCert != nullptr, error = CHIP_ERROR_INTERNAL);
    SuccessOrExit(error = CopySpanToMutableSpan(ByteSpan(rawCert, rawCertLength), rcac));

exit:
    XFREE(rawCert);
    security_free_cert_list(certs);

    return error;
}

CHIP_ERROR CertifierOperationalCredentialsIssuer::GenerateNOCChain(const ByteSpan & csrElements, const ByteSpan & csrNonce,
                                                                   const ByteSpan & attestationSignature,
                                                                   const ByteSpan & attestationChallenge, const ByteSpan & DAC,
                                                                   const ByteSpan & PAI,
                                                                   Callback::Callback<OnNOCChainGeneration> * onCompletion)
{
    ChipLogProgress(Controller, "Verifying Certificate Signing Request");
    TLVReader reader;
    reader.Init(csrElements);

    if (reader.GetType() == kTLVType_NotSpecified)
    {
        ReturnErrorOnFailure(reader.Next());
    }

    VerifyOrReturnError(reader.GetType() == kTLVType_Structure, CHIP_ERROR_WRONG_TLV_TYPE);
    VerifyOrReturnError(reader.GetTag() == AnonymousTag(), CHIP_ERROR_UNEXPECTED_TLV_ELEMENT);

    TLVType containerType;
    ReturnErrorOnFailure(reader.EnterContainer(containerType));
    ReturnErrorOnFailure(reader.Next(kTLVType_ByteString, TLV::ContextTag(1)));

    ByteSpan csr;
    ReturnErrorOnFailure(reader.Get(csr));

    ReturnErrorOnFailure(reader.Next(kTLVType_ByteString, TLV::ContextTag(2)));

    ByteSpan nonce;
    ReturnErrorOnFailure(reader.Get(nonce));

    reader.ExitContainer(containerType);

    Platform::ScopedMemoryBuffer<uint8_t> noc;
    ReturnErrorCodeIf(!noc.Alloc(kMaxCHIPDERCertLength), CHIP_ERROR_NO_MEMORY);
    MutableByteSpan nocSpan(noc.Get(), kMaxCHIPDERCertLength);

    Platform::ScopedMemoryBuffer<uint8_t> icac;
    ReturnErrorCodeIf(!icac.Alloc(kMaxCHIPDERCertLength), CHIP_ERROR_NO_MEMORY);
    MutableByteSpan icacSpan(icac.Get(), kMaxCHIPDERCertLength);

    Platform::ScopedMemoryBuffer<uint8_t> rcac;
    ReturnErrorCodeIf(!rcac.Alloc(kMaxCHIPDERCertLength), CHIP_ERROR_NO_MEMORY);
    MutableByteSpan rcacSpan(rcac.Get(), kMaxCHIPDERCertLength);

    ReturnErrorOnFailure(GenerateNOCChainAfterValidation(mNodeId, mFabricId, DAC, csr, nonce, rcacSpan, icacSpan, nocSpan));

    // TODO(#13825): Should always generate some IPK. Using a temporary fixed value until APIs are plumbed in to set it end-to-end
    // TODO: Force callers to set IPK if used before GenerateNOCChain will succeed.
    ByteSpan defaultIpkSpan = chip::GroupTesting::DefaultIpkValue::GetDefaultIpk();

    // The below static assert validates a key assumption in types used (needed for public API conformance)
    static_assert(CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES == kAES_CCM128_Key_Length, "IPK span sizing must match");

    // Prepare IPK to be sent back. A more fully-fledged operational credentials delegate
    // would obtain a suitable key per fabric.
    uint8_t ipkValue[CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES];
    Crypto::AesCcm128KeySpan ipkSpan(ipkValue);

    ReturnErrorCodeIf(defaultIpkSpan.size() != sizeof(ipkValue), CHIP_ERROR_INTERNAL);
    memcpy(&ipkValue[0], defaultIpkSpan.data(), defaultIpkSpan.size());

    ChipLogProgress(Controller, "Providing certificate chain to the commissioner");
    onCompletion->mCall(onCompletion->mContext, CHIP_NO_ERROR, nocSpan, icacSpan, rcacSpan, MakeOptional(ipkSpan),
                        Optional<NodeId>());
    return CHIP_NO_ERROR;
}

CHIP_ERROR CertifierOperationalCredentialsIssuer::ObtainCsrNonce(MutableByteSpan & csrNonce)
{
    VerifyOrReturnError(csrNonce.size() == kCSRNonceLength, CHIP_ERROR_INVALID_ARGUMENT);
    char * certifier_nonce = util_generate_random_value(static_cast<int>(csrNonce.size()), ALLOWABLE_CHARACTERS);
    VerifyOrReturnError(certifier_nonce != nullptr, CHIP_ERROR_NO_MEMORY);
    memcpy(csrNonce.data(), certifier_nonce, csrNonce.size());
    XFREE(certifier_nonce);

    return CHIP_NO_ERROR;
}

CHIP_ERROR CertifierOperationalCredentialsIssuer::SetAuthCertificate(const char * authCertPath, size_t len)
{
    VerifyOrReturnError(len < sizeof(mAuthCertificate), CHIP_ERROR_INVALID_ARGUMENT);
    strncpy(mAuthCertificate, authCertPath, len);
    return CHIP_NO_ERROR;
}

CHIP_ERROR CertifierOperationalCredentialsIssuer::SetCertConfig(const char * certCfgPath, size_t len)
{
    VerifyOrReturnError(len < sizeof(mCertifierCfg), CHIP_ERROR_INVALID_ARGUMENT);
    strncpy(mCertifierCfg, certCfgPath, len);
    return CHIP_NO_ERROR;
}

void CertifierOperationalCredentialsIssuer::GetTimestampForCertifying()
{
    using namespace std::chrono;
    int64_t ms = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    sprintf(mTimestamp, "%" PRId64, ms);
}

http_response * CertifierOperationalCredentialsIssuer::DoHttpExchange(uint8_t * buffer, CERTIFIER * certifier)
{
    static char auth_header[VERY_LARGE_STRING_SIZE * 4] = "";
    static char tracking_header[LARGE_STRING_SIZE]      = "";
    static char source_header[SMALL_STRING_SIZE]        = "";
    const char * tracking_id  = reinterpret_cast<const char *>(certifier_api_easy_get_opt(mCertifier, CERTIFIER_OPT_TRACKING_ID));
    const char * bearer_token = reinterpret_cast<const char *>(certifier_api_easy_get_opt(mCertifier, CERTIFIER_OPT_CRT));
    const char * source       = reinterpret_cast<const char *>(certifier_api_easy_get_opt(mCertifier, CERTIFIER_OPT_SOURCE));
    const char * certifier_url =
        reinterpret_cast<const char *>(certifier_api_easy_get_opt(mCertifier, CERTIFIER_OPT_CERTIFIER_URL));

    char certifier_certificate_url[256];
    char certificate_url[] = "/certificate";
    strncpy(certifier_certificate_url, certifier_url, sizeof(certifier_certificate_url));
    strncpy(certifier_certificate_url + strlen(certifier_url), certificate_url, sizeof(certifier_certificate_url) - strlen(certifier_url));

    if (bearer_token != nullptr)
    {
        snprintf(auth_header, VERY_LARGE_STRING_SIZE * 4, "Authorization: Bearer %s", bearer_token);
    }
    snprintf(tracking_header, SMALL_STRING_SIZE, "x-xpki-tracking-id: %s", tracking_id);
    snprintf(source_header, SMALL_STRING_SIZE, "x-xpki-source: %s", source);

    const char * headers[] = { "Accept: application/json",
                               "Content-Type: application/json; charset=utf-8",
                               auth_header,
                               tracking_header,
                               source_header,
                               nullptr };
    return certifier_api_easy_http_post(certifier, certifier_certificate_url, headers, (const char *) (buffer));
}

CHIP_ERROR CertifierOperationalCredentialsIssuer::ObtainOpCert(const ByteSpan & dac, const ByteSpan & csr, const ByteSpan & nonce,
                                                               MutableByteSpan & pkcs7OpCert, NodeId nodeId)
{
    CHIP_ERROR err = CHIP_NO_ERROR;

    JSON_Value * root_value   = json_value_init_object();
    JSON_Object * root_object = json_value_get_object(root_value);

    size_t base64CertificateLength = static_cast<size_t>(base64_encode_len(static_cast<int>(dac.size()) + 2));
    size_t base64CSRLength         = static_cast<size_t>(base64_encode_len(static_cast<int>(csr.size()))) + 1;
    Platform::ScopedMemoryBuffer<char> base64Certificate;
    Platform::ScopedMemoryBuffer<char> base64JsonCrt;
    Platform::ScopedMemoryBuffer<char> base64CSR;
    Platform::ScopedMemoryBuffer<char> base64Signature;
    int base64SignatureLength;

    uint8_t derSignature[kMax_ECDSA_Signature_Length_Der];
    MutableByteSpan derSignatureSpan(derSignature);

    char * jsonCSR = nullptr;
    char operationalID[] = "XFN-MTR";
    char nodeIdArray[17];

    http_response * resp                = nullptr;
    const char * OpCertificateChainTemp = nullptr;

    char * mJsonCrt = nullptr;

    size_t pkcs7OpCertBufLen = 0;

    int result = 0;

    char nullTerminatedNonce[kAttestationNonceLength + 1];

    VerifyOrExit(base64Certificate.Alloc(base64CertificateLength), err = CHIP_ERROR_NO_MEMORY);
    VerifyOrExit(base64CSR.Alloc(base64CSRLength), err = CHIP_ERROR_NO_MEMORY);

    memset(nodeIdArray, 0, sizeof(nodeIdArray));
    snprintf(nodeIdArray, sizeof(nodeIdArray), "%016" PRIX64, nodeId);

    json_object_set_string(root_object, "tokenType", cert_id);
    base64_encode(base64Certificate.Get(), dac.data(), static_cast<int>(dac.size()));
    result = json_object_set_string(root_object, "certificate", base64Certificate.Get());
    VerifyOrExit(result == 0, err = CHIP_ERROR_INTERNAL);
    GetTimestampForCertifying();
    result = json_object_set_string(root_object, "timestamp", mTimestamp);
    VerifyOrExit(result == 0, err = CHIP_ERROR_INTERNAL);
    VerifyOrExit(nonce.size() <= sizeof(nullTerminatedNonce) - 1, err = CHIP_ERROR_INVALID_ARGUMENT);
    memcpy(nullTerminatedNonce, nonce.data(), nonce.size());
    nullTerminatedNonce[nonce.size()] = '\0';
    result                            = json_object_set_string(root_object, "nonce", nullTerminatedNonce);
    VerifyOrExit(result == 0, err = CHIP_ERROR_INTERNAL);

    {
        P256ECDSASignature signature;
        MutableByteSpan signatureSpan(signature, signature.Capacity());
        uint8_t md[kSHA256_Hash_Length];
        MutableByteSpan mdSpan(md);
        Hash_SHA256_stream hashStream;

        DeviceAttestationCredentialsProvider * dacProvider = GetDeviceAttestationCredentialsProvider();

        hashStream.Clear();
        SuccessOrExit(err = hashStream.Begin());
        SuccessOrExit(err = hashStream.AddData(dac));
        SuccessOrExit(err = hashStream.AddData(ByteSpan(reinterpret_cast<const uint8_t *>(mTimestamp), strlen(mTimestamp))));
        SuccessOrExit(err = hashStream.AddData(nonce));
        SuccessOrExit(err = hashStream.AddData(ByteSpan(reinterpret_cast<const uint8_t *>(cert_id), strlen(cert_id))));
        SuccessOrExit(err = hashStream.Finish(mdSpan));

        SuccessOrExit(err = dacProvider->SignWithDeviceAttestationKey(mdSpan, signatureSpan));
        SuccessOrExit(err = signature.SetLength(signatureSpan.size()));

        SuccessOrExit(err = EcdsaRawSignatureToAsn1(kMAX_FE_Length, signatureSpan, derSignatureSpan));
    }

    base64SignatureLength = base64_encode_len(static_cast<int>(derSignatureSpan.size()));
    VerifyOrExit(base64Signature.Alloc(static_cast<size_t>(base64SignatureLength + 6)), err = CHIP_ERROR_NO_MEMORY);
    base64_encode(base64Signature.Get(), derSignatureSpan.data(), static_cast<int>(derSignatureSpan.size()));
    result = json_object_set_string(root_object, "signature", base64Signature.Get());
    VerifyOrExit(result == 0, err = CHIP_ERROR_INTERNAL);

    mJsonCrt = json_serialize_to_string_pretty(root_value);
    ChipLogProgress(AppServer, "X509 JSON certificate for obtaining operational credentials: \n%s", mJsonCrt);
    VerifyOrExit(base64JsonCrt.Alloc(static_cast<size_t>(base64_encode_len(static_cast<int>(strlen(mJsonCrt))))),
                 err = CHIP_ERROR_NO_MEMORY);
    base64_encode(base64JsonCrt.Get(), reinterpret_cast<const unsigned char *>(mJsonCrt), static_cast<int>(strlen(mJsonCrt)));
    mCertifier = certifier_api_easy_new();
    certifier_api_easy_set_opt(mCertifier, CERTIFIER_OPT_CFG_FILENAME, reinterpret_cast<void *>(mCertifierCfg));
    certifier_api_easy_set_opt(mCertifier, CERTIFIER_OPT_CRT, base64JsonCrt.Get());
    certifier_api_easy_set_opt(mCertifier, CERTIFIER_OPT_CN_PREFIX, operationalID);
    certifier_api_easy_set_opt(mCertifier, CERTIFIER_OPT_NODE_ID, nodeIdArray);

    base64_encode(base64CSR.Get(), reinterpret_cast<const unsigned char *>(csr.data()), static_cast<int>(csr.size()));
    if (!(certifier_api_easy_create_json_csr(mCertifier, reinterpret_cast<unsigned char *>(base64CSR.Get()), (char *) operationalID,
                                             &jsonCSR)))
    {
        ChipLogError(AppServer, "kProtocol_OpCredentials Error creating JSON CSR.");
        SuccessOrExit(err);
    }
    ChipLogProgress(AppServer, "CSR for: \n%s", jsonCSR);

    certifier_api_easy_set_opt(mCertifier, CERTIFIER_OPT_CA_INFO, reinterpret_cast<void *>(mAuthCertificate));

    ChipLogProgress(AppServer, "kProtocol_OpCredentials Obtaining operational credentials.");
    if (nullptr == (resp = DoHttpExchange(reinterpret_cast<uint8_t *>(jsonCSR), mCertifier)))
    {
        ChipLogError(AppServer, "kProtocol_OpCredentials Error obtaining HTTP response.");
        err = CHIP_ERROR_STATUS_REPORT_RECEIVED;
        SuccessOrExit(err);
    }
    if ((resp->error != 0) || (resp->payload == nullptr))
    {
        ChipLogError(AppServer, "kProtocol_OpCredentials Error in HTTP response:\n%s",
                     util_format_curl_error("certifiercommissioner_request_x509_certificate", resp->http_code, resp->error,
                                            resp->error_msg, resp->payload, __FILE__, __LINE__));
        err = CHIP_ERROR_STATUS_REPORT_RECEIVED;
        SuccessOrExit(err);
    }

    json_value_free(root_value);
    if (json_value_get_type(root_value = json_parse_string_with_comments(resp->payload)) != JSONObject)
    {
        ChipLogError(AppServer, "kProtocol_OpCredentials Error parsing HTTP response JSON.\n%s",
                     util_format_curl_error("certifiercommissioner_request_x509_certificate", resp->http_code, resp->error,
                                            "Could not parse JSON.  Expected it to be an array.", resp->payload, __FILE__,
                                            __LINE__));
        SuccessOrExit(err);
    }

    if (nullptr == (root_object = json_value_get_object(root_value)))
    {
        ChipLogError(AppServer, "kProtocol_OpCredentials Error parsing HTTP response JSON object.\n%s",
                     util_format_curl_error("certifiercommissioner_request_x509_certificate", resp->http_code, resp->error,
                                            "Could not parse JSON.  parsed_json_object_value is NULL!.", resp->payload, __FILE__,
                                            __LINE__));
        SuccessOrExit(err);
    }

    if (nullptr == (OpCertificateChainTemp = (json_object_get_string(root_object, "certificateChain"))))
    {
        ChipLogError(AppServer, "kProtocol_OpCredentials Error obtaining certificate chain from HTTP response JSON.\n%s",
                     util_format_curl_error("certifiercommissioner_request_x509_certificate", resp->http_code, resp->error,
                                            "Could not parse JSON.  certificate_chain is NULL!", resp->payload, __FILE__,
                                            __LINE__));
        SuccessOrExit(err);
    }

    pkcs7OpCertBufLen = strlen(OpCertificateChainTemp);
    VerifyOrReturnError(pkcs7OpCert.size() > pkcs7OpCertBufLen, CHIP_ERROR_BUFFER_TOO_SMALL);
    memcpy(pkcs7OpCert.data(), OpCertificateChainTemp, pkcs7OpCertBufLen);
    pkcs7OpCert.reduce_size(pkcs7OpCertBufLen);

exit:
    json_value_free(root_value);
    return err;
}

} // namespace Controller
} // namespace chip
