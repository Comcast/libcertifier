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
#pragma once

#include <controller/OperationalCredentialsDelegate.h>
#include <credentials/CHIPCert.h>
#include <crypto/CHIPCryptoPAL.h>
#include <lib/core/PeerId.h>
#include <lib/support/DLLUtil.h>

struct CERTIFIER;
struct http_response;

namespace chip {
namespace Controller {

class DLL_EXPORT CertifierOperationalCredentialsIssuer : public OperationalCredentialsDelegate
{
public:
    virtual ~CertifierOperationalCredentialsIssuer();

    CertifierOperationalCredentialsIssuer();

    CHIP_ERROR GenerateNOCChain(const ByteSpan & csrElements, const ByteSpan & csrNonce, const ByteSpan & attestationSignature,
                                const ByteSpan & attestationChallenge, const ByteSpan & DAC, const ByteSpan & PAI,
                                Callback::Callback<OnNOCChainGeneration> * onCompletion) override;

    void SetNodeIdForNextNOCRequest(NodeId nodeId) override { mNodeId = nodeId; }
    void SetFabricIdForNextNOCRequest(FabricId fabricId) override { mFabricId = fabricId; }
    void SetCATValuesForNextNOCRequest(CATValues cats) { mNextCATs = cats; }

    CHIP_ERROR ObtainCsrNonce(MutableByteSpan & csrNonce) override;

    CHIP_ERROR GenerateNOCChainAfterValidation(NodeId nodeId, FabricId fabricId, const ByteSpan & csr, const ByteSpan & nonce,
                                               MutableByteSpan & rcac, MutableByteSpan & icac, MutableByteSpan & noc);

    CHIP_ERROR SetAuthCertificate(const char * authCertPath, size_t len);
    CHIP_ERROR SetCertConfig(const char * certCfgPath, size_t len);

    void SetAutheticationType(Optional<char *> * authType) { mAuthType = authType; }
    void SetSATToken(Optional<char *> * satToken) { mSatToken = satToken; }

private:
    static constexpr size_t kMaxSatTokenSize = 800;

    NodeId mNodeId      = 1;
    FabricId mFabricId  = 1;
    CATValues mNextCATs = kUndefinedCATs;

    CERTIFIER * mCertifier     = nullptr;
    char mAuthCertificate[256] = "libcertifier-cert.crt";
    char mCertifierCfg[256]    = "libcertifier.cfg";
    char mTimestamp[21]        = "";

    Optional<char *> * mAuthType = nullptr;
    Optional<char *> * mSatToken = nullptr;

    void GetTimestampForCertifying();
    http_response * DoHttpExchange(uint8_t * buffer, CERTIFIER * certifier);
    CHIP_ERROR ObtainOpCert(const ByteSpan & csr, const ByteSpan & nonce, MutableByteSpan & pkcs7OpCert, NodeId nodeId,
                            FabricId fabricId);
};

} // namespace Controller
} // namespace chip
