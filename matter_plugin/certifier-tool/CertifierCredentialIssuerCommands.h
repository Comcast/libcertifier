/**
 * Copyright 2021-2023 Comcast Cable Communications Management, LLC
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

#include <CertifierDACProvider.h>
#include <CertifierOperationalCredentialsIssuer.h>

#include <commands/example/ExampleCredentialIssuerCommands.h>

class CertifierCredentialIssuerCommands : public ExampleCredentialIssuerCommands
{
public:
    void SetCertifierToolAuthenticationType(chip::Optional<char *> * authType)
    {
        mOpCredsIssuer.SetCertifierToolAuthenticationType(authType);
    }
    void SetCertifierToolSATToken(chip::Optional<char *> * satToken) { mOpCredsIssuer.SetCertifierToolSATToken(satToken); }

private:
    CHIP_ERROR InitializeCredentialsIssuer(chip::PersistentStorageDelegate & storage) override { return CHIP_NO_ERROR; }
    CHIP_ERROR SetupDeviceAttestation(chip::Controller::SetupParams & setupParams,
                                      const chip::Credentials::AttestationTrustStore * trustStore) override
    {
        ReturnErrorOnFailure(ExampleCredentialIssuerCommands::SetupDeviceAttestation(setupParams, trustStore));

        chip::Credentials::SetDeviceAttestationCredentialsProvider(chip::Credentials::Certifier::GetDACProvider());

        return CHIP_NO_ERROR;
    }
    chip::Controller::OperationalCredentialsDelegate * GetCredentialIssuer() override { return &mOpCredsIssuer; }
    void SetCredentialIssuerCATValues(chip::CATValues cats) override { mOpCredsIssuer.SetCATValuesForNextNOCRequest(cats); }
    CHIP_ERROR GenerateControllerNOCChain(chip::NodeId nodeId, chip::FabricId fabricId, const chip::CATValues & cats,
                                          chip::Crypto::P256Keypair & keypair, chip::MutableByteSpan & rcac,
                                          chip::MutableByteSpan & icac, chip::MutableByteSpan & noc) override
    {
        uint8_t csrBuffer[chip::Crypto::kMAX_CSR_Length];
        size_t csrBufferLength = sizeof(csrBuffer);
        uint8_t nonceBuffer[chip::Controller::kCSRNonceLength];
        chip::MutableByteSpan nonceSpan(nonceBuffer);

        ReturnErrorOnFailure(keypair.NewCertificateSigningRequest(csrBuffer, csrBufferLength));
        VerifyOrReturnError(csrBufferLength < UINT8_MAX, CHIP_ERROR_INTERNAL);

        ReturnErrorOnFailure(mOpCredsIssuer.ObtainCsrNonce(nonceSpan));

        // TODO: Add CATs support
        return mOpCredsIssuer.GenerateNOCChainAfterValidation(nodeId, fabricId, chip::ByteSpan(csrBuffer, csrBufferLength),
                                                              nonceSpan, rcac, icac, noc);
    }

    chip::Controller::CertifierOperationalCredentialsIssuer mOpCredsIssuer;
};
