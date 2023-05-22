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

#include <credentials/DeviceAttestationCredsProvider.h>
#include <lib/core/Optional.h>

namespace chip {
namespace Credentials {
namespace Certifier {

DeviceAttestationCredentialsProvider * GetDACProvider();

namespace {

class CertifierDACProvider : public DeviceAttestationCredentialsProvider
{
public:
    CHIP_ERROR GetCertificationDeclaration(MutableByteSpan & out_cd_buffer) override;
    CHIP_ERROR GetFirmwareInformation(MutableByteSpan & out_firmware_info_buffer) override;
    CHIP_ERROR GetDeviceAttestationCert(MutableByteSpan & out_dac_buffer) override;
    CHIP_ERROR GetProductAttestationIntermediateCert(MutableByteSpan & out_pai_buffer) override;
    CHIP_ERROR SignWithDeviceAttestationKey(const ByteSpan & message_to_sign, MutableByteSpan & out_signature_buffer) override;

    void SetDACFilepath(Optional<char *> * dac_filepath) { m_dac_filepath = dac_filepath; }
    void SetDACPassword(Optional<char *> * dac_password) { m_dac_password = dac_password; }

private:
    char kDefaultDacFilepath[8] = "dac.p12";
    char kDefaultDacPassword[9] = "changeit";

    Optional<char *> * m_dac_filepath = nullptr;
    Optional<char *> * m_dac_password = nullptr;
};

} // namespace

} // namespace Certifier
} // namespace Credentials
} // namespace chip
