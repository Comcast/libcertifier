/**
 * Copyright 2021-22 Comcast Cable Communications Management, LLC
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

#include "CertifierCredentialIssuerCommands.h"
#include "commands/common/Commands.h"

#include "commands/delay/Commands.h"
#include "commands/discover/Commands.h"
#include "commands/group/Commands.h"
#include "commands/interactive/Commands.h"
#include "commands/pairing/Commands.h"
#include "commands/payload/Commands.h"
#include "commands/storage/Commands.h"

#include <zap-generated/cluster/Commands.h>
#include <zap-generated/test/Commands.h>

#include "CertifierDACProvider.h"

using namespace chip::Credentials::Certifier;

void registerCommandsCertifierPairing(Commands & commands, CredentialIssuerCommands * credsIssuerConfig);

// ================================================================================
// Main Code
// ================================================================================
int main(int argc, char * argv[])
{
    CertifierCredentialIssuerCommands credIssuerCommands;
    Commands commands;
    registerCommandsDelay(commands, &credIssuerCommands);
    registerCommandsDiscover(commands, &credIssuerCommands);
    registerCommandsInteractive(commands, &credIssuerCommands);
    registerCommandsPayload(commands);
    registerCommandsPairing(commands, &credIssuerCommands);
    registerCommandsCertifierPairing(commands, &credIssuerCommands);
    registerCommandsTests(commands, &credIssuerCommands);
    registerCommandsGroup(commands, &credIssuerCommands);
    registerClusters(commands, &credIssuerCommands);
    registerCommandsStorage(commands);

    return commands.Run(argc, argv);
}

class CertifierPairOnNetwork : public PairingCommand
{
public:
    CertifierPairOnNetwork(CredentialIssuerCommands * credsIssuerConfig) :
        PairingCommand("onnetwork-certifier", PairingMode::OnNetwork, PairingNetworkType::None, credsIssuerConfig),
        m_certifier_credential_issuer_config(reinterpret_cast<CertifierCredentialIssuerCommands *>(credsIssuerConfig)),
        m_certifier_dac_provider(reinterpret_cast<CertifierDACProvider *>(GetDACProvider()))
    {
        AddArgument("dac-filepath", &m_dac_filepath, "A PKCS12 file bundled with a dac certificate chain for this device");
        AddArgument("dac-password", &m_dac_password, "Password to extract dac and keypair from the dac file");
        AddArgument("sat", 0, 1, &m_sat_authentication, "Enable XPKI SAT Token Autentication");
        AddArgument("sat-token", &m_sat_token, "A SAT Token to be used for XPKI authentication");
        m_certifier_credential_issuer_config->SetSATAuthentication(&m_sat_authentication);
        m_certifier_credential_issuer_config->SetSATToken(&m_sat_token);
        m_certifier_dac_provider->SetDACFilepath(&m_dac_filepath);
        m_certifier_dac_provider->SetDACPassword(&m_dac_password);
    }

private:
    chip::Optional<char *> m_dac_filepath;
    chip::Optional<char *> m_dac_password;
    chip::Optional<char *> m_sat_token;
    chip::Optional<bool> m_sat_authentication;

    CertifierCredentialIssuerCommands * m_certifier_credential_issuer_config = nullptr;
    CertifierDACProvider * m_certifier_dac_provider                          = nullptr;
};

void registerCommandsCertifierPairing(Commands & commands, CredentialIssuerCommands * credsIssuerConfig)
{
    const char * clusterName = "Pairing";

    commands_list clusterCommands = {
        make_unique<CertifierPairOnNetwork>(credsIssuerConfig),
    };

    commands.Register(clusterName, clusterCommands);
}
