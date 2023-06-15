/*
 *
 *    Copyright (c) 2022 Project CHIP Authors
 *    All rights reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include "CertifierOptions.h"
#include "CertifierDACProvider.h"

#include <app/server/Server.h>

using namespace chip::ArgParser;
using namespace chip::Credentials::Certifier;

using chip::ArgParser::OptionDef;
using chip::ArgParser::OptionSet;
using chip::ArgParser::PrintArgError;

constexpr uint16_t kOptionDacFilePath = 0xFF01;
constexpr uint16_t kOptionDacPassword = 0xFF02;

static chip::Optional<char *> g_dac_filepath;
static chip::Optional<char *> g_dac_password;

bool CertifierOptions::HandleOptions(const char * program, OptionSet * options, int identifier, const char * name,
                                     const char * value)
{
    bool retval                                 = true;
    CertifierDACProvider * certifierDACProvider = reinterpret_cast<CertifierDACProvider *>(GetDACProvider());

    switch (identifier)
    {
    case kOptionDacFilePath:
        g_dac_filepath.SetValue(const_cast<char *>(value));
        certifierDACProvider->SetCertifierToolDACFilepath(&g_dac_filepath);
        break;
    case kOptionDacPassword: {
        g_dac_password.SetValue(const_cast<char *>(value));
        certifierDACProvider->SetCertifierToolDACPassword(&g_dac_password);
        break;
    }
    default:
        PrintArgError("%s: INTERNAL ERROR: Unhandled option: %s\n", program, name);
        retval = false;
        break;
    }

    return retval;
}

OptionSet * CertifierOptions::GetOptions()
{
    static OptionDef optionsDef[] = {
        { "input-p12-path", kArgumentRequired, kOptionDacFilePath },
        { "input-p12-password", kArgumentRequired, kOptionDacPassword },
        {},
    };

    static OptionSet options = { CertifierOptions::HandleOptions, optionsDef, "PROGRAM OPTIONS",
                                 "  --input-p12-path <filepath>\n"
                                 "       A pkcs12 file bundled with a dac certificate chain of this device.\n"
                                 "  --input-p12-password <value>\n"
                                 "       Password to extract dac and keypair from the dac file.\n" };

    return &options;
}
