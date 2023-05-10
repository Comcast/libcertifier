/**
 * Copyright 2022 Comcast Cable Communications Management, LLC
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

#include "AppMain.h"
#include "LightingManager.h"
#include "binding-handler.h"
#include "main-common.h"

#include <CertifierDACProvider.h>

void MatterPostAttributeChangeCallback(const chip::app::ConcreteAttributePath & attributePath, uint8_t type,
                                       uint16_t size, uint8_t * value)
{
    if (attributePath.mClusterId == chip::app::Clusters::OnOff::Id &&
        attributePath.mAttributeId == chip::app::Clusters::OnOff::Attributes::OnOff::Id)
    {
        LightingMgr().InitiateAction(*value ? LightingManager::ON_ACTION : LightingManager::OFF_ACTION);
    }
}

int main(int argc, char * argv[])
{
    VerifyOrDie(ChipLinuxAppInit(argc, argv) == 0);
    VerifyOrDie(InitBindingHandlers() == CHIP_NO_ERROR);

    LightingMgr().Init([]() {
        system("./trafficlight off");
        return system("./trafficlight read") == 1 ? LightingManager::kState_On : LightingManager::kState_Off;
    });
    LightingMgr().SetCallbacks(
        [](LightingManager::Action_t action) {
            switch (action)
            {
            case LightingManager::Action_t::ON_ACTION:
                system("./trafficlight on");
                break;
            case LightingManager::Action_t::OFF_ACTION:
                system("./trafficlight off");
                break;
            default:
                break;
            }
        },
        [](LightingManager::Action_t a) {});

    LinuxDeviceOptions::GetInstance().dacProvider = chip::Credentials::Certifier::GetDACProvider();

    ChipLinuxAppMainLoop();
    ApplicationExit();

    return 0;
}
