/**
 * Copyright 2019 Comcast Cable Communications Management, LLC
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

#define _POSIX_C_SOURCE 2

// Includes
#include "certifier/certifier_api_easy.h"
#include "certifier/types.h"
#include "certifier/log.h"

// Main
int main(int argc, char *argv[])
{
    int return_code = 0;
    CERTIFIER *easy = certifier_api_easy_new();

    certifier_api_easy_set_cli_args(easy, argc, argv);
    certifier_api_easy_set_mode(easy, certifier_api_easy_get_mode(easy));
    return_code = certifier_api_easy_perform(easy);

    const char *result = certifier_api_easy_get_result_json(easy);

    if (result != NULL)
    {
        log_info(result);
    }

    certifier_api_easy_destroy(easy);

    return return_code != 0;
}
