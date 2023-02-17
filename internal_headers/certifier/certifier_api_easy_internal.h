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

#ifndef CERTIFIER_API_EASY_INTERNAL_H
#define CERTIFIER_API_EASY_INTERNAL_H

#include "certifier/types.h"
#include "certifier/http.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Send a CSR to HTTP server
 * @param easy
 * @param url
 * @param http_headers
 * @param csr
 * @return HTTP response
 */
http_response * certifier_api_easy_http_post(const CERTIFIER * easy, const char * url, const char * http_headers[],
                                             const char * csr);

int certifier_api_easy_set_keys_and_node_address(CERTIFIER * easy, ECC_KEY * new_key);

void certifier_api_easy_set_ecc_key(CERTIFIER * easy, const ECC_KEY * key);

const ECC_KEY * certifier_api_easy_get_priv_key(CERTIFIER * easy);

int certifier_api_easy_create_json_csr(CERTIFIER * easy, unsigned char * csr, char * node_address, char ** json_csr);

const char * certifier_api_easy_get_node_address(CERTIFIER * easy);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif // CERTIFIER_API_EASY_INTERNAL_H
