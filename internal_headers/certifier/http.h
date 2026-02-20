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

#ifndef CCLIENT_HTTP_H_
#define CCLIENT_HTTP_H_

#include "certifier/certifier_api_easy.h"
#include "certifier/log.h"
#include "certifier/property_internal.h"
#include "certifier/types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define http_set_curlopt(curl, option, value)                                                                                      \
    {                                                                                                                              \
        CURLcode rc = curl_easy_setopt(curl, option, value);                                                                       \
        if (rc != CURLE_OK)                                                                                                        \
        {                                                                                                                          \
            log_warn("cURL: Unable to set option [%d]: curl returned [%d]: %s", option, rc, curl_easy_strerror(rc));               \
        }                                                                                                                          \
    }

typedef struct http_response
{
    const char * error_msg;
    const char * payload;
    size_t payload_len;
    int http_code;
    int error;
} http_response;

int http_init(void);

int http_destroy(void);

http_response * http_get(const CertifierPropMap * props, const char * url, const char * http_headers[]);

http_response * http_post(const CertifierPropMap * props, const char * url, const char * http_headers[], const char * body);

http_response * http_put(const CertifierPropMap * props, const char * url, const char * http_headers[], const char * body);

void http_free_response(http_response * resp);

#ifdef __cplusplus
}
#endif

#endif
