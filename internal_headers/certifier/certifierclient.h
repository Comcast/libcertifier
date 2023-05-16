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

#ifndef CERTIFIERCLIENT_H
#define CERTIFIERCLIENT_H

#include "certifier/error.h"
#include "certifier/property.h"
#include "certifier/property_internal.h"
#include "certifier/types.h"

#ifdef __cplusplus
extern "C" {
#endif

int certifierclient_init();

int certifierclient_destroy();

CertifierError certifierclient_request_x509_certificate(CertifierPropMap * props, const unsigned char * csr,
                                                        const char * node_address, const char * certifier_id, char ** out_cert);

CertifierError certifierclient_revoke_x509_certificate(CertifierPropMap * props, const unsigned char * digest,
                                                       const size_t digest_len);

CertifierError certifierclient_renew_x509_certificate(CertifierPropMap * props, const unsigned char * digest,
                                                      const size_t digest_len, char ** out_cert);

CertifierError certifierclient_check_certificate_status(CertifierPropMap * props, const unsigned char * digest,
                                                        const size_t digest_len);

#ifdef __cplusplus
}
#endif

#endif
