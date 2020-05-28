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

#ifndef LIBLEDGER_certifier_INTERNAL_H
#define LIBLEDGER_certifier_INTERNAL_H

#include "certifier/certifier.h"
#include "certifier/property_internal.h"
#include "certifier/security.h"
#include "certifier/types.h"

#define VERY_SMALL_STRING_SIZE 32
#define SMALL_STRING_SIZE 64
#define MEDIUM_STRING_SIZE 256
#define LARGE_STRING_SIZE 1024
#define VERY_LARGE_STRING_SIZE 2048
#define MAX_STACK_SIZE 10000

/**
 * @defgroup certifier-internal Ledger private API
 * @{
 */

#define NULL_CHECK(p)                                                   \
if (p == NULL)                                                          \
    return CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1

/**
 * Get the property set (libledger settings)
 * @param certifier
 * @return
 * @note for unit testing only!
 */
CertifierPropMap *_certifier_get_properties(Certifier *certifier);

/**
 * Set the x509 certificate
 * @param certifier
 * @param der_cert
 * @note for unit testing only!
 */
void _certifier_set_x509_cert(Certifier *certifier, const X509_CERT *cert);

/**
 * Set the private ECC key
 * @param certifier
 * @param key
 * @note for unit testing only!/s
 */
void _certifier_set_ecc_key(Certifier *certifier, const ECC_KEY *key);

/**
 * @}
 */

#endif //LIBLEDGER_certifier_INTERNAL_H
