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

#ifndef SECTIGO_CLIENT_H
#define SECTIGO_CLIENT_H


#include <certifier/types.h>
#include <certifier/error.h>
#include <certifier/property_internal.h>
#include <certifier/certifier.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <pthread.h>

extern pthread_mutex_t lock;

#ifdef __cplusplus
extern "C" {
#endif


#define IMPULSE_URL "https://certs-dev.xpki.io/"
typedef struct{
const char * sectigo_auth_token;
const char * sectigo_common_name;
const char * sectigo_group_name;
const char * sectigo_group_email;
const char * sectigo_id;
const char * sectigo_owner_fname;
const char * sectigo_owner_lname;
const char * sectigo_employee_type;
const char * sectigo_server_platform;
bool sectigo_sensitive;
const char * sectigo_project_name;
const char * sectigo_business_justification;
const char * sectigo_subject_alt_names;
const char * sectigo_ip_addresses;
const char * sectigo_owner_phonenum;
const char * sectigo_owner_email;
const char * sectigo_cert_type;
const char * sectigo_url;
const char * sectigo_tracking_id;
const char * sectigo_source;


} get_cert_sectigo_param_t;


typedef enum{
    SECTIGO_CLIENT_SUCCESS = 0,
    SECTIGO_CLIENT_INVALID_ARGUMENT,
    SECTIGO_CLIENT_NOT_IMPLEMENTED,
    SECTIGO_CLIENT_ERROR_INTERNAL,

} SECTIGO_CLIENT_ERROR_CODE;

typedef enum
{
    SECTIGO_AUTH_X509,
    SECTIGO_AUTH_SAT,
} SECTIGO_AUTH_TYPE;

CertifierError sectigo_client_request_certificate(CertifierPropMap * props, const unsigned char * csr,
const char * node_address, const char * certifier_id, char ** out_cert);

CertifierError sectigo_generate_certificate_signing_request(Certifier *certifier, char **out_csr_pem);

Certifier * get_sectigo_certifier_instance();

SECTIGO_CLIENT_ERROR_CODE xc_sectigo_get_cert(get_cert_sectigo_param_t * params);

SECTIGO_CLIENT_ERROR_CODE xc_sectigo_get_default_cert_param(get_cert_sectigo_param_t * params);

#ifdef __cplusplus
}
#endif

#endif
