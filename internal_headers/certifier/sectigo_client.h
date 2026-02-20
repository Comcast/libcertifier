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
typedef struct {
    const char * auth_token;
    const char * common_name;
    const char * group_name;
    const char * group_email;
    const char * id;
    const char * owner_first_name;
    const char * owner_last_name;
    const char * project_name;
    const char * business_justification;
    const char * subject_alt_names;
    const char * owner_email;
    const char * sectigo_url;
    const char * devhub_id;
    size_t validity_days;
    const char * key_type;
} sectigo_get_cert_param_t;

typedef struct {
    const char * auth_token;
    const char * group_name;
    const char * group_email;
    const char * status;
    const char * common_name;
    const char * offset;
    size_t limit;
    const char * start_date;
    const char * end_date;
    size_t validity_start_date;
    size_t validity_end_date;
    const char * certificate_order;
    const char * is_cn_in_san;
    const char * request_type;
    const char * timestamp;
    const char * devhub_id;
    const char * key_type;
} sectigo_search_cert_param_t;

typedef struct {
    const char * auth_token;
    const char * common_name;
    const char * serial_number;
    const char * certificate_id;
    const char * requestor_email;
} sectigo_renew_cert_param_t;

typedef struct {
    const char * auth_token;
    const char * common_name;
    const char * serial_number;
    const char * certificate_id;
    const char * requestor_email;
    const char * revocation_request_reason;
} sectigo_revoke_cert_param_t;

typedef struct {
    const char * certificate_path;
} sectigo_ocsp_status_param_t;

typedef enum {
    SECTIGO_CLIENT_SUCCESS = 0,
    SECTIGO_CLIENT_INVALID_ARGUMENT,
    SECTIGO_CLIENT_NOT_IMPLEMENTED,
    SECTIGO_CLIENT_ERROR_INTERNAL,

} SECTIGO_CLIENT_ERROR_CODE;

typedef enum {
    SECTIGO_AUTH_X509,
    SECTIGO_AUTH_SAT,
} SECTIGO_AUTH_TYPE;

CertifierError sectigo_client_request_certificate(CertifierPropMap * props, const unsigned char * csr,
const char * node_address, const char * certifier_id, char ** out_cert);

CertifierError sectigo_client_search_certificates(CertifierPropMap * props);

CertifierError sectigo_client_renew_certificate(CertifierPropMap * props);

CertifierError sectigo_client_revoke_certificate(CertifierPropMap * props);

CertifierError sectigo_client_ocsp_status(CertifierPropMap * props);

CertifierError sectigo_generate_certificate_signing_request(Certifier *certifier, char **out_csr_pem);

Certifier * get_sectigo_certifier_instance();

SECTIGO_CLIENT_ERROR_CODE xc_sectigo_get_cert(sectigo_get_cert_param_t * params);

SECTIGO_CLIENT_ERROR_CODE xc_sectigo_search_cert(sectigo_search_cert_param_t * params);

SECTIGO_CLIENT_ERROR_CODE xc_sectigo_renew_cert(sectigo_renew_cert_param_t * params);

SECTIGO_CLIENT_ERROR_CODE xc_sectigo_revoke_cert(sectigo_revoke_cert_param_t * params);

SECTIGO_CLIENT_ERROR_CODE xc_sectigo_ocsp_status(sectigo_ocsp_status_param_t * params);

SECTIGO_CLIENT_ERROR_CODE xc_sectigo_get_default_cert_param(sectigo_get_cert_param_t * params);

SECTIGO_CLIENT_ERROR_CODE xc_sectigo_get_default_renew_cert_param(sectigo_renew_cert_param_t * params);

SECTIGO_CLIENT_ERROR_CODE xc_sectigo_get_default_revoke_cert_param(sectigo_revoke_cert_param_t * params);

#ifdef __cplusplus
}
#endif

#endif
