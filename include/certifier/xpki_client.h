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

#ifndef XPKI_CLIENT_H
#define XPKI_CLIENT_H

#include <certifier/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CERTIFIER_STATIC_URL "https://cert-static.xpki.io/v1/certifier"
#define DEFAULT_CERTIFIER_URL "https://certifier.xpki.io/v1/certifier"

typedef enum
{
    XPKI_CLIENT_SUCCESS = 0,
    XPKI_CLIENT_ERROR_INTERNAL,
    XPKI_CLIENT_INVALID_ARGUMENT,
    XPKI_CLIENT_NOT_IMPLEMENTED,
    XPKI_CLIENT_CERT_ALREADY_VALID,
    XPKI_CLIENT_ERROR_NO_MEMORY,
} XPKI_CLIENT_ERROR_CODE;

typedef enum
{
    XPKI_CLIENT_CERT_VALID           = 0,
    XPKI_CLIENT_CERT_ABOUT_TO_EXPIRE = 1 << 0,
    XPKI_CLIENT_CERT_EXPIRED         = 1 << 1,
    XPKI_CLIENT_CERT_NOT_YET_VALID   = 1 << 2,
    XPKI_CLIENT_CERT_REVOKED         = 1 << 3,
    XPKI_CLIENT_CERT_UNKNOWN         = 1 << 4,
    XPKI_CLIENT_CERT_INVALID         = 1 << 5,
} XPKI_CLIENT_CERT_STATUS;

typedef enum
{
    XPKI_AUTH_X509,
    XPKI_AUTH_SAT,
} XPKI_AUTH_TYPE;

/** @struct get_cert_param_t
 *  @brief This structure contains all parameters that can be manipulated for a certificate generation.
 *  @var get_cert_param_t::crt
 *  Contains the value of a CRT. Optional.
 *  @var get_cert_param_t::input_p12_path
 *  Contains the path to the PKCS12 Seed.
 *  @var get_cert_param_t::input_p12_password
 *  Contains the password for the PKCS12 Seed
 *  @var get_cert_param_t::output_p12_path.
 *  Contains the path where the resulting certificate shall be written to.
 *  @var get_cert_param_t::output_p12_password
 *  Contains the password for resulting certificate.
 *  @var get_cert_param_t::profile_name
 *  Selects the Profle Name/Certificate Issuer for the certificate being requested from the Server.
 *  @var get_cert_param_t::source_id
 *  Contains the value of the Request Source ID. Optional.
 *  @var get_cert_param_t::auth_token
 *  Contains the Authentication Token. Optional.
 *  @var get_cert_param_t::auth_type
 *  Selects the Authentication type when requesting a certificate to the Server.
 *  See XPKI_AUTH_TYPE enum for more details.
 *  @var get_cert_param_t::overwrite_p12
 *  Enables output file being overwritten if already existing.
 *  @var get_cert_param_t::validity_days
 *  Select the number of valid days the certificate being requested shall last.
 *  @var get_cert_param_t::lite
 *  Select to request a lite certificate.
 *  @var get_cert_param_t::product_id
 *  Choose the Product ID to be registered in the certificate being requested.
 *  Matter Only Cerificate Parameter
 *  @var get_cert_param_t::node_id
 *  Choose the Node ID to be registered in the certificate being requested.
 *  Matter Only Cerificate Parameter
 *  @var get_cert_param_t::fabric_id
 *  Choose the Fabric ID to be registered in the certificate being requested.
 *  Matter Only Cerificate Parameter
 *  @var get_cert_param_t::case_auth_tag
 *  Choose the Case Authentication Tag to be registered in the certificate being requested.
 *  Matter Only Cerificate Parameter
 *  @var get_cert_param_t::static_certifier
 *  Choose whether to use static certifier url for cert requests (Optional).
 *  @var get_cert_param_t::mac_address
 *  Mac Address (Mandatory only on RDK Devices).
 *  @var get_cert_param_t::serial_number
 *  Serial Number (Optional).
 *  @var get_cert_param_t::dns_san
 *  DNS Name added to Subject Alternate Name (SAN) field (Optional).
 *  @var get_cert_param_t::ip_san
 *  IP Address added to Subject Alternate Name (SAN) field (Optional).
 *  @var get_cert_param_t::email_san
 *  Email Address added to Subject Alternate Name (SAN) field (Optional).
 *  @var get_cert_param_t::common_name
 *  Contains the CN value field of the Certificate Subject (Optional).
 *  @var get_cert_param_t::domain
 *  Contains the domain of the CN value field of the Certificate Subject (Optional).
 */
typedef struct
{
    const char * crt;
    const char * input_p12_path;
    const char * input_p12_password;
    const char * output_p12_path;
    const char * output_p12_password;
    const char * profile_name;
    const char * source_id;
    const char * auth_token;
    XPKI_AUTH_TYPE auth_type;
    bool overwrite_p12;
    size_t validity_days;
    bool lite;
    ECC_KEY * keypair;
    // matter only parameters below
    uint16_t product_id;
    uint64_t node_id;
    uint64_t fabric_id;
    uint32_t case_auth_tag;
    // optional parameters below
    bool static_certifier;
    const char * mac_address;
    const char * serial_number;
    const char * dns_san;
    const char * ip_san;
    const char * email_san;
    const char * common_name;
    const char * domain;
    /* Certificate ID (sha1 hash) of the new certificate */
    void** cert_id_out;
} get_cert_param_t;

/** @struct get_cert_status_param_t
 *  @brief This structure contains all parameters that can be manipulated for getting certificate status or renew it.
 *  @var get_cert_status_param_t::p12_path
 *  Contains the path to the PKCS12 File.
 *  @var get_cert_status_param_t::p12_password
 *  Contains the password for the PKCS12 File.
 *  @var get_cert_status_param_t::static_certifier
 *  Choose whether to use static certifier url for cert requests.
 *  @var get_cert_status_param_t::source_id
 *  Contains the value of the Request Source ID. Optional.
 *  @var get_cert_status_param_t::auth_token
 *  Contains the Authentitcation Token. Optional.
 *  @var get_cert_status_param_t::auth_type
 *  Selects the Authentication type when requesting a certificate to the Server.
 */
typedef struct
{
    const char * p12_path;
    const char * p12_password;
    const char * source_id;
    const char * auth_token;
    XPKI_AUTH_TYPE auth_type;
    bool static_certifier;
} get_cert_status_param_t;

/** @struct get_cert_validity_param_t
 *  @brief This structure contains all parameters required for getting certificate validity.
 *  @var get_cert_validity_param_t::p12_path
 *  Contains the path to the PKCS12 File.
 *  @var get_cert_validity_param_t::p12_password
 *  Contains the password for the PKCS12 File.
 */
typedef struct
{
    const char * p12_path;
    const char * p12_password;
} get_cert_validity_param_t;

typedef get_cert_status_param_t renew_cert_param_t;

XPKI_CLIENT_ERROR_CODE xc_get_default_cert_param(get_cert_param_t * params);

XPKI_CLIENT_ERROR_CODE xc_get_default_cert_status_param(get_cert_status_param_t * params);

XPKI_CLIENT_ERROR_CODE xc_get_default_renew_cert_param(renew_cert_param_t * params);

XPKI_CLIENT_ERROR_CODE xc_get_default_cert_validity_param(get_cert_validity_param_t * params);

XPKI_CLIENT_ERROR_CODE xc_get_cert(get_cert_param_t * params);

XPKI_CLIENT_ERROR_CODE xc_renew_cert(renew_cert_param_t * params);

XPKI_CLIENT_ERROR_CODE xc_get_cert_status(get_cert_status_param_t * params, XPKI_CLIENT_CERT_STATUS * status);

XPKI_CLIENT_ERROR_CODE xc_get_cert_validity(get_cert_validity_param_t * params, XPKI_CLIENT_CERT_STATUS * status);

XPKI_CLIENT_ERROR_CODE xc_enable_logs(bool enable);

XPKI_AUTH_TYPE map_to_xpki_auth_type(const char * str);

XPKI_CLIENT_ERROR_CODE xc_print_cert_validity(const char * p12_path, const char * password);

#ifdef __cplusplus
}
#endif

#endif // XPKI_CLIENT_H
