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

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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
} XPKI_CLIENT_CERT_STATUS;

typedef enum
{
    XPKI_AUTH_X509_CRT,
    XPKI_AUTH_TOKEN,
} XPKI_AUTH_TYPE;

#define FOREACH_PROFILE_NAME(PROFILE_NAME)                                                                                         \
    PROFILE_NAME(Comcast_RDKDRI_Issuing_ECC_ICA)                                                                                   \
    PROFILE_NAME(Comcast_RDK_Device_Issuing_ECC_ICA)                                                                               \
    PROFILE_NAME(Comcast_RDK_Issuing_ECC_ICA)                                                                                      \
    PROFILE_NAME(NSE_Platform_Services_Cassandra_RSA_ICA)                                                                          \
    PROFILE_NAME(NSE_Platform_Services_Hadoop_RSA_ICA)                                                                             \
    PROFILE_NAME(NSE_Platform_Services_Kafka_RSA_ICA)                                                                              \
    PROFILE_NAME(NSE_Platform_Services_VSG_RSA_ICA)                                                                                \
    PROFILE_NAME(OTT_Issuing_ECC_ICA)                                                                                              \
    PROFILE_NAME(SAT_NG_Issuing_ECC_ICA)                                                                                           \
    PROFILE_NAME(Sky_RDKDRI_Issuing_ECC_ICA)                                                                                       \
    PROFILE_NAME(Sky_RDK_Device_Issuing_ECC_ICA)                                                                                   \
    PROFILE_NAME(Sky_RDK_Issuing_ECC_ICA)                                                                                          \
    PROFILE_NAME(TPX_Advanced_Voice_CPE_RSA_ICA)                                                                                   \
    PROFILE_NAME(XFN_AS_PAI_1)                                                                                                     \
    PROFILE_NAME(XFN_DL_PAI_1)                                                                                                     \
    PROFILE_NAME(XFN_DL_PAI_1_Class_3)                                                                                             \
    PROFILE_NAME(XFN_Matter_OP_Class_3_ICA)                                                                                        \
    PROFILE_NAME(XFN_Matter_OP_ICA)                                                                                                \
    PROFILE_NAME(Xfinity_Default_Issuing_ECC_ICA)                                                                                  \
    PROFILE_NAME(Xfinity_Digital_Home_Issuing_RSA_ICA)                                                                             \
    PROFILE_NAME(Xfinity_Remote_Device_Issuing_RSA_ICA)                                                                            \
    PROFILE_NAME(Xfinity_Subscriber_Issuing_ECC_ICA)                                                                               \
    PROFILE_NAME(Xfinity_Subscriber_Issuing_RSA_ICA)

#define GENERATE_ENUM(ENUM) ENUM,
#define GENERATE_STRING(STRING) #STRING,

typedef enum
{
    FOREACH_PROFILE_NAME(GENERATE_ENUM) XPKI_PROFILE_MAX
} XPKI_PROFILE_NAME;

/** @struct get_cert_param_t
 *  @brief This structure contains all parameters that can be manipulated for a certificate generation.
 *  @var get_cert_param_t::input_p12_path
 *  Contains the path to the PKCS12 Seed.
 *  @var get_cert_param_t::input_p12_password
 *  Contains the password for the PKCS12 Seed
 *  @var get_cert_param_t::output_p12_path.
 *  Contains the path where the resulting certificate shall be written to.
 *  @var get_cert_param_t::output_p12_password
 *  Contains the password for resulting certificate.
 *  @var get_cert_param_t::auth_type
 *  Selects the Authentication type when requesting a certificate to the Server.
 *  See XPKI_AUTH_TYPE enum for more details.
 *  @var get_cert_param_t::profile_name
 *  Selects the Profle Name/Certificate Issuer for the certificate being requested from the Server.
 *  See XPKI_PROFILE_NAME enum for more details.
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
 *  Choose the Case Authentaiction Tag to be registered in the certificate being requested.
 *  Matter Only Cerificate Parameter
 */
typedef struct
{
    const char * input_p12_path;
    const char * input_p12_password;
    const char * output_p12_path;
    const char * output_p12_password;
    XPKI_AUTH_TYPE auth_type;
    XPKI_PROFILE_NAME profile_name;
    bool overwrite_p12;
    size_t validity_days;
    bool lite;
    // matter only parameters below
    uint16_t product_id;
    uint64_t node_id;
    uint64_t fabric_id;
    uint32_t case_auth_tag;
} get_cert_param_t;

XPKI_CLIENT_ERROR_CODE xc_get_default_cert_param(get_cert_param_t * params);

XPKI_CLIENT_ERROR_CODE xc_get_cert(get_cert_param_t * params);

XPKI_CLIENT_ERROR_CODE xc_renew_cert(const char * p12_path, const char * password);

XPKI_CLIENT_CERT_STATUS xc_get_cert_status(const char * p12_path, const char * password);

#ifdef __cplusplus
}
#endif

#endif // XPKI_CLIENT_H
