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

#ifndef PROPERTY_H
#define PROPERTY_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup props Ledger configuration properties
 * @{
 */

typedef enum CERTIFIER_OPT
{
    /**
     * Set a configuration filename containing settings.
     * @note Dynamic property
     * @note Setting this property via certifier_set_property will reset all settings prior to loading.
     * @post The file at the given path is loaded and any options are set (when the file exists and is valid).
     */
    CERTIFIER_OPT_CFG_FILENAME         = 1,
    CERTIFIER_OPT_AUTH_TYPE            = 2,
    CERTIFIER_OPT_CERTIFIER_URL        = 3,
    CERTIFIER_OPT_HTTP_TIMEOUT         = 4,
    CERTIFIER_OPT_HTTP_CONNECT_TIMEOUT = 5,
    CERTIFIER_OPT_INPUT_P12_PATH       = 6,
    CERTIFIER_OPT_INPUT_P12_PASSWORD   = 7,
    CERTIFIER_OPT_OUTPUT_P12_PATH      = 8,
    CERTIFIER_OPT_OUTPUT_P12_PASSWORD  = 9,
    CERTIFIER_OPT_CA_INFO              = 10,
    CERTIFIER_OPT_CA_PATH              = 11,
    CERTIFIER_OPT_CRT                  = 12,
    CERTIFIER_OPT_PROFILE_NAME         = 13,

    /**
     * Bitmap containing boolean options (read-only).
     * @see ledger_property_set
     * @see CERTIFIER_OPT_OPTION for bits and CERTIFIER_OPT for available options
     * @note value type: int
     */
    CERTIFIER_OPT_OPTIONS      = 14,
    CERTIFIER_OPT_ECC_CURVE_ID = 15,
    CERTIFIER_OPT_SYSTEM_ID    = 16,
    CERTIFIER_OPT_FABRIC_ID    = 17,
    CERTIFIER_OPT_PRODUCT_ID   = 18,
    // 19 is unused
    CERTIFIER_OPT_LOG_FILENAME = 20,
    CERTIFIER_OPT_LOG_LEVEL    = 21,
    // 22 is unused
    CERTIFIER_OPT_AUTH_TOKEN  = 23,
    CERTIFIER_OPT_OUTPUT_NODE = 24,
    CERTIFIER_OPT_TARGET_NODE = 25,
    CERTIFIER_OPT_ACTION      = 26,
    CERTIFIER_OPT_INPUT_NODE  = 27,
    CERTIFIER_OPT_NODE_ID     = 28,
    CERTIFIER_OPT_AUTH_TAG_1  = 29,
    /**
     * Set these enums (30-32) to request certificates with X.509 subjectAltNames (otherName types).
     * @note value type: string
     */
    CERTIFIER_OPT_DNS_SAN   = 30,
    CERTIFIER_OPT_IP_SAN    = 31,
    CERTIFIER_OPT_EMAIL_SAN = 32,
    // 33 - 36 are unused
    CERTIFIER_OPT_LOG_MAX_SIZE = 37,
    // 38,39 are unused
    // 40 - 43 are unused
    CERTIFIER_OPT_TRACKING_ID = 44,

    /**
     * Set the request source. Set this to an identifier, such as the firmware version.
     * @warning This must be set before making any registration requests and cannot be empty.
     * @example HomeHub-10.01.00.000000
     */
    CERTIFIER_OPT_SOURCE        = 45,
    CERTIFIER_OPT_CN_PREFIX     = 46,
    CERTIFIER_OPT_VALIDITY_DAYS = 47,
    CERTIFIER_OPT_EXT_KEY_USAGE = 48,
    CERTIFIER_OPT_DOMAIN        = 49,

    /**
     * Set a log callback function
     * @note value type: CERTIFIER_LOG_callback
     * @see CERTIFIER_LOG_callback
     */
    CERTIFIER_OPT_LOG_FUNCTION,

    /**
     * Set the minimum time that the certificate must remain valid before
     * certifier_register() will consider the certificate is nearly expired.
     * @note value type: int
     */
    CERTIFIER_OPT_CERT_MIN_TIME_LEFT_S,

    /* The following must be maintained in the same order as CERTIFIER_OPT_OPTIONs below */

    /**
     * Do not use directly.
     */
    CERTIFIER_OPT_BOOL_FIRST,

    /**
     * Enable HTTP debug
     * @note value type: bool
     */
    CERTIFIER_OPT_DEBUG_HTTP = CERTIFIER_OPT_BOOL_FIRST,

    /**
     * Enable increased verbosity HTTP debug/s
     * @note value type: bool
     */
    CERTIFIER_OPT_TRACE_HTTP,

    /**
     * Disable any existing keystore when registering.
     * This can be set, for example, when attempting to recover from a corrupted keystore, or to force a re-key.
     * @note The node address and common name will be regenerated upon successful registration.
     * @note value type: bool
     */
    CERTIFIER_OPT_FORCE_REGISTRATION,

    /**
     * @note value type: bool
     */
    CERTIFIER_OPT_MEASURE_PERFORMANCE,

    /**
     * @note value type: bool
     */
    CERTIFIER_OPT_CERTIFICATE_LITE,

    /**
     * @note value type: bool
     */
    CERTIFIER_OPT_USE_SCOPES,

    /**
     * @note value type: string
     */

    CERTIFIER_OPT_MAC_ADDRESS,

    /**
     * Simulate the "not-valid-before" date.
     * @note value type: ASN.1 time string in the format 'YYYYMMDDHHMMSSZ'
     */
    CERTIFIER_OPT_SIMULATION_CERT_EXP_DATE_BEFORE,

    /**
     * Simulate the "not-valid-after" date.
     * @note value type: ASN.1 time string in the format 'YYYYMMDDHHMMSSZ'
     */
    CERTIFIER_OPT_SIMULATION_CERT_EXP_DATE_AFTER,

    /**
     * @brief choose the amount of time (in seconds) that the certifierd
     * daemon shall sleep before * trying to renew a set of certificates
     *
     * @note value type: int
     */
    CERTIFIER_OPT_AUTORENEW_INTERVAL,

    /**
     * @brief choose the path where daemon will look-up for certificates
     * to be renewed
     *
     * @note value type: string
     */
    CERTIFIER_OPT_AUTORENEW_CERTS_PATH_LIST,

    /**
     * @brief if non NULL, an allocated X509_CERT certificate will be
     * placed here
     *
     * @note value type: X509_CERT *
     */
    CERTIFIER_OPT_CERT_X509_OUT,

    /**
     * @brief optional fields to set mTLS certificate (P12)
     * and its password
     *
     * @note value type: string
     */
    CERTIFIER_OPT_MTLS_P12_PATH,
    CERTIFIER_OPT_MTLS_P12_PASSWORD,
    
    CERTIFIER_OPT_SECTIGO_AUTH_TOKEN,
    CERTIFIER_OPT_SECTIGO_COMMON_NAME,
    CERTIFIER_OPT_SECTIGO_GROUP_NAME,
    CERTIFIER_OPT_SECTIGO_GROUP_EMAIL,
    CERTIFIER_OPT_SECTIGO_ID,
    CERTIFIER_OPT_SECTIGO_OWNER_FIRST_NAME,
    CERTIFIER_OPT_SECTIGO_OWNER_LAST_NAME,
    CERTIFIER_OPT_SECTIGO_PROJECT_NAME,
    CERTIFIER_OPT_SECTIGO_BUSINESS_JUSTIFICATION,
    CERTIFIER_OPT_SECTIGO_SUBJECT_ALT_NAMES,
    CERTIFIER_OPT_SECTIGO_OWNER_EMAIL,
    CERTIFIER_OPT_SECTIGO_URL,
    CERTIFIER_OPT_SECTIGO_DEVHUB_ID,
    CERTIFIER_OPT_SECTIGO_VALIDITY_DAYS,
    CERTIFIER_OPT_SECTIGO_KEY_TYPE,
    CERTIFIER_OPT_SECTIGO_SERIAL_NUMBER,
    CERTIFIER_OPT_SECTIGO_CERTIFICATE_ID,
    CERTIFIER_OPT_SECTIGO_REQUESTOR_EMAIL,
    CERTIFIER_OPT_SECTIGO_REVOCATION_REQUEST_REASON,
    CERTIFIER_OPT_SECTIGO_STATUS,
    CERTIFIER_OPT_SECTIGO_OFFSET,
    CERTIFIER_OPT_SECTIGO_LIMIT,
    CERTIFIER_OPT_SECTIGO_START_DATE,
    CERTIFIER_OPT_SECTIGO_END_DATE,
    CERTIFIER_OPT_SECTIGO_VALIDITY_START_DATE,
    CERTIFIER_OPT_SECTIGO_VALIDITY_END_DATE,
    CERTIFIER_OPT_SECTIGO_CERTIFICATE_ORDER,
    CERTIFIER_OPT_SECTIGO_IS_CN_IN_SAN,
    CERTIFIER_OPT_SECTIGO_REQUEST_TYPE,
    CERTIFIER_OPT_SECTIGO_TIMESTAMP,
    CERTIFIER_OPT_SECTIGO_CERT_PATH

} CERTIFIER_OPT;

typedef enum
{
    CERTIFIER_OPTION_DEBUG_HTTP          = 1,
    CERTIFIER_OPTION_TRACE_HTTP          = 2,
    CERTIFIER_OPTION_FORCE_REGISTRATION  = 4,
    CERTIFIER_OPTION_MEASURE_PERFORMANCE = 8,
    CERTIFIER_OPTION_CERTIFICATE_LITE    = 16,
    CERTIFIER_OPTION_USE_SCOPES          = 32,
    // 32, 64, 128, 256, 512, 1024 are unused
} CERTIFIER_OPT_OPTION;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* PROPERTY_H */
