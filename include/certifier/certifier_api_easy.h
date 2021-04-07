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

#ifndef CERTIFIER_API_EASY_H
#define CERTIFIER_API_EASY_H

#include "certifier.h"
#include "certifier/property.h"
#include "certifier/types.h"

typedef struct CERTIFIER CERTIFIER;

typedef struct http_response http_response;

/**
 * Modes for certifier_api_easy_perform.
 * @note Postconditions are true only after calling certifier_api_easy_perform and receiving a 0 (OK) result code.
 */
typedef enum {
    CERTIFIER_MODE_NONE = 0,
    /**
     * Register a device.
     *
     * @pre CERTIFIER_OPT_KEYSTORE contains a valid certificate OR certifier_api_easy_perform()
     *      was invoked with CERTIFIER_MODE_CREATE_*_CRT set.
     *
     *  The following options are set:
     *
     *  - CERTIFIER_OPT_KEYSTORE <br>
     *  - CERTIFIER_OPT_PASSWORD
     *
     * @see CERTIFIER_MODE_GET_CERT_STATUS
     * @see CERTIFIER_MODE_CLIENT_APP
     * @post The file at &lt;CERTIFIER_OPT_KEYSTORE&gt;.p12 contains a keypair and client certificate
     * @post the certifier ID is available in certifier_api_easy_get_result.
     */
            CERTIFIER_MODE_REGISTER = 1,
    //2, 4, 8 & 16 are unused
    /**
     * Generate a node address based on CERTIFIER_OPT_OUTPUT_NODE
     * For devices, this is the DER public key
     * For applications, this is the certifier ID
     * @pre CERTIFIER_OPT_OUTPUT_NODE is set
     * @post the address is available in certifier_api_easy_get_result.
     */
            CERTIFIER_MODE_CREATE_NODE_ADDRESS = 32,


    // 64 is unused

    /**
     * Create a CRT with
     * @see CERTIFIER_MODE_CREATE_CRT
     */
            CERTIFIER_MODE_CREATE_CRT = 128,

    // 512, 1024 & 2048 are unused

    /**
     * Request the current certificate status
     * @post certifier_api_easy_perform() will indicate the certificate status in its return code.
     * @post the certifier id is available in certifier_api_easy_get_result.
     * @note the return code will be a CERTIFIER_ERR_REGISTRATION_STATUS value offset by CERTIFIER_ERR_RENEW_CERT_1.
     */
            CERTIFIER_MODE_GET_CERT_STATUS = 4096,

    /**
     * Automatically renew the certificate if it is 'near' expiration.
     * @note CERTIFIER_OPT_CRT need not be set UNLESS no valid certificate is available.
     * @see CERTIFIER_MODE_GET_CERT_STATUS to query the exact certificate status
     * @post the certifier ID is available in certifier_api_easy_get_result.
     */
            CERTIFIER_MODE_RENEW_CERT = 8192,
    CERTIFIER_MODE_PRINT_CERT = 16384,
    // 32768 is unused


    // 65536 is unused,
    // is unused 131072
} CERTIFIER_MODE;

/**
 * Create a new easy API context. This context may be freely used with the certifier.h interface.
 * @note Free it with certifier_api_easy_destroy() after performing all desired operations.
 * @return the API context or NULL on failure
 */
CERTIFIER *certifier_api_easy_new(void);

/**
 * Create a new easy API context, same as certifier_api_easy_new,
 * but with configuration loaded from a custom file.
 * @return the API context or NULL on failure
 */

CERTIFIER *certifier_api_easy_new_cfg(char *libcertifier_cfg);

/**
 * Free an easy API context
 * @param easy
 */
void certifier_api_easy_destroy(CERTIFIER *easy);

/**
 * Set certifier client application mode.
 * @param easy
 * @param is_app
 * @note This affects the certifier registration type.
 * @note This disables CAR/DAR authorization support when is_app is true.
 * @see CERTIFIER_APP_REGISTRATION
 */
void certifier_api_easy_set_is_client(CERTIFIER *easy, bool is_app);

/**
 * Get a certifier configuration option.
 * @see CERTIFIER_MODE documentation for primary options and CERTIFIER_OPT for a complete list of options.
 * @note Take care to use the correct return type for each option. Results are undefined for
 *       mismatched option types (e.g., a string where a number is required).
 * @param easy
 * @param option
 * @return value See option description for valid values (the value is copied by certifier).
 */
void *certifier_api_easy_get_opt(CERTIFIER *easy, CERTIFIER_OPT option);

/**
 * Set a certifier configuration option.
 * @see CERTIFIER_MODE documentation for primary options and CERTIFIER_OPT for a complete list of options.
 * @note Take care to use the correct value type for each option. Results are undefined for
 *       mismatched option types (e.g., a string where a number is required).
 * @param easy
 * @param option
 * @param value See option description for valid values (the value is copied by certifier).
 * @return
 */
int certifier_api_easy_set_opt(CERTIFIER *easy, CERTIFIER_OPT option, void *value);

/**
 * Set the operation that certifier_api_easy_perform() will attempt.
 * When this is not set, the default action is to register the device.
 * @param easy
 * @param mode
 * @return 0 on success or CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1
 * @see CERTIFIER_MODE for allowed values
 */
int certifier_api_easy_set_mode(CERTIFIER *easy, CERTIFIER_MODE mode);

/**
 * When set, certifier_api_easy_perform() will parse argv for commandline arguments.
 * @param easy
 * @param argc
 * @param argv
 * @return 0 on success or CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1
 * @note caller must not free argv before invoking certifier_api_easy_destroy()
 */
int certifier_api_easy_set_cli_args(CERTIFIER *easy, int argc, char **argv);

/**
 * Get certifier version info
 * @param easy
 * @return a plain version string (caller must free)
 */
char *certifier_api_easy_get_version(CERTIFIER *easy);

/**
 * Execute an operation
 * @see certifier_api_easy_set_mode to set the requested operation
 * @see certifier_api_easy_get_info to get the result
 * @param easy
 * @return 0 on success
 */
int certifier_api_easy_perform(CERTIFIER *easy);

/**
 * Get a JSON document explaining the last operation result.
 * @param easy
 * @return
 */
const char *certifier_api_easy_get_result_json(CERTIFIER *easy);

/**
 * Get the last operation's output
 * @param easy
 * @return a NULL terminated string. Any non-C-string data is base64 encoded.
 */
const char *certifier_api_easy_get_result(CERTIFIER *easy);

/**
 * Get Certifier instance
 * @param easy
 * @return sertifier instance
 */
//Certifier * certifier_get_sertifier_instance(CERTIFIER *easy);

/**
 * Send a CSR to HTTP server
 * @param easy
 * @param url
 * @param http_headers
 * @param csr
 * @return HTTP response
 */
http_response *certifier_api_easy_http_post( const CERTIFIER *easy,
                                             const char *url,
                                             const char *http_headers[],
                                             const char *csr);

int certifier_api_easy_set_keys_and_node_address(CERTIFIER *easy, ECC_KEY *new_key);

void certifier_api_easy_set_ecc_key(CERTIFIER *easy, const ECC_KEY *key);

const ECC_KEY *certifier_api_easy_get_priv_key(CERTIFIER *easy);

int certifier_api_easy_create_json_csr(CERTIFIER *easy, unsigned char *csr, char *node_address, char **json_csr);

const char *certifier_api_easy_get_node_address(CERTIFIER *easy);
/**
 * @}
 */
#endif
