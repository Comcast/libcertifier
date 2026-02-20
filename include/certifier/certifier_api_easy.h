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

#include "certifier/property.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct CERTIFIER CERTIFIER;

/**
 * Modes for certifier_api_easy_perform.
 * @note Postconditions are true only after calling certifier_api_easy_perform and receiving a 0 (OK) result code.
 */
typedef enum
{
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

    CERTIFIER_MODE_REVOKE_CERT = 2,
    // 4, 8 & 16 are unused
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

    CERTIFIER_MODE_COMBO_REGISTER = 512,

    CERTIFIER_MODE_KEY_EXCHANGE = 1024,

    // 2048 is unused

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

    CERTIFIER_MODE_PRINT_VER = 32768,

    CERTIFIER_MODE_PRINT_HELP = 65536,

    CERTIFIER_MODE_SECTIGO_GET_CERT,

    CERTIFIER_MODE_SECTIGO_SEARCH_CERT,

    CERTIFIER_MODE_SECTIGO_RENEW_CERT,

    CERTIFIER_MODE_SECTIGO_REVOKE_CERT,

    CERTIFIER_MODE_SECTIGO_OCSP_STATUS,
    
    // 131072 is unused
} CERTIFIER_MODE;

typedef int (*key_exchange_t)(uint8_t *, size_t, uint8_t *, size_t, int);

/**
 * Create a new easy API context. This context may be freely used with the certifier.h interface.
 * @note Free it with certifier_api_easy_destroy() after performing all desired operations.
 * @return the API context or NULL on failure
 */
CERTIFIER * certifier_api_easy_new(void);

/**
 * Create a new easy API context, same as certifier_api_easy_new,
 * but with configuration loaded from a custom file.
 * @return the API context or NULL on failure
 */

CERTIFIER * certifier_api_easy_new_cfg(char * libcertifier_cfg);

void certifier_set_key_exchange_method(CERTIFIER * easy, key_exchange_t key_exchange);

/**
 * Free an easy API context
 * @param easy
 */
void certifier_api_easy_destroy(CERTIFIER * easy);

/**
 * Get a certifier configuration option.
 * @see CERTIFIER_MODE documentation for primary options and CERTIFIER_OPT for a complete list of options.
 * @note Take care to use the correct return type for each option. Results are undefined for
 *       mismatched option types (e.g., a string where a number is required).
 * @param easy
 * @param option
 * @return value See option description for valid values (the value is copied by certifier).
 */
void * certifier_api_easy_get_opt(CERTIFIER * easy, CERTIFIER_OPT option);

/**
 * Get a certifier configuration option.
 * @see CERTIFIER_MODE documentation for primary options and CERTIFIER_OPT for a complete list of options.
 * @note Take care to use the correct return type for each option. Results are undefined for
 *       mismatched option types (e.g., a string where a number is required).
 * @param easy
 * @param option
 * @return value See option description for valid values (the value is copied by certifier).
 */
void * certifier_api_easy_get_opt(CERTIFIER * easy, CERTIFIER_OPT option);

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
int certifier_api_easy_set_opt(CERTIFIER * easy, CERTIFIER_OPT option, void * value);

/**
 * tbw
 * tbw
 * @param easy
 * @return tbw
 * @see CERTIFIER_MODE for allowed values
 */
CERTIFIER_MODE certifier_api_easy_get_mode(CERTIFIER * easy);

/**
 * Set the operation that certifier_api_easy_perform() will attempt.
 * When this is not set, the default action is to register the device.
 * @param easy
 * @param mode
 * @return 0 on success or CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1
 * @see CERTIFIER_MODE for allowed values
 */
int certifier_api_easy_set_mode(CERTIFIER * easy, CERTIFIER_MODE mode);

/**
 * When set, certifier_api_easy_perform() will parse argv for commandline arguments.
 * @param easy
 * @param argc
 * @param argv
 * @return 0 on success or CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1
 * @note caller must not free argv before invoking certifier_api_easy_destroy()
 */
int certifier_api_easy_set_cli_args(CERTIFIER * easy, int argc, char ** argv);

/**
 * Get certifier version info
 * @param easy
 * @return a plain version string (caller must free)
 */
char * certifier_api_easy_get_version(CERTIFIER * easy);

/**
 * Print Help/Version Info
 * @param easy
 */
int certifier_api_easy_print_helper(CERTIFIER * easy);

/**
 * Execute an operation
 * @see certifier_api_easy_set_mode to set the requested operation
 * @see certifier_api_easy_get_info to get the result
 * @param easy
 * @return 0 on success
 */
int certifier_api_easy_perform(CERTIFIER * easy);

/**
 * Get a JSON document explaining the last operation result.
 * @param easy
 * @return
 */
const char * certifier_api_easy_get_result_json(CERTIFIER * easy);

/**
 * Get the last operation's output
 * @param easy
 * @return a NULL terminated string. Any non-C-string data is base64 encoded.
 */
const char * certifier_api_easy_get_result(CERTIFIER * easy);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
