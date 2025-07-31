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

#ifndef CERTIFIER_H
#define CERTIFIER_H

#include "certifier/property.h"
#include "certifier/types.h"
#include "certifier/error.h"
#include "certifier/property_internal.h"

#define SMALL_STRING_SIZE 64

#ifdef __cplusplus
extern "C" {
#endif

/* CHUNK is the size of the memory chunk used by the zlib routines. */
#define CHUNK 10000
#define ALLOWABLE_CHARACTERS "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnpqrstuvwxyz0123456879"

#define CERTIFIER_ERR_INIT_CERTIFIER 1000
// #define CERTIFIER_ERR_INIT_MINER     2000
#define CERTIFIER_ERR_INIT_SECURITY 3000
#define CERTIFIER_ERR_INIT_CAMERA 4000
#define CERTIFIER_ERR_INIT_MEMORY 4500

#define CERTIFIER_ERR_DESTROY_CERTIFIER 5000
// #define CERTIFIER_ERR_DESTROY_MINER     6000
#define CERTIFIER_ERR_DESTROY_SECURITY 7000
#define CERTIFIER_ERR_DESTROY_CAMERA 7500
#define CERTIFIER_ERR_DESTROY_LOG 7800
#define CERTIFIER_ERR_DESTROY_PROPERTY 7900

#define CERTIFIER_ERR_REGISTER_SECURITY_1 9000
#define CERTIFIER_ERR_REGISTER_SECURITY_5 9001
#define CERTIFIER_ERR_REGISTER_SECURITY_6 9002
#define CERTIFIER_ERR_REGISTER_SECURITY_7 9003
#define CERTIFIER_ERR_REGISTER_DELETE_PKCS12_1 9004
#define CERTIFIER_ERR_REGISTER_RENAME_PKCS12_1 9005
#define CERTIFIER_ERR_REGISTER_DELETE_PKCS12_2 9006
#define CERTIFIER_ERR_REGISTER_RENAME_PKCS12_2 9007
#define CERTIFIER_ERR_REGISTER_CERT_RENEWAL 10000
#define CERTIFIER_ERR_REGISTER_SETUP 11000
#define CERTIFIER_ERR_REGISTER_CERTIFIER_1 12000
#define CERTIFIER_ERR_REGISTER_MINER_1 13000
#define CERTIFIER_ERR_REGISTER_CRT_1 14000
#define CERTIFIER_ERR_REGISTER_CRT_2 15000
#define CERTIFIER_ERR_REGISTER_UNKNOWN 16000

#define CERTIFIER_ERR_PROPERTY_SET 27000
#define CERTIFIER_ERR_PROPERTY_SET_MEMORY 27900

#define CERTIFIER_ERR_CREATE_NODE_ADDRESS_1 100100
#define CERTIFIER_ERR_CREATE_NODE_ADDRESS_2 100200

#define CERTIFIER_ERR_CREATE_CRT_1 100300
#define CERTIFIER_ERR_CREATE_CRT_2 100301
#define CERTIFIER_ERR_CREATE_CRT_3 100302
#define CERTIFIER_ERR_CREATE_CRT_4 100303
#define CERTIFIER_ERR_CREATE_CRT_5 100304
#define CERTIFIER_ERR_CREATE_CRT_6 100305

#define CERTIFIER_ERR_CREATE_X509_CERT_1 100400
#define CERTIFIER_ERR_CREATE_X509_CERT_2 100401
#define CERTIFIER_ERR_CREATE_X509_CERT_3 100402
#define CERTIFIER_ERR_CREATE_X509_CERT_4 100500
#define CERTIFIER_ERR_CREATE_X509_CERT_5 100600
#define CERTIFIER_ERR_CREATE_X509_CERT_6 100680
#define CERTIFIER_ERR_CREATE_X509_CERT_7 100690

#define CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1 100800
#define CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_2 100801
#define CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_3 100802
#define CERTIFIER_ERR_GEN_1 100803
#define CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_5 100804

#define CERTIFIER_ERR_REVOKE_CERT_STATUS_1 110000

#define CERTIFIER_ERR_GET_CERT_STATUS_1 (1 << 15)

#define CERTIFIER_ERR_RENEW_CERT_1 140000

#define CERTIFIER_ERR_PRINT_CERT_1 150000
#define CERTIFIER_ERR_PRINT_CERT_2 160000
#define CERTIFIER_ERR_PRINT_CERT_3 170000
#define CERTIFIER_ERR_PRINT_CERT_4 180000
#define CERTIFIER_ERR_PRINT_CERT_5 190000

#define CERTIFIER_ERR_INTERNAL 1
#define CERTIFIER_ERR_INVALID_ARGUMENT 2

#define CERTIFIER_ERR_GENERATE_CRT_NONCE 1

#define CERTIFIER_ERR_SETUP_ECKEY_FAILURE 1

// NOTUSED - will repurpose
#define CERTIFIER_ERR_SETUP_ECKEY_PUBLIC_WRITE_DER_FAILURE_1 2

#define CERTIFIER_ERR_SETUP_INTERNAL_NODE_ADDRESS_2 3
#define CERTIFIER_ERR_SETUP_EMPTY_FILENAME 4
#define CERTIFIER_ERR_SETUP_EMPTY_PASSWORD 5
#define CERTIFIER_ERR_SETUP_EMPTY_ECC_CURVE 6

#define CERTIFIER_ERR_REGISTRATION_STATUS_X509_NONEXISTENT (1 << 0)
#define CERTIFIER_ERR_REGISTRATION_STATUS_P12_NONEXISTENT (1 << 1)
#define CERTIFIER_ERR_REGISTRATION_STATUS_CERTIFIER_ID_NONEXISTENT (1 << 2)
#define CERTIFIER_ERR_REGISTRATION_STATUS_CERT_TIME_CHECK_1 (1 << 3)
#define CERTIFIER_ERR_REGISTRATION_STATUS_CERT_EXPIRED_1 (1 << 4)
#define CERTIFIER_ERR_REGISTRATION_STATUS_CERT_EXPIRED_2 (1 << 5)
#define CERTIFIER_ERR_REGISTRATION_STATUS_CERT_ABOUT_TO_EXPIRE (1 << 6)
#define CERTIFIER_ERR_REGISTRATION_STATUS_SIMULATION_1 (1 << 7)
#define CERTIFIER_ERR_REGISTRATION_STATUS_SIMULATION_2 (1 << 8)

#define CERTIFIER_ERR_GET_CERT_STATUS_UNKNOWN (1 << 9)
#define CERTIFIER_ERR_GET_CERT_STATUS_REVOKED (1 << 10)
#define CERTIFIER_ERR_GET_CERT_STATUS_GOOD (1 << 11)

typedef enum
{
    CERTIFIER_LOG_TRACE = 0,
    CERTIFIER_LOG_DEBUG,
    CERTIFIER_LOG_INFO,
    CERTIFIER_LOG_WARN,
    CERTIFIER_LOG_ERROR,
    CERTIFIER_LOG_FATAL
} CertifierLogPriority;

typedef struct Map
{
    char node_address[SMALL_STRING_SIZE];
    char * base64_public_key;
    unsigned char * der_public_key;
    int der_public_key_len;
    ECC_KEY * private_ec_key;
    X509_CERT * x509_cert;
} Map;

typedef struct Certifier
{
    CertifierPropMap * prop_map;
    Map tmp_map;
    CertifierError last_error;
    bool sectigo_mode;
} Certifier;

Certifier * certifier_new(void);

int certifier_destroy(Certifier * certifier);

/**
 * Register a device or application
 * @param certifier
 * @param mode
 * @return
 */
int certifier_register(Certifier * certifier);

int certifier_set_property(Certifier * certifier, int name, const void * value);

void * certifier_get_property(Certifier * certifier, int name);

bool certifier_is_option_set(Certifier * certifier, int name);

/**
 * Load the configuration file in CERTIFIER_OPT_CFG_FILENAME
 * @param certifier
 * @return 0 on success, or an error code
 */
int certifier_load_cfg_file(Certifier * certifier);

int sectigo_load_cfg_file(Certifier * certifier);

char * certifier_get_version(Certifier * certifier);

/**
 * Create a JSON document describing an operation
 * @param certifier
 * @param return_code A return code to include in the 'return_code' key.
 * @param output A string to include in the 'output' key. This value is copied.
 * @return a JSON document (caller must free).
 */
char * certifier_create_info(Certifier * certifier, const int return_code, const char * output);

int certifier_create_node_address(const unsigned char * input, int input_len, char ** node_address);

/**
 * Get the node address
 * @param certifier
 * @return
 */
const char * certifier_get_node_address(Certifier * certifier);

/**
 * Get the certifier ID
 * @pre the device is registered
 * @param certifier
 * @return
 */
const char * certifier_get_certifier_id(Certifier * certifier);

int certifier_create_crt(Certifier * certifier, char ** out_crt, const char * type);

int certifier_create_x509_crt(Certifier * certifier, char ** out_crt);

int certifier_create_json_csr(Certifier * certifier, char * csr, char ** out_cert);
int certifier_setup_keys(Certifier * certifier);

int certifier_get_device_registration_status(Certifier * certifier);

/**
 * Get the Certificate Status (GOOD, UNKNOWN, REVOKED)
 * @param certifier
 * @return
 */
int certifier_get_device_certificate_status(Certifier * certifier);

/**
 * Revoke a certificate
 * @param certifier
 * @return
 */
int certifier_revoke_certificate(Certifier * certifier);

/**
 * Renew a certificate
 * @param certifier
 * @return
 */
int certifier_renew_certificate(Certifier * certifier);

/**
 * Callback that will receive log messages
 * @param prio the log priority
 * @param file the source file that emitted 'msg'
 * @param line the line in 'file'
 * @param msg The original, formatted log message (never NULL)
 */
typedef void (*CERTIFIER_LOG_callback)(const CertifierLogPriority prio, const char * file, const uint32_t line, const char * msg);

/**
 * Register a callback to receive logs. This will disable other logging
 * @param cb
 * @see CERTIFIER_LOG_callback
 */
void certifier_set_log_callback(Certifier * certifier, CERTIFIER_LOG_callback cb);

/**
 * Get the x509 certificate in PEM format (without armor)
 * @param certifier
 * @return A base64 encoded certificate or NULL (caller must free)
 */
char * certifier_get_x509_pem(Certifier * certifier);

void certifier_print_certificate(Certifier * certifier, const char * pem, int pem_len);

void certifier_print_certificate_validity(Certifier * certifier);

CertifierError sectigo_generate_certificate_signing_request(Certifier *certifier, char **out_csr_pem);

CertifierPropMap * certifier_get_prop_map(Certifier * certifier);

#ifdef __cplusplus
}
#endif

#endif
