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

#include "certifier/log.h"
#include "certifier/base64.h"
#include "certifier/util.h"

#include "certifier/certifierclient.h"
#include "certifier/system.h"
#include "certifier/certifier.h"
#include "certifier/certifier_internal.h"
#include "certifier/property.h"
#include "certifier/property_internal.h"
#include "certifier/parson.h"
#include "certifier/timer.h"
#include "certifier/error.h"
#include "curl/curl.h"

#ifndef CERTIFIER_VERSION
#define CERTIFIER_VERSION "0.1-071320 (opensource)"
#endif

static CERTIFIER_LOG_callback logger;

typedef struct Map {
    char node_address[SMALL_STRING_SIZE];
    char *base64_public_key;
    unsigned char *der_public_key;
    int der_public_key_len;
    ECC_KEY *private_ec_key;
    X509_CERT *x509_cert;
} Map;

struct Certifier {
    CertifierPropMap *prop_map;
    Map tmp_map;
    CertifierError last_error;
};

static inline void free_tmp(Certifier *certifier);

static inline void assign_last_error(Certifier *certifier, CertifierError *error);

/**
 * @param certifier
 * @param error_code
 * @param error_string A heap allocated string. Be sure to XSTRDUP() any constants
 */
static void set_last_error(Certifier *certifier, const int error_code, char *error_string);

/**
 * Load certificate info
 * @pre This device is registered
 * @pre CERTIFIER_OPT_KEYSTORE is set to a valid pkcs#12 file
 * @pre CERTIFIER_OPT_PASSWORD is set
 * @post tmp_map.x509_cert is set
 * @post last error info is set on failure
 * @return 0 on success or an error code
 */
static int load_cert(Certifier *certifier);

static const X509_CERT *get_cert(Certifier *certifier) {
    if (certifier->tmp_map.x509_cert == NULL) {
        if (load_cert(certifier) != 0) {
            return NULL;
        }
    }

    return certifier->tmp_map.x509_cert;
}

const ECC_KEY *_certifier_get_privkey(Certifier *certifier) {
    if (certifier->tmp_map.private_ec_key == NULL) {
        if (certifier_setup_keys(certifier) != 0) {
            return NULL;
        }
    }

    return certifier->tmp_map.private_ec_key;
}


int certifier_set_keys_and_node_address_with_cn_prefix(Certifier *certifier, ECC_KEY *new_key, char *cn_prefix, CertifierError rc)
{
    int return_code = 0;
    char *tmp_node_address = NULL;

    security_free_eckey(certifier->tmp_map.private_ec_key);
    certifier->tmp_map.private_ec_key = new_key;

    assign_last_error(certifier, &rc);
    return_code = rc.application_error_code;
    if (rc.application_error_code != 0) {
        return_code = CERTIFIER_ERR_SETUP_ECKEY_FAILURE;
        char *err_json = util_format_error("setup_keys",
                                           "propMap.ecKey is null.  This was most likely because the .p12 existed with a different pwd?",
                                           __FILE__, __LINE__);
        set_last_error(certifier, return_code, err_json);
        goto cleanup;
    }

    load_cert(certifier);
    if (return_code != 0) {
        /* load_cert() will set_last_error on failure */
        goto cleanup;
    }

    // Save public key
    XFREE(certifier->tmp_map.der_public_key);
    certifier->tmp_map.der_public_key = NULL;

    certifier->tmp_map.der_public_key_len = security_serialize_der_public_key(certifier->tmp_map.private_ec_key,
                                                                              &certifier->tmp_map.der_public_key);

    if (certifier->tmp_map.der_public_key_len == 0)
        goto cleanup;

    XFREE(certifier->tmp_map.base64_public_key);
    certifier->tmp_map.base64_public_key = XMALLOC(base64_encode_len(certifier->tmp_map.der_public_key_len));
    if (certifier->tmp_map.base64_public_key == NULL) {
        set_last_error(certifier, return_code, "Could not allocate enough memory for "
                                               "certifier->tmp_map.base64_public_key");
        goto cleanup;
    }

    base64_encode(certifier->tmp_map.base64_public_key, certifier->tmp_map.der_public_key,
                  certifier->tmp_map.der_public_key_len);

    if (util_is_not_empty(cn_prefix)) {
        strncpy(certifier->tmp_map.node_address, cn_prefix, sizeof(certifier->tmp_map.node_address) - 1);
    } else {
        // Create Node Address based on public key DER format
        XMEMSET(certifier->tmp_map.node_address, 0, sizeof(certifier->tmp_map.node_address));
        return_code = certifier_create_node_address(certifier->tmp_map.der_public_key,
                                                    certifier->tmp_map.der_public_key_len,
                                                    &tmp_node_address);

        if ((util_is_empty(tmp_node_address)) || (return_code != 0)) {
            return_code = CERTIFIER_ERR_SETUP_INTERNAL_NODE_ADDRESS_2;
            char *err_json = util_format_error("setup_keys", "Internal error. tmpNodeAddress is NULL!", __FILE__,
                                               __LINE__);
            set_last_error(certifier, return_code, err_json);
            goto cleanup;
        }

        XSTRNCPY(certifier->tmp_map.node_address, tmp_node_address, sizeof(certifier->tmp_map.node_address) - 1);
        certifier->tmp_map.node_address[sizeof(certifier->tmp_map.node_address) - 1] = '\0';
    }
    log_debug("\nNode Address: %s\n", certifier->tmp_map.node_address);

    // Clean up
cleanup:
    XFREE(tmp_node_address);

    return return_code;
}

/* createKeys */

int
certifier_setup_keys(Certifier *certifier) {
    NULL_CHECK(certifier);

    int return_code = 0;
    char *tmp_node_address = NULL;

    const char *p12_filename = certifier_get_property(certifier, CERTIFIER_OPT_KEYSTORE);
    const char *password = certifier_get_property(certifier, CERTIFIER_OPT_PASSWORD);
    const char *ecc_curve_id = certifier_get_property(certifier, CERTIFIER_OPT_ECC_CURVE_ID);
    char *cn_prefix = certifier_get_property(certifier, CERTIFIER_OPT_CN_PREFIX);

    if (util_is_empty(p12_filename)) {
        return_code = CERTIFIER_ERR_SETUP_EMPTY_FILENAME;
        goto cleanup;
    }

    if (util_is_empty(password)) {
        return_code = CERTIFIER_ERR_SETUP_EMPTY_PASSWORD;
        goto cleanup;
    }

    if (util_is_empty(ecc_curve_id)) {
        return_code = CERTIFIER_ERR_SETUP_EMPTY_ECC_CURVE;
        goto cleanup;
    }

    // Get or Create the Elliptical Curve Keys
    ECC_KEY *new_key = NULL;
    CertifierError rc = security_find_or_create_keys(certifier->prop_map,
                                                     p12_filename,
                                                     password,
                                                     NULL,
                                                     ecc_curve_id,
                                                     &new_key);

    return_code = certifier_set_keys_and_node_address_with_cn_prefix(certifier, new_key, cn_prefix, rc);

    // Clean up
    cleanup:
    XFREE(tmp_node_address);

    return return_code;
} /* setup_keys */

static int load_cert(Certifier *certifier) {
    X509_CERT *cert = NULL;
    const char *p12_filename = certifier_get_property(certifier, CERTIFIER_OPT_KEYSTORE);
    const char *password = certifier_get_property(certifier, CERTIFIER_OPT_PASSWORD);
    int return_code = 0;

    // If there is a .p12 file, then we were already registered
    if (util_file_exists(p12_filename)) {
        log_debug("PKCS12 file %s exists. Loading x509", p12_filename);
        CertifierError result = security_get_X509_PKCS12_file(p12_filename, password, NULL, &cert);
        assign_last_error(certifier, &result);
        return_code = result.application_error_code;
        if (result.application_error_code != 0) {
            return_code = CERTIFIER_ERR_REGISTRATION_STATUS_X509_NONEXISTENT;
            char *err_json = util_format_error_here("Internal error. Failed to parse x509.");
            set_last_error(certifier, return_code, err_json);
            goto cleanup;
        }

        security_free_cert(certifier->tmp_map.x509_cert);
        certifier->tmp_map.x509_cert = cert;
        cert = NULL;
    } else {
        return_code = CERTIFIER_ERR_REGISTRATION_STATUS_P12_NONEXISTENT;
        char *err_json = util_format_error("certifier_get_device_registration_status", "Could not find the P12 file.",
                                           __FILE__, __LINE__);
        set_last_error(certifier, return_code, err_json);
        goto cleanup;
    }

    cleanup:
    security_free_cert(cert);
    return return_code;
}

int
certifier_get_device_registration_status(Certifier *certifier) {
    NULL_CHECK(certifier);

    int return_code = 0;
    CertifierError time_range_valid = CERTIFIER_ERROR_INITIALIZER;
    time_t raw_time = 0;

    // Check certificate expiration against current time
    time(&raw_time);

    log_debug("BEFORE raw_time%lld\n", (long long) raw_time);

    if (!raw_time) {
        return_code = CERTIFIER_ERR_REGISTRATION_STATUS_CERT_TIME_CHECK_1;
        char *err_json = util_format_error("certifier_get_device_registration_status",
                                           "Could not obtain the system time!",
                                           __FILE__,
                                           __LINE__);
        set_last_error(certifier, return_code, err_json);
        goto cleanup;
    }

    free_tmp(certifier);

    return_code = load_cert(certifier);
    if (return_code != 0) {
        /* load_cert() will set_last_error on failure */
        goto cleanup;
    }

    const char *simulated_cert_expiration_date_before = certifier_get_property(certifier,
                                                                               CERTIFIER_OPT_SIMULATION_CERT_EXP_DATE_BEFORE);
    const char *simulated_cert_expiration_date_after = certifier_get_property(certifier,
                                                                              CERTIFIER_OPT_SIMULATION_CERT_EXP_DATE_AFTER);

    // Check to see if it is about to expire
    time_range_valid = security_check_x509_valid_range(raw_time,
                                                       (size_t) certifier_get_property(certifier,
                                                                                       CERTIFIER_OPT_CERT_MIN_TIME_LEFT_S),
                                                       certifier->tmp_map.x509_cert,
                                                       simulated_cert_expiration_date_before,
                                                       simulated_cert_expiration_date_after);
    assign_last_error(certifier, &time_range_valid);
    return_code = time_range_valid.application_error_code;

    cleanup:

    return (return_code);
}

int certifier_create_node_address(const unsigned char *input, int input_len, char **node_address) {
    int return_code = 0;

    if (util_is_empty((const char *) input)) {
        return CERTIFIER_ERR_CREATE_NODE_ADDRESS_1;
    }

    *node_address = security_encode(input, input_len, &return_code);

    if (return_code != 0) {
        return_code = CERTIFIER_ERR_CREATE_NODE_ADDRESS_2 + return_code;
    }

    return return_code;
}

const char *certifier_get_node_address(Certifier *certifier) {
    if (util_is_empty(certifier->tmp_map.node_address)) {
        /* Loading keys will also load the node_address (derived from public key) */
        if (certifier_setup_keys(certifier) != 0) {
            return NULL;
        }
    }

    return certifier->tmp_map.node_address;
}

int certifier_create_crt(Certifier *certifier, char **out_crt, const char *token_type) {
    NULL_CHECK(certifier);

    int return_code = 0;
    int64_t timestamp_msec; /* timestamp in millisecond. */
    char *transaction_id = NULL;
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    char *serialized_string = NULL;
    const char *token = certifier_get_property(certifier, CERTIFIER_OPT_AUTH_TOKEN);

    if (util_is_empty(token)) {
        return_code = CERTIFIER_ERR_CREATE_CRT_1;
        goto cleanup;
    }

    if (out_crt == NULL) {
        return_code = CERTIFIER_ERR_CREATE_CRT_2;
        goto cleanup;
    }

    if (token_type == NULL) {
        return_code = CERTIFIER_ERR_CREATE_CRT_5;
        goto cleanup;
    }

    json_object_set_string(root_object, "tokenType", token_type);
    // set the token
    json_object_set_string(root_object, "token", token);

    // generate the transaction_id, and timestamps
    transaction_id = util_generate_random_value(16, ALLOWABLE_CHARACTERS);
    if (util_is_empty(transaction_id)) {
        log_error("ERROR: Transaction ID is NULL");
        return_code = CERTIFIER_ERR_CREATE_CRT_3;
        goto cleanup;
    }
    log_debug("Transaction ID is: %s", transaction_id);

    if (util_get_unixtime_ms(&timestamp_msec) != 0) {
        log_error("ERROR: Could not generate milliseconds from epoch #2.");
        return_code = CERTIFIER_ERR_CREATE_CRT_4;
        goto cleanup;
    }

    log_debug("timestamp in milliseconds since epoch is: %"
                      PRIi64, timestamp_msec);

    json_object_set_string(root_object, "nonce", transaction_id);
    json_object_set_number(root_object, "timestamp", timestamp_msec);

    serialized_string = json_serialize_to_string_pretty(root_value);

    if (util_is_empty(serialized_string)) {
        return_code = CERTIFIER_ERR_CREATE_CRT_3;
        goto cleanup;
    }

    *out_crt = XSTRDUP(serialized_string);

    if (util_is_empty(*out_crt)) {
        return_code = CERTIFIER_ERR_CREATE_CRT_4;
        goto cleanup;
    }

    cleanup:
    if (root_value) {
        json_value_free(root_value);
    }

    if (serialized_string) {
        json_free_serialized_string(serialized_string);
    }

    if (transaction_id != NULL) {
        XFREE(transaction_id);
    }

    return return_code;
}

int certifier_create_x509_crt(Certifier *certifier, char **out_crt) {
    NULL_CHECK(certifier);

    int return_code = 0;
    char *generated_crt = NULL;

    if (out_crt == NULL) {
        return_code = CERTIFIER_ERR_CREATE_X509_CERT_3;
        goto cleanup;
    }

    log_info("Calling get_cert()");

    const X509_CERT *cert = get_cert(certifier);
    if (cert == NULL) {
        return_code = CERTIFIER_ERR_CREATE_X509_CERT_6;
        log_error("Could not lazily obtain the cert as it was NULL.",
                  return_code);
        goto cleanup;
    }


    const ECC_KEY *private_key = _certifier_get_privkey(certifier);
    if (private_key == NULL) {
        return_code = CERTIFIER_ERR_CREATE_X509_CERT_7;
        log_error("Could not lazily obtain the private key as it was NULL.",
                  return_code);
        goto cleanup;
    }

    return_code = security_generate_x509_crt(&generated_crt,
                                             (X509_CERT *) cert,
                                             (ECC_KEY *) private_key);
    if (return_code) {
        log_error("Received an error code: <%i> while calling security_generate_x509_crt().  Exiting.",
                  return_code);
        return_code = CERTIFIER_ERR_CREATE_X509_CERT_4 + return_code;
        goto cleanup;
    }
    if ((!generated_crt) || (XSTRLEN(generated_crt) == 0)) {
        log_error("Could not generate the CRT.");
        return_code = CERTIFIER_ERR_CREATE_X509_CERT_5;
        goto cleanup;
    }
    log_info("Generated CRT is: %s\n", generated_crt);

    *out_crt = generated_crt;

    cleanup:
    
    free_tmp(certifier);

    return return_code;
}

static void handle_log_msg(const log_level level, const char *file, const int line, const char *msg) {
    if (logger != NULL) {
        CertifierLogPriority prio = CERTIFIER_LOG_DEBUG;
        switch (level) {
            case LOG_TRACE:
                prio = CERTIFIER_LOG_TRACE;
                break;

            case LOG_DEBUG:
                prio = CERTIFIER_LOG_DEBUG;
                break;

            case LOG_INFO:
                prio = CERTIFIER_LOG_INFO;
                break;

            case LOG_WARN:
                prio = CERTIFIER_LOG_WARN;
                break;

            case LOG_ERROR:
                prio = CERTIFIER_LOG_ERROR;
                break;

            case LOG_FATAL:
                prio = CERTIFIER_LOG_FATAL;
                break;

            default:
                prio = CERTIFIER_LOG_DEBUG;
                break;
        }

        logger(prio, file, (uint32_t) line, msg);
    }
}

void certifier_set_log_callback(Certifier *certifier, CERTIFIER_LOG_callback cb) {
    //TODO: Connect logging to context
    logger = cb;
    if (cb == NULL) {
        log_set_callback(NULL);
    } else {
        log_set_callback(handle_log_msg);
    }
}

char *certifier_get_x509_pem(Certifier *certifier) {
    if (certifier == NULL) {
        return NULL;
    }

    const X509_CERT *cert = get_cert(certifier);
    if (cert == NULL) {
        return NULL;
    }

    size_t der_len = 0;
    unsigned char *der = security_X509_to_DER((X509_CERT *) cert, &der_len);
    char *pem = NULL;

    if (der != NULL && der_len > 0) {
        pem = XMALLOC(base64_encode_len(der_len));
        if (pem == NULL) {
            log_error("Could not allocate enough memory for pem in certifier_get_x509_pem()");
            goto cleanup;
        }
        base64_encode(pem, der, der_len);
    }

    cleanup:
    XFREE(der);

    return pem;
}

static inline void assign_last_error(Certifier *certifier, CertifierError *error) {
    error_clear(&certifier->last_error);
    certifier->last_error = *error;
}

/**
 * Set the last error info
 * @param certifier
 * @param error_code
 * @param error_string a description of the error.
 * @note This function transfers ownership of error_string away from the caller. The value passed to this
 *       parameter MUST NOT be freed and SHOULD NOT be referred to beyond the call site.
 */
static void set_last_error(Certifier *certifier, const int error_code, char *error_string) {
    certifier->last_error.application_error_code = error_code;

    XFREE(certifier->last_error.application_error_msg);

    // todo - should last_error.library_error_msg be freed as well?

    certifier->last_error.application_error_msg = error_string;
}

/*
 * [package] private functions
 */

CertifierPropMap *_certifier_get_properties(Certifier *certifier) {
    return certifier->prop_map;
}

void _certifier_set_x509_cert(Certifier *certifier, const X509_CERT *cert) {
    security_free_cert(certifier->tmp_map.x509_cert);
    X509_CERT *tmp = NULL;

    if (cert != NULL) {
        tmp = security_dup_cert(cert);
    }

    certifier->tmp_map.x509_cert = tmp;
}

void _certifier_set_ecc_key(Certifier *certifier, const ECC_KEY *key) {
    security_free_eckey(certifier->tmp_map.private_ec_key);
    ECC_KEY *tmp = NULL;

    if (key != NULL) {
        tmp = security_dup_eckey(key);
    }

    certifier->tmp_map.private_ec_key = tmp;
}

// Functions
Certifier *
certifier_new(void) {
    int error_code = 0;
    CertifierError result = CERTIFIER_ERROR_INITIALIZER;

    // set initial logging properties
    log_set_stripped(0);
    log_set_newlines(1);

    Certifier *certifier = XCALLOC(1, sizeof(Certifier));
    if (certifier == NULL) {
        log_error("Could not allocate enough memory to construct a certifier\n");
        error_code = CERTIFIER_ERR_INIT_MEMORY;
        goto exit;
    }

    certifier->prop_map = property_new();
    if (certifier->prop_map == NULL) {
        log_error("Could not allocate enough memory to construct a prop_map\n");
        error_code = CERTIFIER_ERR_INIT_MEMORY;
        goto exit;
    }

    error_code = certifierclient_init();
    if (error_code) {
        log_error("certifierclient_init failed\n");
        error_code = CERTIFIER_ERR_INIT_CERTIFIER + error_code;
        goto exit;
    }

    result = security_init();
    if (result.application_error_code != 0) {
        log_error("security_init failed\n");
        error_code = CERTIFIER_ERR_INIT_SECURITY + error_code;
        goto exit;
    }

    /* A default cfgfile may be set, but it is optional. Only attempt to load if set and exists */
    const char *cfgfile = certifier_get_property(certifier, CERTIFIER_OPT_CFG_FILENAME);
    if (!util_is_empty(cfgfile) && access(cfgfile, F_OK) == 0) {
        /* This will reconfigure() automatically. */
        error_code = certifier_load_cfg_file(certifier);
    } else {
    }

    exit:
    error_clear(&result);
    if (error_code != 0) {
        certifier_destroy(certifier);
        certifier = NULL;
    }

    return certifier;
} /* certifier_new */


int
certifier_destroy(Certifier *certifier) {
    int error_code = 0;

    if (certifier == NULL) {
        return error_code;
    }

    error_code = certifierclient_destroy();
    if (error_code) {
        error_code = CERTIFIER_ERR_DESTROY_CERTIFIER + error_code;
        goto exit;
    }

    security_destroy();

    error_code = log_destroy();
    if (error_code) {
        error_code = CERTIFIER_ERR_DESTROY_LOG + error_code;
        goto exit;
    }

    error_code = property_destroy(certifier->prop_map);
    if (error_code) {
        error_code = CERTIFIER_ERR_DESTROY_PROPERTY + error_code;
        goto exit;
    }

    free_tmp(certifier);
    error_clear(&certifier->last_error);
    XFREE(certifier);

    exit:
    return error_code;
}

int certifier_set_property(Certifier *certifier, int name, const void *value) {
    NULL_CHECK(certifier);

    int return_code = 0;
    const void *origValue = property_get(certifier->prop_map, name);

    return_code = property_set(certifier->prop_map, name, value);
    if (return_code != 0) {
        return CERTIFIER_ERR_PROPERTY_SET + return_code;
    }

    switch (name) {
        case CERTIFIER_OPT_CFG_FILENAME: {
            log_info("Configuration file changed; loading settings");

            /* Blow away all settings and reload from config to avoid mixed configs */
            CertifierPropMap *orig = certifier->prop_map;
            certifier->prop_map = property_new();
            if (certifier->prop_map == NULL) {
                log_error("Could not allocate enough memory to construct certifier->prop_map");
                return CERTIFIER_ERR_PROPERTY_SET_MEMORY;
            }
            property_set(certifier->prop_map, name, value);

            if (value != NULL) {
                return_code = certifier_load_cfg_file(certifier);
            } else {
                return_code = 0;
            }

            if (return_code == 0) {
                property_destroy(orig);
            } else {
                property_destroy(certifier->prop_map);
                certifier->prop_map = orig;
                return_code = property_set(certifier->prop_map, name, origValue);
                log_warn("Failed to load configuration (configuration unmodified)!");
            }

            break;
        }

        case CERTIFIER_OPT_LOG_FUNCTION:
            certifier_set_log_callback(certifier, value);
            break;

        case CERTIFIER_OPT_KEYSTORE:
        case CERTIFIER_OPT_PASSWORD:
        case CERTIFIER_OPT_ECC_CURVE_ID:
            free_tmp(certifier);
            break;

        default:
            /* Don't care about this property */
            break;
    }

    return return_code;
}

void *certifier_get_property(Certifier *certifier, int name) {
    if (certifier == NULL) {
        log_error("certifier cannot be NULL");
        return NULL;
    }

    return property_get(certifier->prop_map, name);
}

int certifier_load_cfg_file(Certifier *certifier) {
    NULL_CHECK(certifier);

    int return_code = 0;

    return_code = property_set_defaults_from_cfg_file(certifier->prop_map);

    if (return_code != 0) {
        return_code = CERTIFIER_ERR_PROPERTY_SET + return_code;
    }

    return return_code;
}

char *certifier_create_info(Certifier *certifier, const int return_code, const char *output) {
    if (certifier == NULL) {
        return NULL;
    }

    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    char *serialized_string = NULL;

    json_object_set_number(root_object, "return_code", return_code);

    json_object_set_number(root_object, "application_error_code", certifier->last_error.application_error_code);
    json_object_dotset_value(root_object, "application_error_message",
                             json_parse_string(certifier->last_error.application_error_msg));

    json_object_set_number(root_object, "library_error_code", certifier->last_error.library_error_code);
    json_object_dotset_value(root_object, "library_error_message",
                             json_parse_string(certifier->last_error.library_error_msg));

    if (util_is_not_empty(output)) {
        json_object_set_string(root_object, "output", output);
    }

    serialized_string = json_serialize_to_string_pretty(root_value);

    json_value_free(root_value);

    return serialized_string;
}

char *certifier_get_version(Certifier *certifier) {
    if (certifier == NULL) {
        return NULL;
    }

    curl_version_info_data *curl_version_data = curl_version_info(CURLVERSION_NOW);

    char *security_version = security_get_version();

    char *certifier_version = NULL;

    const char *permission_enabled = "PERMISSION:DISABLED";

    if ((security_version != NULL) && (curl_version_data != NULL)) {
        certifier_version = util_format_str("libcertifier %s;libcurl %s;%s;%s",
                                            CERTIFIER_VERSION,
                                            curl_version_data->version,
                                            security_version,
                                            permission_enabled);
    }

    if (security_version != NULL) {
        XFREE(security_version);
    }
    return certifier_version;
}

static void free_tmp(Certifier *certifier) {
    if (certifier->tmp_map.der_public_key) {
        XFREE(certifier->tmp_map.der_public_key);
    }

    if (certifier->tmp_map.base64_public_key) {
        XFREE(certifier->tmp_map.base64_public_key);
    }

    _certifier_set_ecc_key(certifier, NULL);
    _certifier_set_x509_cert(certifier, NULL);

    XMEMSET(&certifier->tmp_map, 0, sizeof(certifier->tmp_map));
}

int certifier_register(Certifier *certifier, int mode) {
    NULL_CHECK(certifier);

    int return_code = 0;
    int csr_len = 0;
    char *csr_byte_ptr = NULL;
    CertifierError certifier_err_info = CERTIFIER_ERROR_INITIALIZER;
    char *renamed_p12_filename = NULL;

    char *san = NULL;
    char *x509_certs = NULL;
    X509_LIST *certs = NULL;

    int force_registration = 0;
    bool is_cert_auto_renewal_enabled = false;

    const char *p12_filename = certifier_get_property(certifier, CERTIFIER_OPT_KEYSTORE);

    double start_user_cpu_time = 0, end_user_cpu_time = 0;
    double start_system_cpu_time = 0, end_system_cpu_time = 0;
    long int start_memory_used = 0, end_memory_used = 0;

    int measure_performance = property_is_option_set(certifier->prop_map, CERTIFIER_OPTION_MEASURE_PERFORMANCE);

    if (measure_performance) {
        start_user_cpu_time = system_user_cpu_time();
        start_system_cpu_time = system_system_cpu_time();
        start_memory_used = system_get_memory_used();

        timer_reset();
        timer_start_time();
        timer_start_CPU_time();
    }

    force_registration = property_is_option_set(certifier->prop_map, CERTIFIER_OPTION_FORCE_REGISTRATION);
    is_cert_auto_renewal_enabled = property_is_option_set(certifier->prop_map, CERTIFIER_OPTION_AUTO_RENEW_CERT);

    if (util_is_empty(p12_filename)) {
        return_code = CERTIFIER_ERR_REGISTER_SECURITY_6;
        char *err_json = util_format_error("certifier_register_device",
                                           "p12_filename was not set.", __FILE__, __LINE__);
        set_last_error(certifier, return_code, err_json);
        goto cleanup;
    }

    log_info("P12 filename is: %s", p12_filename);

    // Check to see if the P12 file already exists.  If it does AND the force_registration flag was set
    // then, we will rename the existing .p12 file.  If, for some reason, the renamed file existed, like
    // from a leftover incomplete registration, or the file permission was not set right, try to
    // delete that file.
    if (util_file_exists(p12_filename) && force_registration) {
        renamed_p12_filename = util_format_str("%s.bk", p12_filename);

        if (util_file_exists(renamed_p12_filename)) {
            if (util_delete_file(renamed_p12_filename)) {
                return_code = CERTIFIER_ERR_REGISTER_DELETE_PKCS12_1;
                char *err_json = util_format_error("certifier_register_device",
                                                   "Error trying to delete a renamed PKCS12 file [1]", __FILE__,
                                                   __LINE__);
                set_last_error(certifier, return_code, err_json);
                goto cleanup;
            }
        }

        if (util_rename_file(p12_filename, renamed_p12_filename)) {
            return_code = CERTIFIER_ERR_REGISTER_RENAME_PKCS12_1;
            char *err_json = util_format_error("certifier_register_device",
                                               "Error trying to delete a renamed PKCS12 file [1].", __FILE__,
                                               __LINE__);
            set_last_error(certifier, return_code, err_json);
            goto cleanup;
        }

        log_info("Renamed file: %s to %s", p12_filename, renamed_p12_filename);
    }

    return_code = certifier_get_device_registration_status(certifier);
    switch (return_code) {
        case 0:
            log_info("\nCertificate has not yet expired and already exists.  Returning.  No need to register again.\n");
            goto cleanup;

        case CERTIFIER_ERR_REGISTRATION_STATUS_CERT_EXPIRED_1:
        case CERTIFIER_ERR_REGISTRATION_STATUS_CERT_ABOUT_TO_EXPIRE:
            if (is_cert_auto_renewal_enabled) {
                log_info("\nAutomatically renewing certificate...\n");
                /* Only generate an X509 CRT if it was not explicitly overridden to support manual recovery */
                if (util_is_empty(certifier_get_property(certifier, CERTIFIER_OPT_CRT))) {
                    char *renew_crt = NULL;
                    const X509_CERT *cert = get_cert(certifier);
                    const ECC_KEY *private_key = _certifier_get_privkey(certifier);
                    return_code = security_generate_x509_crt(&renew_crt,
                                                             (X509_CERT *) cert,
                                                             (ECC_KEY *) private_key);

                    if (return_code == 0) {
                        int crt_len = (int) XSTRLEN(renew_crt);
                        char *encodedCRT = XMALLOC(base64_encode_len(crt_len));
                        if (encodedCRT == NULL) {
                            set_last_error(certifier, return_code,
                                           util_format_error_here("Could not allocate enough memory for encoded CRT!"));
                            goto cleanup;
                        }

                        base64_encode(encodedCRT, (unsigned char *) renew_crt, crt_len);
                        return_code = certifier_set_property(certifier, CERTIFIER_OPT_CRT, encodedCRT);
                        XFREE(encodedCRT);

                        if (return_code != 0) {
                            set_last_error(certifier, return_code,
                                           util_format_error_here("Could not set CERTIFIER_OPT_CRT property!"));
                            goto cleanup;
                        }
                    } else {
                        set_last_error(certifier, return_code,
                                       util_format_error_here("Could not generate an X509 CRT!"));
                        goto cleanup;
                    }

                    XFREE(renew_crt);
                }
            } else {
                return_code = CERTIFIER_ERR_REGISTER_CERT_RENEWAL + return_code;
                log_info("\nOpted out for auto renewal...\n");
                goto cleanup;
            }
            break;

        default:
            log_info(
                    "\nReceived return_code: %i from certifier_get_device_registration_status and registering again.\n",
                    return_code);
            break;
    }
    return_code = 0;
    set_last_error(certifier, return_code, NULL);

    if (_certifier_get_privkey(certifier) == NULL ||
        certifier->tmp_map.der_public_key == NULL ||
        certifier->tmp_map.base64_public_key == NULL) {

        log_error("Error in Setup.");
        return_code = CERTIFIER_ERR_REGISTER_SETUP + return_code;
        goto cleanup;
    }

    // Create the Certificate Signing Request
    log_info("\nCreating Certificate Signing Request...\n");
    csr_byte_ptr = security_generate_certificate_signing_request(certifier->tmp_map.private_ec_key, &csr_len);
    if (csr_len && csr_byte_ptr) {
        log_debug("\nGot a valid Certificate Signing Request.");
        log_debug("\nCertificate Signing Request: %s\n", csr_byte_ptr);
    } else {
        return_code = CERTIFIER_ERR_REGISTER_SECURITY_1;
        char *err_json = util_format_error("certifier_register_device",
                                           "Internal error.  Failed to Generate Certificate Signing Request!.",
                                           __FILE__, __LINE__);
        set_last_error(certifier, return_code, err_json);
        goto cleanup;
    }


    // Register Client with CA Authority
    log_info("\nRegistering Client...\n");

    certifier_err_info = certifierclient_request_x509_certificate(certifier->prop_map,
                                                                  (unsigned char *) csr_byte_ptr,
                                                                  certifier->tmp_map.node_address,
                                                                  NULL, /* TODO: CERTIFIER_OPT_certifier_id ? */
                                                                  &x509_certs);

    if (x509_certs == NULL || certifier_err_info.application_error_code != 0) {
        log_error("\n<<< Failed to Request X509 Certificate! >>>\n");
        assign_last_error(certifier, &certifier_err_info);
        return_code = CERTIFIER_ERR_REGISTER_CERTIFIER_1 + certifier_err_info.application_error_code;
        goto cleanup;
    } else {
        log_info("\nObtained x509 Certificate Successfully!\n");
    }

    log_info("\nTrimming x509 certificates...\n");
    util_trim(x509_certs);

    log_info("\nLoading Certs from PKCS7...\n");
    certifier_err_info = security_load_certs_from_pem(x509_certs, &certs);
    assign_last_error(certifier, &certifier_err_info);
    return_code = certifier_err_info.application_error_code;
    if (certifier_err_info.application_error_code != 0) {
        log_error("\n<<< Failed to load certs from pkcs7. >>>\n");
        return_code = CERTIFIER_ERR_REGISTER_SECURITY_5;
        goto cleanup;
    }

    security_print_certs_in_list(certs, stderr);

    /* Cert is owned by the 'certs' stack; create our own copy and save it */
    _certifier_set_x509_cert(certifier, security_cert_list_get(certs, 0));
    if (certifier->tmp_map.x509_cert == NULL) {
        return_code = CERTIFIER_ERR_REGISTER_SECURITY_6;
        set_last_error(certifier, return_code,
                       util_format_error_here("Failed to get certificate from certificate list!"));
        goto cleanup;
    }

    const char *password = certifier_get_property(certifier, CERTIFIER_OPT_PASSWORD);

    //FIXME: This decision is done too late. Overwrite policy should be explicit
    // and checked before trying to register (e.g., CERTIFIER_OPT_FORCE_REGISTRATION).
    if (util_file_exists(p12_filename) && !is_cert_auto_renewal_enabled) {
        log_info("\nPKCS12 file %s exists. NOT overwriting!\n", p12_filename);
    } else {
        log_info("\nSaving PKCS12 file %s...\n", p12_filename);
        security_persist_pkcs_12_file(p12_filename, password, certifier->tmp_map.private_ec_key,
                                      certifier->tmp_map.x509_cert, certs, &certifier_err_info);
        assign_last_error(certifier, &certifier_err_info);
        return_code = certifier_err_info.application_error_code;
        log_info("\nPersisted PKCS12 file %s\n", p12_filename);

        if (certifier_err_info.application_error_code != 0) {
            return_code = CERTIFIER_ERR_REGISTER_SECURITY_7;
            goto cleanup;
        }
    }

    // delete the Renamed file if it exists
    if (util_file_exists(renamed_p12_filename)) {
        if (util_delete_file(renamed_p12_filename)) {
            return_code = CERTIFIER_ERR_REGISTER_DELETE_PKCS12_2;
            char *err_json = util_format_error("certifier_register",
                                               "Error trying to delete a renamed PKCS12 file [2].",
                                               __FILE__,
                                               __LINE__);
            set_last_error(certifier, return_code, err_json);
            goto cleanup;
        }
    }

    san = security_get_field_from_cert(certifier->tmp_map.x509_cert, "X509v3 Subject Alternative Name");
    // FIXME: Suspicious overwrite. This value is not exposed via the certifier.h interface and is the certifier_id (OU)
    // in certifier example certificates.
    if (mode == CERTIFIER_APP_REGISTRATION && util_is_not_empty(san)) {
        XSTRNCPY(certifier->tmp_map.node_address, san, sizeof(certifier->tmp_map.node_address) - 1);
        certifier->tmp_map.node_address[sizeof(certifier->tmp_map.node_address) - 1] = '\0';
    }

    // Clean up
    cleanup:

    security_free_cert_list(certs);
    XFREE(san);

    XFREE(x509_certs);

    if (csr_byte_ptr) {
        XFREE(csr_byte_ptr);
    }

    /* FIXME: It is silly to copy items into tmp_map just to throw them away */
    free_tmp(certifier);

    if (force_registration && (util_file_exists(renamed_p12_filename)) && (!util_file_exists(p12_filename))) {
        if (util_rename_file(renamed_p12_filename, p12_filename) != 0) {
            return_code = CERTIFIER_ERR_REGISTER_RENAME_PKCS12_2;
            char *err_json = util_format_error("certifier_register",
                                               "Error trying to delete a renamed PKCS12 file [2].",
                                               __FILE__,
                                               __LINE__);
            set_last_error(certifier, return_code, err_json);
        } else {
            log_info("Renamed file: %s to %s", renamed_p12_filename, p12_filename);
        }
    }

    if (measure_performance) {
        timer_end_time();
        timer_end_CPU_time();
        timer_calculate_cpu_utilization();
        end_memory_used = system_get_memory_used();

        end_user_cpu_time = system_user_cpu_time();
        end_system_cpu_time = system_system_cpu_time();

        log_debug("certifier_register[performance] - Answer %10.1f, Elapsed Time %7.4f, CPU Time %7.4f, CPU Ut %3.0f",
                  timer_get_answer(), timer_get_secs_value(), timer_get_cpu_secs(), timer_get_cpu_utilization());

        if ((start_memory_used > 0) && (end_memory_used > 0)) {
            log_debug("certifier_register[performance] start_memory_used: %ld", start_memory_used);
            log_debug("certifier_register[performance] end_memory_used: %ld", end_memory_used);
        }

        if ((start_user_cpu_time > 0) && (end_user_cpu_time > 0)) {
            log_debug("certifier_register[performance] start_user_cpu_time: %7.4f", start_user_cpu_time);
            log_debug("certifier_register[performance] end_user_cpu_time: %7.4f", end_user_cpu_time);
        }

        if ((start_system_cpu_time > 0) && (end_system_cpu_time > 0)) {
            log_debug("certifier_register[performance] start_system_cpu_time: %7.4f", start_system_cpu_time);
            log_debug("certifier_register[performance] end_system_cpu_time: %7.4f", end_system_cpu_time);
        }
    }

    XFREE(renamed_p12_filename);

    return return_code;
} /* certifier_register */
    

CertifierPropMap *certifier_easy_api_get_props(Certifier *certifier)
{
    return (certifier->prop_map);
}



void certifier_easy_api_get_node_address(Certifier *certifier, char *node_address)
{
    memcpy(node_address, certifier->tmp_map.node_address,SMALL_STRING_SIZE);
}


char* certifier_create_csr_post_data(CertifierPropMap *props,
                                                    const unsigned char *csr,
                                                    const char *node_address,
                                                    const char *certifier_id)
{
    char *json_csr = NULL;

    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    char *serialized_string = NULL;

    const char *system_id = property_get(props, CERTIFIER_OPT_SYSTEM_ID);
    const char *mac_address = property_get(props, CERTIFIER_OPT_MAC_ADDRESS);
    size_t  num_days   = (size_t) property_get(props, CERTIFIER_OPT_NUM_DAYS);
    bool is_certificate_lite = property_is_option_set(props, CERTIFIER_OPTION_CERTIFICATE_LITE);

    json_object_set_string(root_object, "csr", (const char *) csr);
    json_object_set_string(root_object, "nodeAddress", node_address);

    if (util_is_not_empty(system_id))
    {
        if (is_certificate_lite)
        {
            log_debug("\nfabric Id :\n%s\n", system_id);
            json_object_set_string(root_object, "fabricId", system_id);
        }
        else
        {
            log_debug("\nsystem Id :\n%s\n", system_id);
            json_object_set_string(root_object, "systemId", system_id);
        }
    }

    if (util_is_not_empty(certifier_id)) {
        log_debug("\nCertifier Id :\n%s\n", certifier_id);
        json_object_set_string(root_object, "ledgerId", certifier_id);
    }

    if (util_is_not_empty(mac_address)) {
        log_debug("\nmacAddress Id :\n%s\n", mac_address);
        json_object_set_string(root_object, "macAddress", mac_address);
    }

    if (num_days > 0) {
        log_debug("\nvalidityDays  :\n%d\n", num_days);
        json_object_set_number(root_object, "validityDays", num_days);
    }

    if (is_certificate_lite)
    {
        log_debug("CertificateLite=1");
        json_object_set_string(root_object, "certificateLite", "true");
    }

    serialized_string = json_serialize_to_string_pretty(root_value);

    log_debug("\nCertificate Request POST Data:\n%s\n", serialized_string);

    json_csr = XSTRDUP(serialized_string);

    if (root_value) {
        json_value_free(root_value);
    }
    XFREE(serialized_string);

    return json_csr;
}

