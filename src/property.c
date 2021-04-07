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

#define _GNU_SOURCE 1

#include "certifier/property_internal.h"
#include "certifier/certifier.h"
#include "certifier/log.h"
#include "certifier/parson.h"
#include "certifier/types.h"
#include "certifier/util.h"

#ifndef DEFAULT_LOG_LEVEL
#define DEFAULT_LOG_LEVEL            4
#endif
#define DEFAULT_LOG_MAX_SIZE         5000000
#define DEFAULT_HTTP_TIMEOUT         15
#define DEFAULT_HTTP_CONNECT_TIMEOUT 15
#define DEFAULT_ECC_CURVE_ID         "prime256v1"
#define DEFAULT_CFG_FILENAME         "libcertifier.cfg"
#define DEFAULT_CRT_TYPE             "X509"
#define DEFAULT_CA_INFO              "libcertifier-cert.crt"
#define DEFAULT_CA_PATH              "."
#define DEFAULT_CERTIFER_URL         "https://certifier.xpki.io/v1/certifier/certificate"
#define DEFAULT_CERT_MIN_TIME_LEFT_S 7 * 24 * 60 * 60;
#define DEFAULT_OPT_SOURCE           "unset-libcertifier-c-native"

/*
 * All flexible arrays must be on the bottom (last ones)
 * These are the char * types
 */
struct _PropMap {
    XFILE log_file_fp;
    int log_level;
    int log_max_size;
    int http_connect_timeout;
    int http_timeout;
    int options;
    int cert_min_time_left_s;
    int num_days;
    char *log_file;
    char *ca_info;
    char *ca_path;
    char *certifier_url;
    char *cfg_filename;
    char *crt_type;
    char *p12_filename;
    char *password;
    char *certifier_id;
    char *system_id;
    char *mac_address;
    char *crt;
    char *source;
    char *cn_prefix;
    char *ext_key_usage_value;
    char *tracking_id;
    char *ecc_curve_id;
    char *simulated_cert_expiration_date_after;
    char *simulated_cert_expiration_date_before;
    char *root_ca;
    char *int_ca;
    char *auth_token;
    char *output_node;
    char *target_node;
    char *action;
    char *input_node;
};

static void free_prop_map_values(CertifierPropMap *prop_map);

static inline bool is_bool_option(CERTIFIER_OPT which) {
    return which >= CERTIFIER_OPT_BOOL_FIRST;
}

static void print_warning(char *property_name) {
    log_warn("WARNING!  Property key: %s should not be used in PRODUCTION.  It could cause security-related issues.",
             property_name);
}

#define SV(field, value) if (field != NULL) { XFREE(field); field=NULL; }  if (value != NULL) { field = XSTRDUP(value); };

CertifierPropMap *property_new(void) {
    CertifierPropMap *prop_map = XCALLOC(1,sizeof(CertifierPropMap));
    if (prop_map == NULL) {
        log_error("Could not initialize CertifierPropMap.");
        return NULL;
    }

    property_set_defaults(prop_map);
    return prop_map;
}

CertifierPropMap *property_ext(void) {
    CertifierPropMap *prop_map = XCALLOC(1, sizeof(CertifierPropMap));
    if (prop_map == NULL)
    {
        log_error("Could not initialize CertifierPropMap.");
        return NULL;
    }

    property_set_ext(prop_map);
    return prop_map;
}

int property_destroy(CertifierPropMap *prop_map) {

    if (prop_map != NULL) {
        free_prop_map_values(prop_map);
    }

    XFREE(prop_map);

    return 0;
}

int property_set_option(CertifierPropMap *prop_map, CERTIFIER_OPT_OPTION option, bool enable) {
    if (enable) {
        prop_map->options |= option;
    } else {
        prop_map->options &= ~option;
    }

    return 0;
}

bool property_is_option_set(CertifierPropMap *map, CERTIFIER_OPT_OPTION option) {
    return (map->options & option) != 0;
}

int
property_set_int(CertifierPropMap *prop_map, CERTIFIER_OPT name, int value) {

    int retval = 0;

    if (value < 0) {
        return CERTIFIER_ERR_PROPERTY_SET_4;
    }

    switch (name) {
        case CERTIFIER_OPT_HTTP_TIMEOUT:
            prop_map->http_timeout = value;
            break;

        case CERTIFIER_OPT_HTTP_CONNECT_TIMEOUT:
            prop_map->http_connect_timeout = value;
            break;

        case CERTIFIER_OPT_LOG_LEVEL:
            prop_map->log_level = value;
            log_set_level(prop_map->log_level);
            break;

        case CERTIFIER_OPT_LOG_MAX_SIZE:
            prop_map->log_max_size = value;
            log_set_max_size(value);
            break;

        case CERTIFIER_OPT_CERT_MIN_TIME_LEFT_S:
            prop_map->cert_min_time_left_s = value;
            break;

        case CERTIFIER_OPT_NUM_DAYS:
            prop_map->num_days = value;
            break;

        default:
            retval = CERTIFIER_ERR_PROPERTY_SET_5;
    }

    return retval;
}

int
property_set(CertifierPropMap *prop_map, CERTIFIER_OPT name, const void *value) {
    int retval = 0;

    // check if value is null for strings
    switch (name) {
        case CERTIFIER_OPT_HTTP_TIMEOUT:
        case CERTIFIER_OPT_HTTP_CONNECT_TIMEOUT:
        case CERTIFIER_OPT_OPTIONS:
        case CERTIFIER_OPT_LOG_LEVEL:
        case CERTIFIER_OPT_LOG_FUNCTION:
        case CERTIFIER_OPT_CERT_MIN_TIME_LEFT_S:
        case CERTIFIER_OPT_NUM_DAYS:
            // do nothing;
            break;
        default:
            if (!is_bool_option(name) && value == NULL) {
                return CERTIFIER_ERR_PROPERTY_SET_1;
            }
    }

    if (name <= 0) {
        return CERTIFIER_ERR_PROPERTY_SET_2;
    }

    switch (name) {
        case CERTIFIER_OPT_CFG_FILENAME:
        SV(prop_map->cfg_filename, value);
            break;
        case CERTIFIER_OPT_CRT_TYPE:
        SV(prop_map->crt_type, value);
            break;
        case CERTIFIER_OPT_CERTIFIER_URL:
            if (util_starts_with(value, "https://")) {
                SV(prop_map->certifier_url, value);
            } else {
                retval = CERTIFIER_ERR_PROPERTY_SET_7;
            }
            break;

        case CERTIFIER_OPT_KEYSTORE:
        SV(prop_map->p12_filename, value);
            break;

        case CERTIFIER_OPT_PASSWORD:
        SV(prop_map->password, value);
            break;

        case CERTIFIER_OPT_CA_INFO:
        SV(prop_map->ca_info, value);
            break;

        case CERTIFIER_OPT_CA_PATH:
        SV(prop_map->ca_path, value);
            break;

        case CERTIFIER_OPT_CRT:
        SV(prop_map->crt, value);
            break;

        case CERTIFIER_OPT_ECC_CURVE_ID:
        SV(prop_map->ecc_curve_id, value);
            break;

        case CERTIFIER_OPT_SYSTEM_ID:
        SV(prop_map->system_id, value);
            break;

        case CERTIFIER_OPT_MAC_ADDRESS:
        SV(prop_map->mac_address, value);
            break;

        case CERTIFIER_OPT_SIMULATION_CERT_EXP_DATE_BEFORE:
        SV(prop_map->simulated_cert_expiration_date_before, value);
            break;

        case CERTIFIER_OPT_SIMULATION_CERT_EXP_DATE_AFTER:
        SV(prop_map->simulated_cert_expiration_date_after, value);
            break;

            /* integer options */
        case CERTIFIER_OPT_HTTP_TIMEOUT:
        case CERTIFIER_OPT_HTTP_CONNECT_TIMEOUT:
        case CERTIFIER_OPT_LOG_LEVEL:
        case CERTIFIER_OPT_LOG_MAX_SIZE:
        case CERTIFIER_OPT_CERT_MIN_TIME_LEFT_S:
        case CERTIFIER_OPT_NUM_DAYS:
            retval = property_set_int(prop_map, name, (int) (size_t) value);
            break;

        case CERTIFIER_OPT_ROOT_CA:
        SV(prop_map->root_ca, value);
            break;

        case CERTIFIER_OPT_INT_CA:
        SV(prop_map->int_ca, value);
            break;

        case CERTIFIER_OPT_LOG_FILENAME:
        SV(prop_map->log_file, value);
            log_set_file_name(value);
            break;

        case CERTIFIER_OPT_AUTH_TOKEN:
        SV(prop_map->auth_token, value);
            break;

        case CERTIFIER_OPT_OUTPUT_NODE:
        SV(prop_map->output_node, value);
            break;

        case CERTIFIER_OPT_TARGET_NODE:
        SV(prop_map->target_node, value);
            break;

        case CERTIFIER_OPT_ACTION:
        SV(prop_map->action, value);
            break;

        case CERTIFIER_OPT_INPUT_NODE:
        SV(prop_map->input_node, value);
            break;

        case CERTIFIER_OPT_SOURCE:
        SV(prop_map->source, value);
            break;

        case CERTIFIER_OPT_CN_PREFIX:
        SV(prop_map->cn_prefix, value);
            break;

        case CERTIFIER_OPT_TRACKING_ID:
        SV(prop_map->tracking_id, value);
            break;

        case CERTIFIER_OPT_EXT_KEY_USAGE:
        SV(prop_map->ext_key_usage_value, value);
            break;

        case CERTIFIER_OPT_LOG_FUNCTION:
            /* This is handled by certifier_set_property */
            break;

        case CERTIFIER_OPT_OPTIONS:
            /* readonly value */
            log_warn("Property [%d] is read-only", name);
            retval = CERTIFIER_ERR_PROPERTY_SET_1;
            break;

        case CERTIFIER_OPT_DEBUG_HTTP:
        case CERTIFIER_OPT_TRACE_HTTP:
        case CERTIFIER_OPT_TLS_INSECURE_HOST:
        case CERTIFIER_OPT_TLS_INSECURE_PEER:
        case CERTIFIER_OPT_FORCE_REGISTRATION:
        case CERTIFIER_OPT_AUTO_RENEW_CERT:
        case CERTIFIER_OPT_MEASURE_PERFORMANCE:
        case CERTIFIER_OPT_CERTIFICATE_LITE: {
            unsigned int bit = name - CERTIFIER_OPT_BOOL_FIRST;

            CERTIFIER_OPT_OPTION option = 1U << bit;
            property_set_option(prop_map, option, value != 0);
            break;
        }

        default:
            /* some unknown property type */
            log_warn("property_set: unrecognized property [%d]", name);
            return CERTIFIER_ERR_PROPERTY_SET_10;
    }

    return retval;
} /* property_set */

void *
property_get(CertifierPropMap *prop_map, CERTIFIER_OPT name) {
    void *retval = NULL;

    if (name <= 0) {
        log_error("invalid property [%d]", name);
        return NULL;
    }

    switch (name) {
        case CERTIFIER_OPT_CFG_FILENAME:
            retval = prop_map->cfg_filename;
            break;

        case CERTIFIER_OPT_CRT_TYPE:
            retval = prop_map->crt_type;
            break;

        case CERTIFIER_OPT_CERTIFIER_URL:
            retval = prop_map->certifier_url;
            break;

        case CERTIFIER_OPT_HTTP_TIMEOUT:
            retval = (void *) (size_t) prop_map->http_timeout;
            break;

        case CERTIFIER_OPT_HTTP_CONNECT_TIMEOUT:
            retval = (void *) (size_t) prop_map->http_connect_timeout;
            break;

        case CERTIFIER_OPT_KEYSTORE:
            retval = prop_map->p12_filename;
            break;

        case CERTIFIER_OPT_PASSWORD:
            retval = prop_map->password;
            break;

        case CERTIFIER_OPT_CA_INFO:
            retval = prop_map->ca_info;
            break;

        case CERTIFIER_OPT_CA_PATH:
            retval = prop_map->ca_path;
            break;

        case CERTIFIER_OPT_CRT:
            retval = prop_map->crt;
            break;

        case CERTIFIER_OPT_ECC_CURVE_ID:
            retval = prop_map->ecc_curve_id;
            break;

        case CERTIFIER_OPT_OPTIONS:
            retval = (void *) (size_t) prop_map->options;
            break;

        case CERTIFIER_OPT_SYSTEM_ID:
            retval = prop_map->system_id;
            break;

        case CERTIFIER_OPT_MAC_ADDRESS:
            retval = prop_map->mac_address;
            break;

        case CERTIFIER_OPT_SIMULATION_CERT_EXP_DATE_BEFORE:
            retval = prop_map->simulated_cert_expiration_date_before;
            break;

        case CERTIFIER_OPT_SIMULATION_CERT_EXP_DATE_AFTER:
            retval = prop_map->simulated_cert_expiration_date_after;
            break;

        case CERTIFIER_OPT_ROOT_CA:
            retval = prop_map->root_ca;
            break;

        case CERTIFIER_OPT_INT_CA:
            retval = prop_map->int_ca;
            break;

        case CERTIFIER_OPT_LOG_LEVEL:
            retval = (void *) (size_t) prop_map->log_level;
            break;

        case CERTIFIER_OPT_LOG_MAX_SIZE:
            retval = (void *) (size_t) prop_map->log_max_size;
            break;

        case CERTIFIER_OPT_LOG_FILENAME:
            retval = prop_map->log_file;
            break;

        case CERTIFIER_OPT_AUTH_TOKEN:
            retval = prop_map->auth_token;
            break;

        case CERTIFIER_OPT_OUTPUT_NODE:
            retval = prop_map->output_node;
            break;

        case CERTIFIER_OPT_TARGET_NODE:
            retval = prop_map->target_node;
            break;

        case CERTIFIER_OPT_ACTION:
            retval = prop_map->action;
            break;

        case CERTIFIER_OPT_INPUT_NODE:
            retval = prop_map->input_node;
            break;

        case CERTIFIER_OPT_TRACKING_ID:
            retval = prop_map->tracking_id;
            break;

        case CERTIFIER_OPT_SOURCE:
            retval = prop_map->source;
            break;

        case CERTIFIER_OPT_CN_PREFIX:
            retval = prop_map->cn_prefix;
            break;
        case CERTIFIER_OPT_NUM_DAYS:
            retval = (void *) (size_t) prop_map->num_days; // TODO - need to revisit these casts
            break;

        case CERTIFIER_OPT_CERT_MIN_TIME_LEFT_S:
            retval = (void *) (size_t) prop_map->cert_min_time_left_s; // TODO - need to revisit these casts
            break;

        case CERTIFIER_OPT_EXT_KEY_USAGE:
            retval = prop_map->ext_key_usage_value;
            break;

        case CERTIFIER_OPT_LOG_FUNCTION:
            /* Write-only value */
            retval = NULL;
            break;

        case CERTIFIER_OPT_DEBUG_HTTP:
        case CERTIFIER_OPT_TRACE_HTTP:
        case CERTIFIER_OPT_TLS_INSECURE_HOST:
        case CERTIFIER_OPT_TLS_INSECURE_PEER:
        case CERTIFIER_OPT_FORCE_REGISTRATION:
        case CERTIFIER_OPT_AUTO_RENEW_CERT:
        case CERTIFIER_OPT_MEASURE_PERFORMANCE:
        case CERTIFIER_OPT_CERTIFICATE_LITE: {
            unsigned int bit = name - CERTIFIER_OPT_BOOL_FIRST;

            CERTIFIER_OPT_OPTION option = 1U << bit;
            retval = (void *) property_is_option_set(prop_map, option);
            break;
        }

        default:
            log_warn("property_get: unrecognized property [%d]", name);
            retval = NULL;
            break;
    }

    return retval;
} /* property_get */

int
property_set_defaults(CertifierPropMap *prop_map) {
    int return_code = 0;
    char *trace_id = NULL;

    // generate tracking ID
    trace_id = util_generate_random_value(16, ALLOWABLE_CHARACTERS);
    if (trace_id) {
        return_code = property_set(prop_map, CERTIFIER_OPT_TRACKING_ID, trace_id);
        XFREE(trace_id);
        if (return_code != 0) {
            return return_code;
        }
    }

    if (prop_map->cfg_filename == NULL) {
        return_code = property_set(prop_map, CERTIFIER_OPT_CFG_FILENAME, DEFAULT_CFG_FILENAME);
        if (return_code != 0) {
            log_error("Failed to set default property name: CERTIFIER_OPT_CFG_FILENAME with error code: %i",
                      return_code);
            return return_code;
        }
    }

    if (prop_map->crt_type == NULL) {
        return_code = property_set(prop_map, CERTIFIER_OPT_CRT_TYPE, DEFAULT_CRT_TYPE);
        if (return_code != 0) {
            log_error("Failed to set default property name: CERTIFIER_OPT_CRT_TYPE with error code: %i", return_code);
            return return_code;
        }
    }

    if (prop_map->certifier_url == NULL) {
        return_code = property_set(prop_map, CERTIFIER_OPT_CERTIFIER_URL, DEFAULT_CERTIFER_URL);
        if (return_code != 0) {
            log_error("Failed to set default property name: CERTIFIER_OPT_CERTIFIER_URL with error code: %i",
                      return_code);
            return return_code;
        }
    }

    return_code = property_set(prop_map, CERTIFIER_OPT_HTTP_TIMEOUT, (void *) DEFAULT_HTTP_TIMEOUT);
    if (return_code != 0) {
        log_error("Failed to set default property name: CERTIFIER_OPT_HTTP_TIMEOUT with error code: %i", return_code);
    }

    return_code = property_set(prop_map, CERTIFIER_OPT_HTTP_CONNECT_TIMEOUT, (void *) DEFAULT_HTTP_CONNECT_TIMEOUT);
    if (return_code != 0) {
        log_error("Failed to set default property name: CERTIFIER_OPT_HTTP_CONNECT_TIMEOUT with error code: %i",
                  return_code);
        return return_code;
    }

    if (prop_map->ca_info == NULL) {
        return_code = property_set(prop_map, CERTIFIER_OPT_CA_INFO, DEFAULT_CA_INFO);
        if (return_code != 0) {
            log_error("Failed to set default property name: CERTIFIER_OPT_CA_INFO with error code: %i", return_code);
            return return_code;
        }
    }

    if (prop_map->ca_path == NULL) {
        return_code = property_set(prop_map, CERTIFIER_OPT_CA_PATH, DEFAULT_CA_PATH);
        if (return_code != 0) {
            log_error("Failed to set default property name: CERTIFIER_OPT_CA_PATH with error code: %i", return_code);
            return return_code;
        }
    }

    if (prop_map->ecc_curve_id == NULL) {
        return_code = property_set(prop_map, CERTIFIER_OPT_ECC_CURVE_ID, DEFAULT_ECC_CURVE_ID);
        if (return_code != 0) {
            log_error("Failed to set default property name: CERTIFIER_OPT_ECC_CURVE_ID with error code: %i",
                      return_code);
            return return_code;
        }
    }

    if (prop_map->root_ca == NULL) {
        return_code = property_set(prop_map, CERTIFIER_OPT_ROOT_CA, DEFAULT_ROOT_CA);
        if (return_code != 0) {
            log_error("Failed to set default property name: CERTIFIER_OPT_ROOT_CA with error code: %i", return_code);
            return return_code;
        }
    }

    if (prop_map->int_ca == NULL) {
        return_code = property_set(prop_map, CERTIFIER_OPT_INT_CA, DEFAULT_INT_CA);
        if (return_code != 0) {
            log_error("Failed to set default property name: CERTIFIER_OPT_INT_CA with error code: %i", return_code);
            return return_code;
        }
    }

    return_code = property_set(prop_map, CERTIFIER_OPT_LOG_LEVEL, (void *)DEFAULT_LOG_LEVEL);
    if (return_code != 0) {
        log_error("Failed to set default property name: CERTIFIER_OPT_LOG_LEVEL with error code: %i", return_code);
        return return_code;
    }

    return_code = property_set(prop_map, CERTIFIER_OPT_LOG_MAX_SIZE, (void *) (size_t) DEFAULT_LOG_MAX_SIZE);
    if (return_code != 0) {
        log_error("Failed to set default property name: CERTIFIER_OPT_LOG_MAX_SIZE with error code: %i", return_code);
        return return_code;
    }
    log_set_max_size(prop_map->log_max_size);

    prop_map->options |= CERTIFIER_OPTION_AUTO_RENEW_CERT;


    prop_map->cert_min_time_left_s = DEFAULT_CERT_MIN_TIME_LEFT_S;

    return_code = property_set(prop_map, CERTIFIER_OPT_SOURCE, DEFAULT_OPT_SOURCE);
    if (return_code != 0) {
        log_error("Failed to set default property name: CERTIFIER_OPT_SOURCE with error code: %i", return_code);
        return return_code;
    }   

    return return_code;
}

int property_set_ext(CertifierPropMap *prop_map) {
    JSON_Value *json;
    const char *ext_key_usage_value = NULL;
    int ret = 0;

    char *file_contents = NULL;
    size_t file_contents_len = 0;

    ret = util_slurp(DEFAULT_CFG_FILENAME, &file_contents, &file_contents_len);
    if (ret != 0)
    {
        log_error("Received code: %i from util_slurp", ret);
        if (file_contents != NULL)
        {
            XFREE(file_contents);
        }
        return 1;
    }
    else
    {
        json = json_parse_string_with_comments(file_contents);
        XFREE(file_contents);
        if (json == NULL)
        {
            log_error("json_parse_string_with_comments returned a NULL value.  Perhaps JSON malformed?", ret);
            return 1;
        }
    }

    ext_key_usage_value = json_object_get_string(json_object(json), "libcertifier.ext.key.usage");
    if (ext_key_usage_value)
    {
        //log_info("Loaded Extended Key Usage Values: %s", ext_key_usage_value);
        property_set(prop_map, CERTIFIER_OPT_EXT_KEY_USAGE, ext_key_usage_value);
    }

    if (json)
    {
        json_value_free(json);
    }

    return 0;
}

int
property_set_defaults_from_cfg_file(CertifierPropMap *propMap) {

    JSON_Value *json;

    const char *certifier_url_value = NULL;
    const char *crt_type_value = NULL;
    const char *password_value = NULL;
    const char *system_id_value = NULL;
    int http_timeout_value;
    int http_connect_timeout_value;
    int http_trace_value;
    const char *keystore_value = NULL;
    int disable_auto_renewal_value;
    const char *ca_info_value = NULL;
    const char *ca_path_value = NULL;
    int tls_verify_peer_value;
    int tls_verify_host_value;
    const char *ecc_curve_id_value = NULL;
    const char *root_ca_value = NULL;
    const char *int_ca_value = NULL;
    const char *log_file_value = NULL;
    int log_level_value;
    int log_max_size_value;
    int measure_performance_value;
    double cert_min_time_left_s;
    int num_days;
    const char *source = NULL;
    int certificate_lite_value;
    const char *cn_prefix = NULL;
    const char *ext_key_usage_value = NULL;

    int ret = 0;

    char *file_contents = NULL;
    size_t file_contents_len = 0;

    log_info("Loading cfg file: %s", propMap->cfg_filename);

    log_debug("About to call: util_slurp with path: %s", propMap->cfg_filename);
    ret = util_slurp(propMap->cfg_filename, &file_contents, &file_contents_len);
    if (ret != 0) {
        log_error("Received code: %i from util_slurp", ret);
        if (file_contents != NULL) {
            XFREE(file_contents);
        }
        return 1;
    } else {
        json = json_parse_string_with_comments(file_contents);
        XFREE(file_contents);
        if (json == NULL) {
            log_error("json_parse_string_with_comments returned a NULL value.  Perhaps JSON malformed?", ret);
            return 1;
        }
    }

    certifier_url_value = json_object_get_string(json_object(json), "libcertifier.certifier.url");
    if (certifier_url_value) {
        log_info("Loaded certifier url: %s from config file.", certifier_url_value);
        property_set(propMap, CERTIFIER_OPT_CERTIFIER_URL, certifier_url_value);
    }

    crt_type_value = json_object_get_string(json_object(json), "libcertifier.crt.type");
    if (crt_type_value) {
        log_info("Loaded crt.type: %s from config file.", crt_type_value);
        property_set(propMap, CERTIFIER_OPT_CRT_TYPE, crt_type_value);
    }

    password_value = json_object_get_string(json_object(json), "libcertifier.password");
    if (password_value) {
        print_warning("password");
        log_info("Loaded password from config file.");
        property_set(propMap, CERTIFIER_OPT_PASSWORD, password_value);
    }

    system_id_value = json_object_get_string(json_object(json), "libcertifier.system.id");
    if (system_id_value) {
        log_info("Loaded system_id_value: %s from config file.", system_id_value);
        property_set(propMap, CERTIFIER_OPT_SYSTEM_ID, system_id_value);
    }

    http_timeout_value = json_object_get_number(json_object(json), "libcertifier.http.timeout");
    if (http_timeout_value >= 0) {
        log_info("Loaded http_timeout_value: %i from cfg file.", http_timeout_value);
        property_set(propMap, CERTIFIER_OPT_HTTP_TIMEOUT, (void *) (size_t) http_timeout_value);
    }

    http_connect_timeout_value = json_object_get_number(json_object(json), "libcertifier.http.connect.timeout");
    if (http_connect_timeout_value >= 0) {
        log_info("Loaded http_connect_timeout_value: %i from cfg file.", http_connect_timeout_value);
        property_set(propMap, CERTIFIER_OPT_HTTP_CONNECT_TIMEOUT, (void *) (size_t) http_connect_timeout_value);
    }

    http_trace_value = json_object_get_number(json_object(json), "libcertifier.http.trace");
    if (http_trace_value == 1) {
        log_info("Loaded http_trace_value: %i from cfg file.", http_trace_value);
        print_warning("http.trace");
        propMap->options |= (CERTIFIER_OPTION_TRACE_HTTP | CERTIFIER_OPTION_DEBUG_HTTP);
    }

    measure_performance_value = json_object_get_number(json_object(json), "libcertifier.measure.performance");
    if (measure_performance_value == 1) {
        log_info("Loaded measure.performance: %i from cfg file.", http_trace_value);
        propMap->options |= CERTIFIER_OPTION_MEASURE_PERFORMANCE;
    }

    keystore_value = json_object_get_string(json_object(json), "libcertifier.keystore");
    if (keystore_value) {
        log_info("Loaded keystore_value: %s from cfg file.", keystore_value);
        property_set(propMap, CERTIFIER_OPT_KEYSTORE, keystore_value);
    }

    ca_info_value = json_object_get_string(json_object(json), "libcertifier.ca.info");
    if (ca_info_value) {
        log_info("Loaded ca_info_value: %s from cfg file.", ca_info_value);
        property_set(propMap, CERTIFIER_OPT_CA_INFO, ca_info_value);
    }

    ca_path_value = json_object_get_string(json_object(json), "libcertifier.ca.path");
    if (ca_path_value) {
        log_info("Loaded ca_path_value: %s from cfg file.", ca_path_value);
        property_set(propMap, CERTIFIER_OPT_CA_PATH, ca_path_value);
    }

    cert_min_time_left_s = json_object_get_number(json_object(json), "libcertifier.cert.min_time_left_s");
    if (cert_min_time_left_s >= 0 && cert_min_time_left_s <= XINT_MAX) {
        log_info("Loaded cert.min_time_left_s: %.0f", cert_min_time_left_s);
        property_set(propMap, CERTIFIER_OPT_CERT_MIN_TIME_LEFT_S, (void *) (size_t) cert_min_time_left_s);
    }
    num_days = json_object_get_number(json_object(json), "libcertifier.num.days");
    if (num_days)
    {
        log_info("Loaded num_days: %d", num_days);
        property_set(propMap, CERTIFIER_OPT_NUM_DAYS, (void *)(size_t)num_days);
    }
    disable_auto_renewal_value = json_object_get_number(json_object(json), "libcertifier.disable.auto.renewal");
    if (disable_auto_renewal_value == 1) {
        log_info("Loaded disable_auto_renewal_value: %i from cfg file.", disable_auto_renewal_value);
        propMap->options &= ~CERTIFIER_OPTION_AUTO_RENEW_CERT;
    }

    tls_verify_peer_value = json_object_get_number(json_object(json), "libcertifier.tls.insecure.peer");
    if (tls_verify_peer_value == 1) {
        print_warning("tls.insecure.peer");
        log_info("Loaded tls_verify_peer_value: %i from cfg file.", tls_verify_peer_value);
        propMap->options |= CERTIFIER_OPTION_TLS_INSECURE_PEER;
    }

    tls_verify_host_value = json_object_get_number(json_object(json), "libcertifier.tls.insecure.host");
    if (tls_verify_host_value == 1) {
        print_warning("tls.insecure.host");
        log_info("Loaded tls_verify_host_value: %i from cfg file.", tls_verify_host_value);
        propMap->options |= CERTIFIER_OPTION_TLS_INSECURE_HOST;
    }

    ecc_curve_id_value = json_object_get_string(json_object(json), "libcertifier.ecc.curve.id");
    if (ecc_curve_id_value) {
        log_info("Loaded ecc_curve_id_value: %s from cfg file.", ecc_curve_id_value);
        property_set(propMap, CERTIFIER_OPT_ECC_CURVE_ID, ecc_curve_id_value);
    }

    root_ca_value = json_object_get_string(json_object(json), "libcertifier.root.ca");
    if (root_ca_value) {
        log_info("Loaded root_ca_value: %s from cfg file.", root_ca_value);
        property_set(propMap, CERTIFIER_OPT_ROOT_CA, root_ca_value);
    }

    int_ca_value = json_object_get_string(json_object(json), "libcertifier.int.ca");
    if (int_ca_value) {
        log_info("Loaded int_ca_value: %s from cfg file.", int_ca_value);
        property_set(propMap, CERTIFIER_OPT_INT_CA, int_ca_value);
    }

    log_file_value = json_object_get_string(json_object(json), "libcertifier.log.file");
    if (log_file_value) {
        log_info("Loaded Log File Value: %s from cfg file.", log_file_value);
        property_set(propMap, CERTIFIER_OPT_LOG_FILENAME, log_file_value);
    }

    log_level_value = json_object_get_number(json_object(json), "libcertifier.log.level");
    if (log_level_value >= 0) {
        log_info("Loaded Log Level value: %i from cfg file.", log_level_value);
        property_set(propMap, CERTIFIER_OPT_LOG_LEVEL,
                     (void *) (size_t) (log_level_value));
    }

    log_max_size_value = json_object_get_number(json_object(json), "libcertifier.log.max.size");
    if (log_max_size_value >= 0) {
        log_info("Loaded Log Max Size value: %i from cfg file.", log_max_size_value);
        property_set(propMap, CERTIFIER_OPT_LOG_MAX_SIZE,
                     (void *) (size_t) (log_max_size_value));
    }
    log_set_max_size(propMap->log_max_size);

    source = json_object_get_string(json_object(json), "libcertifier.source.name");
    if (source) {
        log_info("Loaded source.name %s from cfg file.", source);
        property_set(propMap, CERTIFIER_OPT_SOURCE, source);
    }

    certificate_lite_value = json_object_get_number(json_object(json), "libcertifier.certificate.lite");
    if (certificate_lite_value == 1) {
        log_info("Loaded certificate.lite: %i from cfg file.", certificate_lite_value);
        print_warning("certificate.lite");
        propMap->options |= (CERTIFIER_OPTION_CERTIFICATE_LITE);
    }
    cn_prefix = json_object_get_string(json_object(json), "libcertifier.cn.name");
    if (cn_prefix != NULL)
    {
        log_info("Loaded Common Name value: %s from cfg file.", cn_prefix);
        property_set(propMap, CERTIFIER_OPT_CN_PREFIX, cn_prefix);
    }
    ext_key_usage_value = json_object_get_string(json_object(json), "libcertifier.ext.key.usage");
    if (ext_key_usage_value)
    {
        log_info("Loaded Extended Key Usage Values: %s from cfg file.", ext_key_usage_value);
        property_set(propMap, CERTIFIER_OPT_EXT_KEY_USAGE, ext_key_usage_value);
    }

    if (json) {
        json_value_free(json);
    }

    return 0;
}

#define FV(field) if (field != NULL) { XFREE(field); }

static void free_prop_map_values(CertifierPropMap *prop_map) {
    // free the values
    FV(prop_map->log_file);
    FV(prop_map->ca_info);
    FV(prop_map->ca_path);
    FV(prop_map->certifier_url);
    FV(prop_map->crt_type);
    FV(prop_map->cfg_filename);
    FV(prop_map->p12_filename);
    FV(prop_map->password);
    FV(prop_map->certifier_id);
    FV(prop_map->system_id);
    FV(prop_map->mac_address);
    FV(prop_map->crt);
    FV(prop_map->ecc_curve_id);
    FV(prop_map->simulated_cert_expiration_date_after);
    FV(prop_map->simulated_cert_expiration_date_before);
    FV(prop_map->root_ca);
    FV(prop_map->int_ca);
    FV(prop_map->auth_token);
    FV(prop_map->output_node);
    FV(prop_map->target_node);
    FV(prop_map->action);
    FV(prop_map->input_node);
    FV(prop_map->tracking_id);
    FV(prop_map->source);
    FV(prop_map->cn_prefix);
    FV(prop_map->ext_key_usage_value);
}
