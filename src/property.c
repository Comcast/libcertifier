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

#include "certifier/certifier.h"
#include "certifier/log.h"
#include "certifier/parson.h"
#include "certifier/property_internal.h"
#include "certifier/types.h"
#include "certifier/util.h"
#include "certifier/security.h"

#ifndef DEFAULT_LOG_LEVEL
#define DEFAULT_LOG_LEVEL 4
#endif
#define DEFAULT_LOG_MAX_SIZE 5000000
#define DEFAULT_HTTP_TIMEOUT 15
#define DEFAULT_HTTP_CONNECT_TIMEOUT 15
#define DEFAULT_ECC_CURVE_ID "prime256v1"
#define DEFAULT_OUTPUT_P12_PATH "output.p12"
#define DEFAULT_CFG_FILENAME "libcertifier.cfg"
#define DEFAULT_USER_CFG_FILENAME "/usr/local/etc/certifier/libcertifier.cfg"
#define DEFAULT_GLOBAL_CFG_FILENAME "/etc/certifier/libcertifier.cfg"
#define DEFAULT_AUTH_TYPE "X509"
#define DEFAULT_CA_INFO "libcertifier-cert.crt"
#define DEFAULT_USER_CA_INFO "/usr/local/etc/certfier/libcertifier-cert.crt"
#define DEFAULT_GLOBAL_CA_INFO "/etc/ssl/certs/libcertifier-cert.crt"
#define DEFAULT_CA_PATH "/etc/ssl/certs"
#define DEFAULT_USER_CA_PATH "/usr/local/etc/certfier"
#define DEFAULT_GLOBAL_CA_PATH "/etc/certifier"
#define DEFAULT_CURDIR_CA_PATH "."
#define DEFAULT_CERTIFIER_URL "https://certifier.xpki.io/v1/certifier"
#define DEFAULT_PROFILE_NAME "XFN_Matter_OP_Class_3_ICA"
#define DEFAULT_CERT_MIN_TIME_LEFT_S 90 * 24 * 60 * 60;
#define DEFAULT_OPT_SOURCE "unset-libcertifier-c-native"
#define DEFAULT_PRODUCT_ID "1101"
#define DEFAULT_AUTORENEW_INTERVAL 86400
#define DEFAULT_AUTORENEW_CERTS_PATH "~/.libcertifier"

static char * simple_json_array_to_csv(const char *json_array_str)
{
    // Assumes input like ["a","b","c"]
    if (!json_array_str || json_array_str[0] != '[') return XSTRDUP("");
    size_t len = strlen(json_array_str);
    char *csv = XCALLOC(len + 1, sizeof(char));
    if (!csv) return NULL;

    size_t j = 0;
    bool in_string = false;
    for (size_t i = 0; i < len; ++i) {
        char c = json_array_str[i];
        if (c == '"') {
            in_string = !in_string;
            continue;
        }
        if (in_string) {
            csv[j++] = c;
        } else if (c == ',' && j > 0) {
            csv[j++] = ',';
        }
    }
    csv[j] = '\0';
    return csv;
}

const char * get_default_cfg_filename()
{
    static char cfg[]       = DEFAULT_CFG_FILENAME;
    static char user_cfg[]  = DEFAULT_USER_CFG_FILENAME;
    static char glbl_cfg[]  = DEFAULT_GLOBAL_CFG_FILENAME;
    char * cfg_order_list[] = { cfg, user_cfg, glbl_cfg };

    for (int i = 0; i < sizeof(cfg_order_list) / sizeof(*cfg_order_list); ++i)
    {
        if (util_file_exists(cfg_order_list[i]))
        {
            return cfg_order_list[i];
        }
    }

    return NULL;
}

const char * get_default_ca_path()
{
    static char ca[]        = DEFAULT_CA_PATH;
    static char user_ca[]   = DEFAULT_USER_CA_PATH;
    static char glbl_ca[]   = DEFAULT_GLOBAL_CA_PATH;
    static char curdir_ca[] = DEFAULT_CURDIR_CA_PATH;
    char * ca_order_list[]  = { ca, user_ca, glbl_ca, curdir_ca };

    static char ca_filepath[256] = { 0 };

    for (int i = 0; i < sizeof(ca_order_list) / sizeof(*ca_order_list); ++i)
    {
        size_t max_len = strlen(ca_order_list[i]) + strlen(DEFAULT_CA_INFO) + 2;
        if (max_len > sizeof(ca_filepath))
        {
            return NULL;
        }

        memcpy(ca_filepath, ca_order_list[i], strlen(ca_order_list[i]));
        ca_filepath[strlen(ca_order_list[i])] = '/';
        memcpy(ca_filepath + strlen(ca_order_list[i]) + 1, DEFAULT_CA_INFO, strlen(DEFAULT_CA_INFO));
        ca_filepath[max_len - 1] = '\0';

        if (util_file_exists(ca_filepath))
        {
            return ca_order_list[i];
        }
    }

    return NULL;
}

const char * get_default_ca_info()
{
    static char ca[]       = DEFAULT_CA_INFO;
    static char user_ca[]  = DEFAULT_USER_CA_INFO;
    static char glbl_ca[]  = DEFAULT_GLOBAL_CA_INFO;
    char * ca_order_list[] = { ca, user_ca, glbl_ca };

    for (int i = 0; i < sizeof(ca_order_list) / sizeof(*ca_order_list); ++i)
    {
        if (util_file_exists(ca_order_list[i]))
        {
            return ca_order_list[i];
        }
    }

    return ca;
}

/*
 * All flexible arrays must be on the bottom (last ones)
 * These are the char * types
 */
struct _PropMap
{
    XFILE log_file_fp;
    int log_level;
    int log_max_size;
    int http_connect_timeout;
    int http_timeout;
    int options;
    int cert_min_time_left_s;
    int validity_days;
    int autorenew_interval;
    char * log_file;
    char * ca_info;
    char * ca_path;
    char * certifier_url;
    char * cfg_filename;
    char * auth_type;
    char * p12_filename;
    char * output_p12_filename;
    char * password;
    char * password_out;
    char * certifier_id;
    char * system_id;
    char * fabric_id;
    char * node_id;
    char * product_id;
    char * auth_tag_1;
    char * mac_address;
    char * dns_san;
    char * ip_san;
    char * email_san;
    char * crt;
    char * profile_name;
    char * source;
    char * cn_prefix;
    char * domain;
    char * ext_key_usage_value;
    char * tracking_id;
    char * ecc_curve_id;
    char * simulated_cert_expiration_date_after;
    char * simulated_cert_expiration_date_before;
    char * auth_token;
    char * output_node;
    char * target_node;
    char * action;
    char * input_node;
    char * autorenew_certs_path_list;
    X509_CERT * cert_x509_out;
    char * mtls_filename;
    char * mtls_p12_filename;
    //Sectigo values
    char * sectigo_auth_token;
    char * sectigo_common_name;
    char * sectigo_group_name;
    char * sectigo_group_email;
    char * sectigo_id;
    char * sectigo_owner_fname;
    char * sectigo_owner_lname;
    char * sectigo_employee_type;
    char * sectigo_server_platform;
    bool sectigo_sensitive;
    char * sectigo_project_name;
    char * sectigo_business_justification;
    char * sectigo_subject_alt_names;
    char * sectigo_ip_addresses;
    char * sectigo_owner_phonenum;
    char * sectigo_owner_email;
    char * sectigo_cert_type;
    char * sectigo_tracking_id;
    char * sectigo_source;
    char * sectigo_url;
};

static void free_prop_map_values(CertifierPropMap * prop_map);

static inline bool is_bool_option(CERTIFIER_OPT which)
{
    return which >= CERTIFIER_OPT_BOOL_FIRST;
}

static void print_warning(char * property_name)
{
    log_warn("WARNING!  Property key: %s should not be used in PRODUCTION.  It could cause security-related issues.",
             property_name);
}

#define SV(field, value)                                                                                                           \
    if (field != value)                                                                                                            \
    {                                                                                                                              \
        if (field != NULL)                                                                                                         \
        {                                                                                                                          \
            XFREE(field);                                                                                                          \
            field = NULL;                                                                                                          \
        }                                                                                                                          \
        if (value != NULL)                                                                                                         \
        {                                                                                                                          \
            field = XSTRDUP(value);                                                                                                \
        }                                                                                                                          \
    };

CertifierPropMap * property_new(void)
{
    CertifierPropMap * prop_map = XCALLOC(1, sizeof(CertifierPropMap));
    if (prop_map == NULL)
    {
        log_error("Could not initialize CertifierPropMap.");
        return NULL;
    }

    property_set_defaults(prop_map);
    return prop_map;
}

CertifierPropMap * property_ext(void)
{
    CertifierPropMap * prop_map = XCALLOC(1, sizeof(CertifierPropMap));
    if (prop_map == NULL)
    {
        log_error("Could not initialize CertifierPropMap.");
        return NULL;
    }

    property_set_ext(prop_map);
    return prop_map;
}

int property_destroy(CertifierPropMap * prop_map)
{

    if (prop_map != NULL)
    {
        free_prop_map_values(prop_map);
    }

    XFREE(prop_map);

    return 0;
}

int property_set_option(CertifierPropMap * prop_map, CERTIFIER_OPT_OPTION option, bool enable)
{
    if (enable)
    {
        prop_map->options |= option;
    }
    else
    {
        prop_map->options &= ~option;
    }

    return 0;
}

bool property_is_option_set(CertifierPropMap * map, CERTIFIER_OPT_OPTION option)
{
    return (map->options & option) != 0;
}

int property_set_int(CertifierPropMap * prop_map, CERTIFIER_OPT name, int value)
{

    int retval = 0;

    if (value < 0)
    {
        return CERTIFIER_ERR_PROPERTY_SET_4;
    }

    switch (name)
    {
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

    case CERTIFIER_OPT_VALIDITY_DAYS:
        prop_map->validity_days = value;
        break;

    case CERTIFIER_OPT_AUTORENEW_INTERVAL:
        prop_map->autorenew_interval = value;
        break;

    default:
        retval = CERTIFIER_ERR_PROPERTY_SET_5;
    }

    return retval;
}

int sectigo_property_set(CertifierPropMap * prop_map, int name, const void * value)
{
    int retval = 0;
    switch (name)
    {
        case CERTIFIER_OPT_CFG_FILENAME:
            prop_map->cfg_filename = XSTRDUP((const char *)value);
            break;
        case CERTIFIER_OPT_LOG_LEVEL:
            prop_map->log_level = (int)(size_t)value;
            log_set_level(prop_map->log_level);
            break;
        case CERTIFIER_OPT_SECTIGO_AUTH_TOKEN:
            prop_map->sectigo_auth_token = XSTRDUP((const char *)value);
            break;
        case CERTIFIER_OPT_SECTIGO_COMMON_NAME:
            prop_map->sectigo_common_name = XSTRDUP((const char *)value);
            break;
        case CERTIFIER_OPT_SECTIGO_GROUP_NAME:
            prop_map->sectigo_group_name = XSTRDUP((const char *)value);
            break;
        case CERTIFIER_OPT_SECTIGO_GROUP_EMAIL:
            prop_map->sectigo_group_email = XSTRDUP((const char *)value);
            break;
        case CERTIFIER_OPT_SECTIGO_ID:
            prop_map->sectigo_id = XSTRDUP((const char *)value);
            break;
        case CERTIFIER_OPT_SECTIGO_OWNER_FNAME:
            prop_map->sectigo_owner_fname = XSTRDUP((const char *)value);
            break;
        case CERTIFIER_OPT_SECTIGO_OWNER_LNAME:
            prop_map->sectigo_owner_lname = XSTRDUP((const char *)value);
            break;
        case CERTIFIER_OPT_SECTIGO_EMPLOYEE_TYPE:
            prop_map->sectigo_employee_type = XSTRDUP((const char *)value);
            break;
        case CERTIFIER_OPT_SECTIGO_SERVER_PLATFORM:
            prop_map->sectigo_server_platform = XSTRDUP((const char *)value);
            break;
        case CERTIFIER_OPT_SECTIGO_SENSITIVE:
            prop_map->sectigo_sensitive = (bool)(size_t)value;
            break;
        case CERTIFIER_OPT_SECTIGO_PROJECT_NAME:
            prop_map->sectigo_project_name = XSTRDUP((const char *)value);
            break;
        case CERTIFIER_OPT_SECTIGO_BUSINESS_JUSTIFICATION:
            prop_map->sectigo_business_justification = XSTRDUP((const char *)value);
            break;
        case CERTIFIER_OPT_SECTIGO_SUBJECT_ALT_NAMES:
            prop_map->sectigo_subject_alt_names = XSTRDUP((const char *)value);
            break;
        case CERTIFIER_OPT_SECTIGO_IP_ADDRESSES:
            prop_map->sectigo_ip_addresses = XSTRDUP((const char *)value);
            break;
        case CERTIFIER_OPT_SECTIGO_CERT_TYPE:
            prop_map->sectigo_cert_type = XSTRDUP((const char *)value);
            break;
        case CERTIFIER_OPT_SECTIGO_OWNER_PHONENUM:
            prop_map->sectigo_owner_phonenum = XSTRDUP((const char *)value);
            break;
        case CERTIFIER_OPT_SECTIGO_OWNER_EMAIL:
            prop_map->sectigo_owner_email = XSTRDUP((const char *)value);
            break;
        case CERTIFIER_OPT_SECTIGO_TRACKING_ID:
            prop_map->sectigo_tracking_id = XSTRDUP((const char *)value);
            break;
        case CERTIFIER_OPT_SECTIGO_SOURCE:
            prop_map->sectigo_source = XSTRDUP((const char *)value);
            break;
        case CERTIFIER_OPT_SECTIGO_CERTIFIER_URL:
            prop_map->sectigo_url = XSTRDUP((const char *)value);
            break;
        default:
            log_warn("sectigo_property_set: unrecognized property [%d]", name);
            retval = CERTIFIER_ERR_PROPERTY_SET_10;
            break;
    }
    return retval;
}
int property_set(CertifierPropMap * prop_map, CERTIFIER_OPT name, const void * value)
{
    int retval = 0;

    // check if value is null for strings
    switch (name)
    {
    case CERTIFIER_OPT_HTTP_TIMEOUT:
    case CERTIFIER_OPT_HTTP_CONNECT_TIMEOUT:
    case CERTIFIER_OPT_OPTIONS:
    case CERTIFIER_OPT_LOG_LEVEL:
    case CERTIFIER_OPT_LOG_FUNCTION:
    case CERTIFIER_OPT_CERT_MIN_TIME_LEFT_S:
    case CERTIFIER_OPT_VALIDITY_DAYS:
    case CERTIFIER_OPT_AUTORENEW_INTERVAL:
        // do nothing;
        break;
    default:
        if (!is_bool_option(name) && value == NULL)
        {
            return CERTIFIER_ERR_PROPERTY_SET_1;
        }
    }

    if (name <= 0)
    {
        return CERTIFIER_ERR_PROPERTY_SET_2;
    }

    switch (name)
    {
    case CERTIFIER_OPT_CERT_X509_OUT:
        security_free_cert(prop_map->cert_x509_out);
        prop_map->cert_x509_out = (X509_CERT *) value;
        break;
    case CERTIFIER_OPT_CFG_FILENAME:
        SV(prop_map->cfg_filename, value);
        break;
    case CERTIFIER_OPT_AUTH_TYPE:
        SV(prop_map->auth_type, value);
        break;
    case CERTIFIER_OPT_CERTIFIER_URL:
        if (util_starts_with(value, "https://"))
        {
            SV(prop_map->certifier_url, value);
        }
        else
        {
            retval = CERTIFIER_ERR_PROPERTY_SET_7;
        }
        break;

    case CERTIFIER_OPT_INPUT_P12_PATH:
        SV(prop_map->p12_filename, value);
        break;

    case CERTIFIER_OPT_OUTPUT_P12_PATH:
        SV(prop_map->output_p12_filename, value);
        break;

    case CERTIFIER_OPT_INPUT_P12_PASSWORD:
        SV(prop_map->password, value);
        break;

    case CERTIFIER_OPT_OUTPUT_P12_PASSWORD:
        SV(prop_map->password_out, value);
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

    case CERTIFIER_OPT_PROFILE_NAME:
        SV(prop_map->profile_name, value);
        break;

    case CERTIFIER_OPT_ECC_CURVE_ID:
        SV(prop_map->ecc_curve_id, value);
        break;

    case CERTIFIER_OPT_SYSTEM_ID:
        SV(prop_map->system_id, value);
        break;

    case CERTIFIER_OPT_FABRIC_ID:
        SV(prop_map->fabric_id, value);
        break;

    case CERTIFIER_OPT_NODE_ID:
        SV(prop_map->node_id, value);
        break;

    case CERTIFIER_OPT_PRODUCT_ID:
        SV(prop_map->product_id, value);
        break;

    case CERTIFIER_OPT_AUTH_TAG_1:
        SV(prop_map->auth_tag_1, value);
        break;

    case CERTIFIER_OPT_MAC_ADDRESS:
        SV(prop_map->mac_address, value);
        break;

    case CERTIFIER_OPT_DNS_SAN:
        SV(prop_map->dns_san, value);
        break;

    case CERTIFIER_OPT_IP_SAN:
        SV(prop_map->ip_san, value);
        break;

    case CERTIFIER_OPT_EMAIL_SAN:
        SV(prop_map->email_san, value);
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
    case CERTIFIER_OPT_VALIDITY_DAYS:
    case CERTIFIER_OPT_AUTORENEW_INTERVAL:
        retval = property_set_int(prop_map, name, (int) (size_t) value);
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

    case CERTIFIER_OPT_DOMAIN:
        SV(prop_map->domain, value);
        break;

    case CERTIFIER_OPT_TRACKING_ID:
        SV(prop_map->tracking_id, value);
        break;

    case CERTIFIER_OPT_EXT_KEY_USAGE:
        SV(prop_map->ext_key_usage_value, value);
        break;

    case CERTIFIER_OPT_AUTORENEW_CERTS_PATH_LIST:
        SV(prop_map->autorenew_certs_path_list, value);
        break;

    case CERTIFIER_OPT_LOG_FUNCTION:
        /* This is handled by certifier_set_property */
        break;

    case CERTIFIER_OPT_OPTIONS:
        /* readonly value */
        log_warn("Property [%d] is read-only", name);
        retval = CERTIFIER_ERR_PROPERTY_SET_1;
        break;

    case CERTIFIER_OPT_MTLS_P12_PATH:
        SV(prop_map->mtls_filename, value);
        break;

    case CERTIFIER_OPT_MTLS_P12_PASSWORD:
        SV(prop_map->mtls_p12_filename, value);
        break;

    case CERTIFIER_OPT_DEBUG_HTTP:
    case CERTIFIER_OPT_TRACE_HTTP:
    case CERTIFIER_OPT_FORCE_REGISTRATION:
    case CERTIFIER_OPT_MEASURE_PERFORMANCE:
    case CERTIFIER_OPT_CERTIFICATE_LITE: {
        unsigned int bit = name - CERTIFIER_OPT_BOOL_FIRST;

        CERTIFIER_OPT_OPTION option = 1U << bit;
        property_set_option(prop_map, option, value != 0);
        break;
    }

    case CERTIFIER_OPT_USE_SCOPES: {
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

void * property_get(CertifierPropMap * prop_map, CERTIFIER_OPT name)
{
    void * retval = NULL;

    if (name <= 0)
    {
        log_error("invalid property [%d]", name);
        return NULL;
    }

    switch (name)
    {
    case CERTIFIER_OPT_CFG_FILENAME:
        retval = prop_map->cfg_filename;
        break;

    case CERTIFIER_OPT_CERT_X509_OUT:
        retval = (void *) prop_map->cert_x509_out;
        break;

    case CERTIFIER_OPT_AUTH_TYPE:
        retval = prop_map->auth_type;
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

    case CERTIFIER_OPT_INPUT_P12_PATH:
        retval = prop_map->p12_filename;
        break;

    case CERTIFIER_OPT_OUTPUT_P12_PATH:
        retval = prop_map->output_p12_filename;
        break;

    case CERTIFIER_OPT_INPUT_P12_PASSWORD:
        retval = prop_map->password;
        break;

    case CERTIFIER_OPT_OUTPUT_P12_PASSWORD:
        retval = prop_map->password_out;
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

    case CERTIFIER_OPT_PROFILE_NAME:
        retval = prop_map->profile_name;
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

    case CERTIFIER_OPT_FABRIC_ID:
        retval = prop_map->fabric_id;
        break;

    case CERTIFIER_OPT_NODE_ID:
        retval = prop_map->node_id;
        break;

    case CERTIFIER_OPT_PRODUCT_ID:
        retval = prop_map->product_id;
        break;

    case CERTIFIER_OPT_AUTH_TAG_1:
        retval = prop_map->auth_tag_1;
        break;

    case CERTIFIER_OPT_MAC_ADDRESS:
        retval = prop_map->mac_address;
        break;

    case CERTIFIER_OPT_DNS_SAN:
        retval = prop_map->dns_san;
        break;

    case CERTIFIER_OPT_IP_SAN:
        retval = prop_map->ip_san;
        break;

    case CERTIFIER_OPT_EMAIL_SAN:
        retval = prop_map->email_san;
        break;

    case CERTIFIER_OPT_SIMULATION_CERT_EXP_DATE_BEFORE:
        retval = prop_map->simulated_cert_expiration_date_before;
        break;

    case CERTIFIER_OPT_SIMULATION_CERT_EXP_DATE_AFTER:
        retval = prop_map->simulated_cert_expiration_date_after;
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

    case CERTIFIER_OPT_DOMAIN:
        retval = prop_map->domain;
        break;

    case CERTIFIER_OPT_VALIDITY_DAYS:
        retval = (void *) (size_t) prop_map->validity_days; // TODO - need to revisit these casts
        break;

    case CERTIFIER_OPT_AUTORENEW_INTERVAL:
        retval = (void *) (size_t) prop_map->autorenew_interval; // TODO - need to revisit these casts
        break;

    case CERTIFIER_OPT_CERT_MIN_TIME_LEFT_S:
        retval = (void *) (size_t) prop_map->cert_min_time_left_s; // TODO - need to revisit these casts
        break;

    case CERTIFIER_OPT_EXT_KEY_USAGE:
        retval = prop_map->ext_key_usage_value;
        break;

    case CERTIFIER_OPT_AUTORENEW_CERTS_PATH_LIST:
        retval = prop_map->autorenew_certs_path_list;
        break;

    case CERTIFIER_OPT_LOG_FUNCTION:
        /* Write-only value */
        retval = NULL;
        break;

    case CERTIFIER_OPT_MTLS_P12_PATH:
        retval = prop_map->mtls_filename;
        break;

    case CERTIFIER_OPT_MTLS_P12_PASSWORD:
        retval = prop_map->mtls_p12_filename;
        break;

    case CERTIFIER_OPT_DEBUG_HTTP:
    case CERTIFIER_OPT_TRACE_HTTP:
    case CERTIFIER_OPT_FORCE_REGISTRATION:
    case CERTIFIER_OPT_MEASURE_PERFORMANCE:
    case CERTIFIER_OPT_CERTIFICATE_LITE: {
        unsigned int bit = name - CERTIFIER_OPT_BOOL_FIRST;

        CERTIFIER_OPT_OPTION option = 1U << bit;
        retval                      = (void *) property_is_option_set(prop_map, option);
        break;
    }

    case CERTIFIER_OPT_USE_SCOPES: {
        unsigned int bit = name - CERTIFIER_OPT_BOOL_FIRST;

        CERTIFIER_OPT_OPTION option = 1U << bit;
        retval                      = (void *) property_is_option_set(prop_map, option);
        break;
    }

    case CERTIFIER_OPT_SECTIGO_AUTH_TOKEN:
        retval = (void *) prop_map->sectigo_auth_token;
        break;
    case CERTIFIER_OPT_SECTIGO_COMMON_NAME:
        retval = (void *) prop_map->sectigo_common_name;
        break;
    case CERTIFIER_OPT_SECTIGO_GROUP_NAME:
        retval = (void *) prop_map->sectigo_group_name;
        break;
    case CERTIFIER_OPT_SECTIGO_GROUP_EMAIL:
        retval = (void *) prop_map->sectigo_group_email;
        break;
    case CERTIFIER_OPT_SECTIGO_ID:
        retval = (void *) prop_map->sectigo_id;
        break;
    case CERTIFIER_OPT_SECTIGO_OWNER_FNAME:
        retval = (void *) prop_map->sectigo_owner_fname;
        break;
    case CERTIFIER_OPT_SECTIGO_OWNER_LNAME:
        retval = (void *) prop_map->sectigo_owner_lname;
        break;
    case CERTIFIER_OPT_SECTIGO_EMPLOYEE_TYPE:
        retval = (void *) prop_map->sectigo_employee_type;
        break;
    case CERTIFIER_OPT_SECTIGO_SERVER_PLATFORM:
        retval = (void *) prop_map->sectigo_server_platform;
        break;
    case CERTIFIER_OPT_SECTIGO_SENSITIVE:
        retval = (void *)(size_t) prop_map->sectigo_sensitive;
        break;
    case CERTIFIER_OPT_SECTIGO_PROJECT_NAME:
        retval = (void *) prop_map->sectigo_project_name;
        break;
    case CERTIFIER_OPT_SECTIGO_BUSINESS_JUSTIFICATION:
        retval = (void *) prop_map->sectigo_business_justification;
        break;
    case CERTIFIER_OPT_SECTIGO_SUBJECT_ALT_NAMES:
        retval = (void *) prop_map->sectigo_subject_alt_names;
        break;
    case CERTIFIER_OPT_SECTIGO_IP_ADDRESSES:
        retval = (void *) prop_map->sectigo_ip_addresses;
        break;
    case CERTIFIER_OPT_SECTIGO_OWNER_PHONENUM:
        retval = (void *) prop_map->sectigo_owner_phonenum;
        break;
    case CERTIFIER_OPT_SECTIGO_OWNER_EMAIL:
        retval = (void *) prop_map->sectigo_owner_email;
        break;
    case CERTIFIER_OPT_SECTIGO_CERT_TYPE:
        retval = (void *) prop_map->sectigo_cert_type;
        break;
    case CERTIFIER_OPT_SECTIGO_TRACKING_ID:
        retval = (void *) prop_map->sectigo_tracking_id;
        break;
    case CERTIFIER_OPT_SECTIGO_SOURCE:
        retval = (void *) prop_map->sectigo_source;
        break;
    case CERTIFIER_OPT_SECTIGO_CERTIFIER_URL:
        retval = (void *) prop_map->sectigo_url;
        break;

    default:
        log_warn("property_get: unrecognized property [%d]", name);
        retval = NULL;
        break;
    }

    return retval;
} /* property_get */

int property_set_defaults(CertifierPropMap * prop_map)
{
    int return_code = 0;
    char * trace_id = NULL;

    // generate tracking ID
    trace_id = util_generate_random_value(16, ALLOWABLE_CHARACTERS);
    if (trace_id)
    {
        return_code = property_set(prop_map, CERTIFIER_OPT_TRACKING_ID, trace_id);
        XFREE(trace_id);
        if (return_code != 0)
        {
            return return_code;
        }
    }

    if (prop_map->cfg_filename == NULL)
    {
        const char * default_cfg_filename = get_default_cfg_filename();
        return_code                       = property_set(prop_map, CERTIFIER_OPT_CFG_FILENAME, default_cfg_filename);
        if (return_code != 0)
        {
            log_error("Failed to set default property name: CERTIFIER_OPT_CFG_FILENAME with error code: %i", return_code);
            return return_code;
        }
    }

    if (prop_map->auth_type == NULL)
    {
        return_code = property_set(prop_map, CERTIFIER_OPT_AUTH_TYPE, DEFAULT_AUTH_TYPE);
        if (return_code != 0)
        {
            log_error("Failed to set default property name: CERTIFIER_OPT_AUTH_TYPE with error code: %i", return_code);
            return return_code;
        }
    }

    if (prop_map->certifier_url == NULL)
    {
        return_code = property_set(prop_map, CERTIFIER_OPT_CERTIFIER_URL, DEFAULT_CERTIFIER_URL);
        if (return_code != 0)
        {
            log_error("Failed to set default property name: CERTIFIER_OPT_CERTIFIER_URL with error code: %i", return_code);
            return return_code;
        }
    }

    if (prop_map->profile_name == NULL)
    {
        return_code = property_set(prop_map, CERTIFIER_OPT_PROFILE_NAME, DEFAULT_PROFILE_NAME);
        if (return_code != 0)
        {
            log_error("Failed to set default property name: CERTIFIER_OPT_PROFILE_NAME with error code: %i", return_code);
            return return_code;
        }
    }

    if (prop_map->product_id == NULL)
    {
        return_code = property_set(prop_map, CERTIFIER_OPT_PRODUCT_ID, DEFAULT_PRODUCT_ID);
        if (return_code != 0)
        {
            log_error("Failed to set default property name: CERTIFIER_OPT_PRODUCT_ID with error code: %i", return_code);
            return return_code;
        }
    }

    return_code = property_set(prop_map, CERTIFIER_OPT_HTTP_TIMEOUT, (void *) DEFAULT_HTTP_TIMEOUT);
    if (return_code != 0)
    {
        log_error("Failed to set default property name: CERTIFIER_OPT_HTTP_TIMEOUT with error code: %i", return_code);
    }

    return_code = property_set(prop_map, CERTIFIER_OPT_HTTP_CONNECT_TIMEOUT, (void *) DEFAULT_HTTP_CONNECT_TIMEOUT);
    if (return_code != 0)
    {
        log_error("Failed to set default property name: CERTIFIER_OPT_HTTP_CONNECT_TIMEOUT with error code: %i", return_code);
        return return_code;
    }

    if (prop_map->ca_info == NULL)
    {
        const char * default_ca_info = get_default_ca_info();
        return_code                  = property_set(prop_map, CERTIFIER_OPT_CA_INFO, default_ca_info);
        if (return_code != 0)
        {
            log_error("Failed to set default property name: CERTIFIER_OPT_CA_INFO with error code: %i", return_code);
            return return_code;
        }
    }

    if (prop_map->ca_path == NULL)
    {
        const char * default_ca_path = get_default_ca_path();
        return_code                  = property_set(prop_map, CERTIFIER_OPT_CA_PATH, default_ca_path);
        if (return_code != 0)
        {
            log_error("Failed to set default property name: CERTIFIER_OPT_CA_PATH with error code: %i", return_code);
        }
    }

    if (prop_map->ecc_curve_id == NULL)
    {
        return_code = property_set(prop_map, CERTIFIER_OPT_ECC_CURVE_ID, DEFAULT_ECC_CURVE_ID);
        if (return_code != 0)
        {
            log_error("Failed to set default property name: CERTIFIER_OPT_ECC_CURVE_ID with error code: %i", return_code);
            return return_code;
        }
    }

    return_code = property_set(prop_map, CERTIFIER_OPT_LOG_LEVEL, (void *) DEFAULT_LOG_LEVEL);
    if (return_code != 0)
    {
        log_error("Failed to set default property name: CERTIFIER_OPT_LOG_LEVEL with error code: %i", return_code);
        return return_code;
    }

    return_code = property_set(prop_map, CERTIFIER_OPT_LOG_MAX_SIZE, (void *) (size_t) DEFAULT_LOG_MAX_SIZE);
    if (return_code != 0)
    {
        log_error("Failed to set default property name: CERTIFIER_OPT_LOG_MAX_SIZE with error code: %i", return_code);
        return return_code;
    }
    log_set_max_size(prop_map->log_max_size);

    prop_map->cert_min_time_left_s = DEFAULT_CERT_MIN_TIME_LEFT_S;

    return_code = property_set(prop_map, CERTIFIER_OPT_SOURCE, DEFAULT_OPT_SOURCE);
    if (return_code != 0)
    {
        log_error("Failed to set default property name: CERTIFIER_OPT_SOURCE with error code: %i", return_code);
        return return_code;
    }

    if (prop_map->output_p12_filename == NULL)
    {
        return_code = property_set(prop_map, CERTIFIER_OPT_OUTPUT_P12_PATH, DEFAULT_OUTPUT_P12_PATH);
        if (return_code != 0)
        {
            log_error("Failed to set default property name: CERTIFIER_OPT_OUTPUT_P12_PATH with error code: %i", return_code);
            return return_code;
        }
    }

    return_code = property_set(prop_map, CERTIFIER_OPT_AUTORENEW_INTERVAL, (void *) DEFAULT_AUTORENEW_INTERVAL);
    if (return_code != 0)
    {
        log_error("Failed to set default property name: CERTIFIER_OPT_AUTORENEW_INTERVAL with error code: %i", return_code);
        return return_code;
    }

    if (prop_map->autorenew_certs_path_list == NULL)
    {
        return_code = property_set(prop_map, CERTIFIER_OPT_AUTORENEW_CERTS_PATH_LIST, DEFAULT_AUTORENEW_CERTS_PATH);
        if (return_code != 0)
        {
            log_error("Failed to set default property name: CERTIFIER_OPT_AUTORENEW_CERTS_PATH_LIST with error code: %i",
                      return_code);
            return return_code;
        }
    }

    return return_code;
}

int property_set_sectigo_defaults_from_cfg_file(CertifierPropMap * propMap)
{
    JSON_Value *json;
    int ret = 0;
    char *file_contents = NULL;
    size_t file_contents_len = 0;

    log_info("Loading Sectigo cfg file: %s", propMap->cfg_filename);

    ret = util_slurp(propMap->cfg_filename, &file_contents, &file_contents_len);
    if (ret != 0) {
        log_error("Failed to read config file: %s", propMap->cfg_filename);
        if (file_contents) XFREE(file_contents);
        return 1;
    }

    file_contents[file_contents_len] = '\0';
    json = json_parse_string_with_comments(file_contents);
    XFREE(file_contents);
    if (!json) {
        log_error("Failed to parse JSON config file: %s", propMap->cfg_filename);
        return 1;
    }

    JSON_Object *root = json_object(json);
    size_t count = json_object_get_count(root);
    for (size_t i = 0; i < count; ++i) {
        const char *key = json_object_get_name(root, i);

        // Only process keys starting with "libcertifier.sectigo."
        if (strncmp(key, "libcertifier.sectigo.", strlen("libcertifier.sectigo.")) != 0) {
            continue;
        }

        

    // Handle boolean for sensitive
    if (strcmp(key, "libcertifier.sectigo.sensitive") == 0) {
        int bool_val = json_object_get_boolean(root, key);
        propMap->sectigo_sensitive = (bool)bool_val;
        continue;
    }

    // Handle arrays for subject alt names and ip addresses
    if (strcmp(key, "libcertifier.sectigo.subject.alt.names") == 0) {
    const char *array_str = json_object_get_string(root, key);
    char *csv = NULL;
    if (array_str) {
        csv = simple_json_array_to_csv(array_str);
    } else {
        csv = XSTRDUP(""); // Always set to empty string if missing/empty
    }
    sectigo_property_set(propMap, CERTIFIER_OPT_SECTIGO_SUBJECT_ALT_NAMES, csv);
    XFREE(csv);
    continue;
}
if (strcmp(key, "libcertifier.sectigo.ip.addresses") == 0) {
    const char *array_str = json_object_get_string(root, key);
    char *csv = NULL;
    if (array_str) {
        csv = simple_json_array_to_csv(array_str);
    } else {
        csv = XSTRDUP("");
    }
    sectigo_property_set(propMap, CERTIFIER_OPT_SECTIGO_IP_ADDRESSES, csv);
    XFREE(csv);
    continue;
}

        const char *value_str = json_object_get_string(root, key);
        if (value_str) {
            // Map config key to property enum
            if (strcmp(key, "libcertifier.sectigo.auth.token") == 0)
                sectigo_property_set(propMap, CERTIFIER_OPT_SECTIGO_AUTH_TOKEN, value_str);
            else if (strcmp(key, "libcertifier.sectigo.common.name") == 0)
                sectigo_property_set(propMap, CERTIFIER_OPT_SECTIGO_COMMON_NAME, value_str);
            else if (strcmp(key, "libcertifier.sectigo.group.name") == 0)
                sectigo_property_set(propMap, CERTIFIER_OPT_SECTIGO_GROUP_NAME, value_str);
            else if (strcmp(key, "libcertifier.sectigo.group.email") == 0)
                sectigo_property_set(propMap, CERTIFIER_OPT_SECTIGO_GROUP_EMAIL, value_str);
            else if (strcmp(key, "libcertifier.sectigo.id") == 0)
                sectigo_property_set(propMap, CERTIFIER_OPT_SECTIGO_ID, value_str);
            else if (strcmp(key, "libcertifier.sectigo.owner.fname") == 0)
                sectigo_property_set(propMap, CERTIFIER_OPT_SECTIGO_OWNER_FNAME, value_str);
            else if (strcmp(key, "libcertifier.sectigo.owner.lname") == 0)
                sectigo_property_set(propMap, CERTIFIER_OPT_SECTIGO_OWNER_LNAME, value_str);
            else if (strcmp(key, "libcertifier.sectigo.employee.type") == 0)
                sectigo_property_set(propMap, CERTIFIER_OPT_SECTIGO_EMPLOYEE_TYPE, value_str);
            else if (strcmp(key, "libcertifier.sectigo.server.platform") == 0)
                sectigo_property_set(propMap, CERTIFIER_OPT_SECTIGO_SERVER_PLATFORM, value_str);
            else if (strcmp(key, "libcertifier.sectigo.project.name") == 0)
                sectigo_property_set(propMap, CERTIFIER_OPT_SECTIGO_PROJECT_NAME, value_str);
            else if (strcmp(key, "libcertifier.sectigo.business.justification") == 0)
                sectigo_property_set(propMap, CERTIFIER_OPT_SECTIGO_BUSINESS_JUSTIFICATION, value_str);
            else if (strcmp(key, "libcertifier.sectigo.owner.phonenum") == 0)
                sectigo_property_set(propMap, CERTIFIER_OPT_SECTIGO_OWNER_PHONENUM, value_str);
            else if (strcmp(key, "libcertifier.sectigo.owner.email") == 0)
                sectigo_property_set(propMap, CERTIFIER_OPT_SECTIGO_OWNER_EMAIL, value_str);
            else if (strcmp(key, "libcertifier.sectigo.cert.type") == 0)
                sectigo_property_set(propMap, CERTIFIER_OPT_SECTIGO_CERT_TYPE, value_str);
            else if (strcmp(key, "libcertifier.sectigo.certifier.url") == 0)
                sectigo_property_set(propMap, CERTIFIER_OPT_SECTIGO_CERTIFIER_URL, value_str);
            else if (strcmp(key, "libcertifier.sectigo.tracking.id") == 0)
                sectigo_property_set(propMap, CERTIFIER_OPT_SECTIGO_TRACKING_ID, value_str);
            else if (strcmp(key, "libcertifier.sectigo.source") == 0)
                sectigo_property_set(propMap, CERTIFIER_OPT_SECTIGO_SOURCE, value_str);
            // Add more mappings as needed
        }
    }

    if (json) json_value_free(json);
    return 0;
}


int property_set_ext(CertifierPropMap * prop_map)
{
    JSON_Value * json;
    const char * ext_key_usage_value = NULL;
    int ret                          = 0;

    char * file_contents     = NULL;
    size_t file_contents_len = 0;

    const char * default_cfg_filename = get_default_cfg_filename();
    ret                               = util_slurp(default_cfg_filename, &file_contents, &file_contents_len);
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
        file_contents[file_contents_len] = '\0';
        json                             = json_parse_string_with_comments(file_contents);
        XFREE(file_contents);
        if (json == NULL)
        {
            log_error("json_parse_string_with_comments returned a NULL value.  Perhaps JSON malformed?  Received error code: <%i>",
                      ret);
            return 1;
        }
    }

    ext_key_usage_value = json_object_get_string(json_object(json), "libcertifier.ext.key.usage");
    if (ext_key_usage_value)
    {
        // log_info("Loaded Extended Key Usage Values: %s", ext_key_usage_value);
        property_set(prop_map, CERTIFIER_OPT_EXT_KEY_USAGE, ext_key_usage_value);
    }

    if (json)
    {
        json_value_free(json);
    }

    return 0;
}

int property_set_defaults_from_cfg_file(CertifierPropMap * propMap)
{

    JSON_Value * json;

    const char * certifier_url_value = NULL;
    const char * profile_name_value  = NULL;
    const char * auth_type_value     = NULL;
    const char * password_value      = NULL;
    const char * system_id_value     = NULL;
    const char * fabric_id_value     = NULL;
    const char * node_id_value       = NULL;
    const char * product_id_value    = NULL;
    const char * auth_tag_1_value    = NULL;
    int http_timeout_value;
    int http_connect_timeout_value;
    int http_trace_value;
    const char * input_p12_path_value = NULL;
    const char * sat_token_value      = NULL;
    const char * ca_info_value        = NULL;
    const char * ca_path_value        = NULL;
    const char * ecc_curve_id_value   = NULL;
    const char * log_file_value       = NULL;
    int log_level_value;
    int log_max_size_value;
    int measure_performance_value;
    int autorenew_interval_value;
    int validity_days;
    const char * source = NULL;
    int certificate_lite_value;
    int certificate_scopes_value;
    const char * cn_prefix                       = NULL;
    const char * ext_key_usage_value             = NULL;
    const char * autorenew_certs_path_list_value = NULL;
    const char * mtls_p12_path_value             = NULL;
    const char * mtls_password_value             = NULL;

    int ret = 0;

    char * file_contents     = NULL;
    size_t file_contents_len = 0;

    log_info("Loading cfg file: %s", propMap->cfg_filename);

    log_debug("About to call: util_slurp with path: %s", propMap->cfg_filename);
    ret = util_slurp(propMap->cfg_filename, &file_contents, &file_contents_len);
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
        file_contents[file_contents_len] = '\0';
        json                             = json_parse_string_with_comments(file_contents);
        XFREE(file_contents);
        if (json == NULL)
        {
            log_error("json_parse_string_with_comments returned a NULL value.  Perhaps JSON malformed? Received error code: <%i>",
                      ret);
            return 1;
        }
    }

    certifier_url_value = json_object_get_string(json_object(json), "libcertifier.certifier.url");
    if (certifier_url_value)
    {
        log_info("Loaded certifier url: %s from config file.", certifier_url_value);
        property_set(propMap, CERTIFIER_OPT_CERTIFIER_URL, certifier_url_value);
    }

    profile_name_value = json_object_get_string(json_object(json), "libcertifier.profile.name");
    if (profile_name_value)
    {
        log_info("Loaded profile name: %s from config file.", profile_name_value);
        property_set(propMap, CERTIFIER_OPT_PROFILE_NAME, profile_name_value);
    }

    auth_type_value = json_object_get_string(json_object(json), "libcertifier.auth.type");
    if (auth_type_value)
    {
        log_info("Loaded crt.type: %s from config file.", auth_type_value);
        property_set(propMap, CERTIFIER_OPT_AUTH_TYPE, auth_type_value);
    }

    password_value = json_object_get_string(json_object(json), "libcertifier.input.p12.password");
    if (password_value)
    {
        print_warning("password");
        log_info("Loaded password from config file.");
        property_set(propMap, CERTIFIER_OPT_INPUT_P12_PASSWORD, password_value);
    }

    system_id_value = json_object_get_string(json_object(json), "libcertifier.system.id");
    if (system_id_value)
    {
        log_info("Loaded system_id_value: %s from config file.", system_id_value);
        property_set(propMap, CERTIFIER_OPT_SYSTEM_ID, system_id_value);
    }

    fabric_id_value = json_object_get_string(json_object(json), "libcertifier.fabric.id");
    if (fabric_id_value)
    {
        log_info("Loaded fabric_id_value: %s from config file.", fabric_id_value);
        property_set(propMap, CERTIFIER_OPT_FABRIC_ID, fabric_id_value);
    }

    node_id_value = json_object_get_string(json_object(json), "libcertifier.node.id");
    if (node_id_value)
    {
        log_info("Loaded node_id_value: %s from config file.", node_id_value);
        property_set(propMap, CERTIFIER_OPT_NODE_ID, node_id_value);
    }

    product_id_value = json_object_get_string(json_object(json), "libcertifier.product.id");
    if (product_id_value)
    {
        log_info("Loaded product_id_value: %s from config file.", product_id_value);
        property_set(propMap, CERTIFIER_OPT_PRODUCT_ID, product_id_value);
    }

    auth_tag_1_value = json_object_get_string(json_object(json), "libcertifier.authentication.tag.1");
    if (auth_tag_1_value)
    {
        log_info("Loaded auth_tag_1_value: %s from config file.", auth_tag_1_value);
        property_set(propMap, CERTIFIER_OPT_AUTH_TAG_1, auth_tag_1_value);
    }

    http_timeout_value = json_object_get_number(json_object(json), "libcertifier.http.timeout");
    if (http_timeout_value >= 0)
    {
        log_info("Loaded http_timeout_value: %i from cfg file.", http_timeout_value);
        property_set(propMap, CERTIFIER_OPT_HTTP_TIMEOUT, (void *) (size_t) http_timeout_value);
    }

    http_connect_timeout_value = json_object_get_number(json_object(json), "libcertifier.http.connect.timeout");
    if (http_connect_timeout_value >= 0)
    {
        log_info("Loaded http_connect_timeout_value: %i from cfg file.", http_connect_timeout_value);
        property_set(propMap, CERTIFIER_OPT_HTTP_CONNECT_TIMEOUT, (void *) (size_t) http_connect_timeout_value);
    }

    http_trace_value = json_object_get_number(json_object(json), "libcertifier.http.trace");
    if (http_trace_value == 1)
    {
        log_info("Loaded http_trace_value: %i from cfg file.", http_trace_value);
        print_warning("http.trace");
        propMap->options |= (CERTIFIER_OPTION_TRACE_HTTP | CERTIFIER_OPTION_DEBUG_HTTP);
    }

    measure_performance_value = json_object_get_number(json_object(json), "libcertifier.measure.performance");
    if (measure_performance_value == 1)
    {
        log_info("Loaded measure.performance: %i from cfg file.", measure_performance_value);
        propMap->options |= CERTIFIER_OPTION_MEASURE_PERFORMANCE;
    }

    autorenew_interval_value = json_object_get_number(json_object(json), "libcertifier.autorenew.interval");
    if (autorenew_interval_value == 1)
    {
        log_info("Loaded autorenew.interval: %i from cfg file.", autorenew_interval_value);
        property_set(propMap, CERTIFIER_OPT_AUTORENEW_INTERVAL, (void *) (size_t) autorenew_interval_value);
    }

    input_p12_path_value = json_object_get_string(json_object(json), "libcertifier.input.p12.path");
    if (input_p12_path_value)
    {
        log_info("Loaded input_p12_path_value: %s from cfg file.", input_p12_path_value);
        property_set(propMap, CERTIFIER_OPT_INPUT_P12_PATH, input_p12_path_value);
    }

    sat_token_value = json_object_get_string(json_object(json), "libcertifier.sat.token");
    if (sat_token_value)
    {
        log_info("Loaded sat_token_value: %s from cfg file.", sat_token_value);
        property_set(propMap, CERTIFIER_OPT_AUTH_TOKEN, sat_token_value);
    }

    ca_info_value = json_object_get_string(json_object(json), "libcertifier.ca.info");
    if (ca_info_value)
    {
        log_info("Loaded ca_info_value: %s from cfg file.", ca_info_value);
        property_set(propMap, CERTIFIER_OPT_CA_INFO, ca_info_value);
    }

    ca_path_value = json_object_get_string(json_object(json), "libcertifier.ca.path");
    if (ca_path_value)
    {
        log_info("Loaded ca_path_value: %s from cfg file.", ca_path_value);
        property_set(propMap, CERTIFIER_OPT_CA_PATH, ca_path_value);
    }

    validity_days = json_object_get_number(json_object(json), "libcertifier.validity.days");
    if (validity_days)
    {
        log_info("Loaded validity_days: %d", validity_days);
        property_set(propMap, CERTIFIER_OPT_VALIDITY_DAYS, (void *) (size_t) validity_days);
    }

    ecc_curve_id_value = json_object_get_string(json_object(json), "libcertifier.ecc.curve.id");
    if (ecc_curve_id_value)
    {
        log_info("Loaded ecc_curve_id_value: %s from cfg file.", ecc_curve_id_value);
        property_set(propMap, CERTIFIER_OPT_ECC_CURVE_ID, ecc_curve_id_value);
    }

    log_file_value = json_object_get_string(json_object(json), "libcertifier.log.file");
    if (log_file_value)
    {
        log_info("Loaded Log File Value: %s from cfg file.", log_file_value);
        property_set(propMap, CERTIFIER_OPT_LOG_FILENAME, log_file_value);
    }

    log_level_value = json_object_get_number(json_object(json), "libcertifier.log.level");
    if (log_level_value >= 0)
    {
        log_info("Loaded Log Level value: %i from cfg file.", log_level_value);
        property_set(propMap, CERTIFIER_OPT_LOG_LEVEL, (void *) (size_t) (log_level_value));
    }

    log_max_size_value = json_object_get_number(json_object(json), "libcertifier.log.max.size");
    if (log_max_size_value >= 0)
    {
        log_info("Loaded Log Max Size value: %i from cfg file.", log_max_size_value);
        property_set(propMap, CERTIFIER_OPT_LOG_MAX_SIZE, (void *) (size_t) (log_max_size_value));
    }
    log_set_max_size(propMap->log_max_size);

    source = json_object_get_string(json_object(json), "libcertifier.source.id");
    if (source)
    {
        log_info("Loaded source.id %s from cfg file.", source);
        property_set(propMap, CERTIFIER_OPT_SOURCE, source);
    }

    certificate_lite_value = json_object_get_number(json_object(json), "libcertifier.certificate.lite");
    if (certificate_lite_value == 1)
    {
        log_info("Loaded certificate.lite: %i from cfg file.", certificate_lite_value);
        print_warning("certificate.lite");
        propMap->options |= (CERTIFIER_OPTION_CERTIFICATE_LITE);
    }
    certificate_scopes_value = json_object_get_number(json_object(json), "libcertifier.certificate.scopes");
    if (certificate_scopes_value == 1)
    {
        log_info("Loaded certificate.scopes: %i from cfg file.", certificate_scopes_value);
        print_warning("certificate.scopes");
        propMap->options |= (CERTIFIER_OPTION_USE_SCOPES);
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

    autorenew_certs_path_list_value = json_object_get_string(json_object(json), "libcertifier.autorenew.certs.path.list");
    if (autorenew_certs_path_list_value)
    {
        log_info("Loaded autorenew certs path: %s from config file.", autorenew_certs_path_list_value);
        property_set(propMap, CERTIFIER_OPT_AUTORENEW_CERTS_PATH_LIST, autorenew_certs_path_list_value);
    }

    mtls_p12_path_value = json_object_get_string(json_object(json), "libcertifier.mtls.p12.path");
    if (mtls_p12_path_value)
    {
        log_info("Loaded mtls_p12_path_value: %s from cfg file.", mtls_p12_path_value);
        property_set(propMap, CERTIFIER_OPT_MTLS_P12_PATH, mtls_p12_path_value);
    }

    mtls_password_value = json_object_get_string(json_object(json), "libcertifier.mtls.p12.password");
    if (mtls_password_value)
    {
        print_warning("password");
        log_info("Loaded mTLS password from config file.");
        property_set(propMap, CERTIFIER_OPT_MTLS_P12_PASSWORD, mtls_password_value);
    }

    if (json)
    {
        json_value_free(json);
    }

    return 0;
}

#define FV(field)                                                                                                                  \
    if (field != NULL)                                                                                                             \
    {                                                                                                                              \
        XFREE(field);                                                                                                              \
    }

static void free_prop_map_values(CertifierPropMap * prop_map)
{
    // free the values
    FV(prop_map->log_file);
    FV(prop_map->ca_info);
    FV(prop_map->ca_path);
    FV(prop_map->certifier_url);
    FV(prop_map->auth_type);
    FV(prop_map->cfg_filename);
    FV(prop_map->p12_filename);
    FV(prop_map->output_p12_filename);
    FV(prop_map->password);
    FV(prop_map->password_out);
    FV(prop_map->certifier_id);
    FV(prop_map->system_id);
    FV(prop_map->fabric_id);
    FV(prop_map->node_id);
    FV(prop_map->product_id);
    FV(prop_map->auth_tag_1);
    FV(prop_map->mac_address);
    FV(prop_map->dns_san);
    FV(prop_map->ip_san);
    FV(prop_map->email_san);
    FV(prop_map->crt);
    FV(prop_map->profile_name);
    FV(prop_map->ecc_curve_id);
    FV(prop_map->simulated_cert_expiration_date_after);
    FV(prop_map->simulated_cert_expiration_date_before);
    FV(prop_map->auth_token);
    FV(prop_map->output_node);
    FV(prop_map->target_node);
    FV(prop_map->action);
    FV(prop_map->input_node);
    FV(prop_map->autorenew_certs_path_list);
    FV(prop_map->tracking_id);
    FV(prop_map->source);
    FV(prop_map->cn_prefix);
    FV(prop_map->domain);
    FV(prop_map->ext_key_usage_value);
    security_free_cert(prop_map->cert_x509_out);
    FV(prop_map->mtls_filename);
    FV(prop_map->mtls_p12_filename);
    FV(prop_map->sectigo_auth_token);
    FV(prop_map->sectigo_common_name);
    FV(prop_map->sectigo_group_name);
    FV(prop_map->sectigo_group_email);
    FV(prop_map->sectigo_id);
    FV(prop_map->sectigo_owner_fname);
    FV(prop_map->sectigo_owner_lname);
    FV(prop_map->sectigo_employee_type);
    FV(prop_map->sectigo_server_platform);
    FV(prop_map->sectigo_project_name);
    FV(prop_map->sectigo_business_justification);
    FV(prop_map->sectigo_subject_alt_names);
    FV(prop_map->sectigo_ip_addresses);
    FV(prop_map->sectigo_owner_phonenum);
    FV(prop_map->sectigo_owner_email);
    FV(prop_map->sectigo_cert_type);
    FV(prop_map->sectigo_tracking_id);
    FV(prop_map->sectigo_source);
    FV(prop_map->sectigo_url);
}

CertifierPropMap * property_new_sectigo(void)
{
    CertifierPropMap * prop_map = XCALLOC(1, sizeof(CertifierPropMap));
    if (prop_map == NULL)
    {
        log_error("Could not initialize CertifierPropMap.");
        return NULL;
    }
    
    return prop_map;
}
