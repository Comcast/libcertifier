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

#include "certifier/sectigo_client.h"
#include <certifier/base64.h>
#include <certifier/certifier.h>
#include "certifier/code_utils.h"
#include "certifier/types.h"
#include "certifier/certifierclient.h"
#include "certifier/certifier_internal.h"
#include "certifier/http.h"
#include "certifier/log.h"
#include "certifier/parson.h"
#include "certifier/util.h"
#include "certifier/error.h"
#include "certifier/property_internal.h"


#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <curl/curl.h>

#include <errno.h>
#include <stdbool.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

Certifier * get_sectigo_certifier_instance()
{
    static Certifier * certifier = NULL;

    if (certifier == NULL)
    {
        certifier = certifier_new();
        certifier->sectigo_mode = true;
        certifier_set_property(certifier, CERTIFIER_OPT_LOG_LEVEL, (void *) (size_t) 0);
        
        // Load Sectigo config file if it exists
        const char *cfg_filename = certifier_get_property(certifier, CERTIFIER_OPT_CFG_FILENAME);
        if (cfg_filename && access(cfg_filename, F_OK) == 0) {
            sectigo_load_cfg_file(certifier);
        }
    }
    return certifier;
}

static void append_query_param(char *url, size_t url_size, const char *key, const char *value, int *first_param)
{
    if (!value || strlen(value) == 0) {
        return;
    }
    
    size_t current_len = strlen(url);
    snprintf(url + current_len, url_size - current_len,
             "%s%s=%s", *first_param ? "?" : "&", key, value);
    *first_param = 0;
}

// For numeric parameters
static void append_query_param_num(char *url, size_t url_size, const char *key, size_t value, int *first_param)
{
    if (value == 0) {
        return;
    }
    
    size_t current_len = strlen(url);
    snprintf(url + current_len, url_size - current_len,
             "%s%s=%zu", *first_param ? "?" : "&", key, value);
    *first_param = 0;
}

SECTIGO_CLIENT_ERROR_CODE xc_sectigo_get_default_cert_param(sectigo_get_cert_param_t * params)
{
    Certifier * certifier = get_sectigo_certifier_instance();

    memset(params, 0, sizeof(sectigo_get_cert_param_t));

    void * param = NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_AUTH_TOKEN);
    params->auth_token = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_COMMON_NAME);
    params->common_name = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_GROUP_NAME);
    params->group_name = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_GROUP_EMAIL);
    params->group_email = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_ID);
    params->id = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_OWNER_FIRST_NAME);
    params->owner_first_name = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_OWNER_LAST_NAME);
    params->owner_last_name = param ? XSTRDUP((const char *)param) : NULL;
    
    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_PROJECT_NAME);
    params->project_name = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_BUSINESS_JUSTIFICATION);
    params->business_justification = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_SUBJECT_ALT_NAMES);
    params->subject_alt_names = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_OWNER_EMAIL);
    params->owner_email = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_URL);
    params->sectigo_url = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_DEVHUB_ID);
    params->devhub_id = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_VALIDITY_DAYS);
    params->validity_days = param ? (size_t) param : 365;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_KEY_TYPE);
    params->key_type = param ? XSTRDUP((const char *)param) : NULL;

    return SECTIGO_CLIENT_SUCCESS;
}

SECTIGO_CLIENT_ERROR_CODE xc_sectigo_get_default_renew_cert_param(sectigo_renew_cert_param_t * params)
{
    Certifier * certifier = get_sectigo_certifier_instance();

    memset(params, 0, sizeof(sectigo_renew_cert_param_t));

    void * param = NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_AUTH_TOKEN);
    params->auth_token = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_COMMON_NAME);
    params->common_name = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_SERIAL_NUMBER);
    params->serial_number = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_CERTIFICATE_ID);
    params->certificate_id = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_REQUESTOR_EMAIL);
    params->requestor_email = param ? XSTRDUP((const char *)param) : NULL;

    return SECTIGO_CLIENT_SUCCESS;
}

SECTIGO_CLIENT_ERROR_CODE xc_sectigo_get_default_revoke_cert_param(sectigo_revoke_cert_param_t * params)
{
    Certifier * certifier = get_sectigo_certifier_instance();

    memset(params, 0, sizeof(sectigo_revoke_cert_param_t));

    void * param = NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_AUTH_TOKEN);
    params->auth_token = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_COMMON_NAME);
    params->common_name = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_SERIAL_NUMBER);
    params->serial_number = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_CERTIFICATE_ID);
    params->certificate_id = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_REQUESTOR_EMAIL);
    params->requestor_email = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_REVOCATION_REQUEST_REASON);
    params->revocation_request_reason = param ? XSTRDUP((const char *)param) : NULL;

    return SECTIGO_CLIENT_SUCCESS;
}

CertifierError sectigo_client_request_certificate(CertifierPropMap * props, const unsigned char * csr,
const char * node_address, const char * certifier_id, char ** out_cert)
{
    Certifier *certifier = get_sectigo_certifier_instance();
    CertifierError rc = CERTIFIER_ERROR_INITIALIZER;
    JSON_Value *root_value = NULL;
    JSON_Object *root_obj = NULL;
    char *json_body = NULL;
    
    if (out_cert == NULL)
    {
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg  = util_format_error_here("out cert cannot be null");
        return rc;
    }

    char auth_header[VERY_LARGE_STRING_SIZE * 4] = "";
    char tracking_header[LARGE_STRING_SIZE]      = "";
    char source_header[SMALL_STRING_SIZE]        = "";
    JSON_Object * parsed_json_object_value       = NULL;
    JSON_Value * parsed_json_root_value          = NULL;
    char * serialized_string                     = NULL;
    http_response * resp                         = NULL;
    const char * tracking_id                     = property_get(props, CERTIFIER_OPT_TRACKING_ID);
    const char * bearer_token                    = property_get(props, CERTIFIER_OPT_SECTIGO_AUTH_TOKEN);
    const char * source                          = "libcertifier";
    const char * sectigo_base_url                = property_get(props, CERTIFIER_OPT_SECTIGO_URL);

    if (!bearer_token) {
        log_error("Missing CERTIFIER_OPT_SECTIGO_AUTH_TOKEN");
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg  = util_format_error_here("Bearer token is missing");
        goto cleanup;
    }
    if (!sectigo_base_url) {
        log_error("Missing CERTIFIER_OPT_SECTIGO_URL");
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg  = util_format_error_here("Sectigo base URL is missing");
        goto cleanup;
    }

    // Build full URL: base + endpoint
    char sectigo_create_cert_url[256];
    char create_cert_endpoint[] = "/api/createCertificate";
    strncpy(sectigo_create_cert_url, sectigo_base_url, sizeof(sectigo_create_cert_url) - 1);
    strncpy(sectigo_create_cert_url + strlen(sectigo_base_url), create_cert_endpoint,
            sizeof(sectigo_create_cert_url) - 1 - strlen(sectigo_base_url));

    log_debug("Tracking ID is: %s\n", tracking_id);
    log_debug("Sectigo URL: %s\n", sectigo_create_cert_url);

    if (bearer_token != NULL) {
    snprintf(auth_header, sizeof(auth_header), "Authorization: %s", bearer_token);
    }
    snprintf(tracking_header, sizeof(tracking_header), "x-xpki-request-id: %s", tracking_id);
    snprintf(source_header, sizeof(source_header), "x-xpki-source: %s", source);

    const char *headers[] = {
        "Accept: */*",
        "Connection: keep-alive",
        "cache-control: no-cache",
        "Content-Type: application/json",
        source_header,
        tracking_header,
        "x-xpki-partner-id: comcast",
        auth_header,
        NULL
    };

    CertifierError csr_rc = sectigo_generate_certificate_signing_request(certifier, &serialized_string);
    
    if (csr_rc.application_error_code != 0 || serialized_string == NULL) {
        rc.application_error_code = csr_rc.application_error_code;
        rc.application_error_msg = csr_rc.application_error_msg;
        goto cleanup;
    }

    // Take Mutex
    if (pthread_mutex_lock(&lock) != 0)
    {
        rc.application_error_code = 17;
        rc.application_error_msg = "sectigo_client_request_certificate: pthread_mutex_lock failed";
        goto cleanup;
    }
    // Give Mutex
    if (pthread_mutex_unlock(&lock) != 0)
    {
        rc.application_error_code = 18;
        rc.application_error_msg = "sectigo_client_request_certificate: pthread_mutex_unlock failed";
        goto cleanup;
    }

    sectigo_get_cert_param_t params;
    xc_sectigo_get_default_cert_param(&params);

    // Build JSON body
    root_value = json_value_init_object();
    root_obj = json_value_get_object(root_value);

    json_object_set_string(root_obj, "certificateSigningRequest", serialized_string);

    json_object_set_string(root_obj, "commonName", params.common_name ? params.common_name : "");
    json_object_set_string(root_obj, "groupName", params.group_name ? params.group_name : "");
    json_object_set_string(root_obj, "groupEmailAddress", params.group_email ? params.group_email : "");
    json_object_set_string(root_obj, "id", params.id ? params.id : "");
    json_object_set_string(root_obj, "ownerFirstName", params.owner_first_name ? params.owner_first_name : "");
    json_object_set_string(root_obj, "ownerLastName", params.owner_last_name ? params.owner_last_name : "");
    json_object_set_string(root_obj, "projectName", params.project_name ? params.project_name : "");
    json_object_set_string(root_obj, "businessJustification", params.business_justification ? params.business_justification : "");
    json_object_set_string(root_obj, "certificateType", "comodo");  // Always "comodo"
    json_object_set_string(root_obj, "ownerEmailAddress", params.owner_email ? params.owner_email : "");
    
    // The following parameters are optional. Only include if set
    if (params.devhub_id) {
        json_object_set_string(root_obj, "devhubId", params.devhub_id);
    }
    
    if (params.validity_days > 0) {
        json_object_set_number(root_obj, "validityDays", (double)params.validity_days);
    }
   
    if (params.key_type) {
        json_object_set_string(root_obj, "keyType", params.key_type);
    }

    // subjectAltNames as array
    JSON_Value *san_array = json_value_init_array();
    JSON_Array *san_json_array = json_value_get_array(san_array);
    if (params.subject_alt_names && strlen(params.subject_alt_names) > 0) {
        char *san_copy = XSTRDUP(params.subject_alt_names);
        char *token = strtok(san_copy, ",");
        while (token) {
            json_array_append_value(san_json_array, json_value_init_string(token));
            token = strtok(NULL, ",");
        }
        XFREE(san_copy);
    }
    json_object_set_value(root_obj, "subjectAltNames", san_array);

    json_body = json_serialize_to_string(root_value);

    resp = http_post(props, sectigo_create_cert_url, headers, json_body);
    if (resp == NULL)
    {
        goto cleanup;
    }

    rc.application_error_code = resp->error;

    // Check for errors
    if (resp->error != 0)
    {
        rc.application_error_msg = util_format_curl_error("sectigo_client_request_certificate", resp->http_code, resp->error,
                                                          resp->error_msg, resp->payload, __FILE__, __LINE__);
        goto cleanup;
    }

    if (resp->payload == NULL)
    {
        log_error("ERROR: Failed to populate payload");
        goto cleanup;
    }

    parsed_json_root_value = json_parse_string_with_comments(resp->payload);
    if (json_value_get_type(parsed_json_root_value) != JSONObject)
    {
        rc.application_error_msg =
            util_format_curl_error("sectigo_client_request_certificate", resp->http_code, resp->error,
                                   "Could not parse JSON.  Expected it to be an array.", resp->payload, __FILE__, __LINE__);
        goto cleanup;
    }

    parsed_json_object_value = json_value_get_object(parsed_json_root_value);

    if (parsed_json_object_value == NULL)
    {
        rc.application_error_msg =
            util_format_curl_error("sectigo_client_request_certificate", resp->http_code, resp->error,
                                   "Could not parse JSON.  parsed_json_object_value is NULL!.", resp->payload, __FILE__, __LINE__);
        goto cleanup;
    }

cleanup:
    http_free_response(resp);

    if (parsed_json_root_value) json_value_free(parsed_json_root_value);

    XFREE(serialized_string);

    if (json_body) json_free_serialized_string(json_body);
    if (root_value) json_value_free(root_value);
    
    return rc;
}

CertifierError sectigo_client_search_certificates(CertifierPropMap * props)
{
    CertifierError rc = CERTIFIER_ERROR_INITIALIZER;

    char auth_header[VERY_LARGE_STRING_SIZE * 4] = "";
    char tracking_header[LARGE_STRING_SIZE]      = "";
    char source_header[SMALL_STRING_SIZE]        = "";
    http_response * resp                         = NULL;
    const char * tracking_id                     = property_get(props, CERTIFIER_OPT_TRACKING_ID);
    const char * bearer_token                    = property_get(props, CERTIFIER_OPT_SECTIGO_AUTH_TOKEN);
    const char * source                          = "libcertifier";
    const char * sectigo_base_url                = property_get(props, CERTIFIER_OPT_SECTIGO_URL);

    if (!bearer_token) {
        log_error("Missing CERTIFIER_OPT_SECTIGO_AUTH_TOKEN");
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg  = util_format_error_here("Bearer token is missing");
        goto cleanup;
    }
    if (!sectigo_base_url) {
        log_error("Missing CERTIFIER_OPT_SECTIGO_URL");
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg  = util_format_error_here("Sectigo base URL is missing");
        goto cleanup;
    }

    // Build full URL: base + endpoint
    char sectigo_search_cert_url[256];
    char search_cert_endpoint[] = "/api/getCertificates";
    strncpy(sectigo_search_cert_url, sectigo_base_url, sizeof(sectigo_search_cert_url) - 1);
    strncpy(sectigo_search_cert_url + strlen(sectigo_base_url), search_cert_endpoint,
            sizeof(sectigo_search_cert_url) - 1 - strlen(sectigo_base_url));
    log_debug("Tracking ID is: %s\n", tracking_id);

    if (bearer_token != NULL) {
        snprintf(auth_header, sizeof(auth_header), "Authorization: %s", bearer_token);
    }
    snprintf(tracking_header, sizeof(tracking_header), "x-xpki-request-id: %s", tracking_id);
    snprintf(source_header, sizeof(source_header), "x-xpki-source: %s", source);

    const char *headers[] = {
        "Accept: */*",
        "Connection: keep-alive",
        "cache-control: no-cache",
        "Content-Type: application/json",
        source_header,
        tracking_header,
        "x-xpki-partner-id: comcast",
        auth_header,
        NULL
    };

    // Take Mutex
    if (pthread_mutex_lock(&lock) != 0)
    {
        rc.application_error_code = 17;
        rc.application_error_msg = "sectigo_client_search_certificates: pthread_mutex_lock failed";
        goto cleanup;
    }

    int first_param = 1; // Used to determine whether to prepend '?' or '&' for query parameters
    append_query_param(sectigo_search_cert_url, sizeof(sectigo_search_cert_url), "groupName", property_get(props, CERTIFIER_OPT_SECTIGO_GROUP_NAME), &first_param);
    append_query_param(sectigo_search_cert_url, sizeof(sectigo_search_cert_url), "groupEmailAddress", property_get(props, CERTIFIER_OPT_SECTIGO_GROUP_EMAIL), &first_param);
    append_query_param(sectigo_search_cert_url, sizeof(sectigo_search_cert_url), "status", property_get(props, CERTIFIER_OPT_SECTIGO_STATUS), &first_param);
    append_query_param(sectigo_search_cert_url, sizeof(sectigo_search_cert_url), "commonName", property_get(props, CERTIFIER_OPT_SECTIGO_COMMON_NAME), &first_param);
    append_query_param(sectigo_search_cert_url, sizeof(sectigo_search_cert_url), "offset", property_get(props, CERTIFIER_OPT_SECTIGO_OFFSET), &first_param);
    append_query_param_num(sectigo_search_cert_url, sizeof(sectigo_search_cert_url), "limit", (size_t) property_get(props, CERTIFIER_OPT_SECTIGO_LIMIT), &first_param);
    append_query_param(sectigo_search_cert_url, sizeof(sectigo_search_cert_url), "startDate", property_get(props, CERTIFIER_OPT_SECTIGO_START_DATE), &first_param);
    append_query_param(sectigo_search_cert_url, sizeof(sectigo_search_cert_url), "endDate", property_get(props, CERTIFIER_OPT_SECTIGO_END_DATE), &first_param);
    append_query_param(sectigo_search_cert_url, sizeof(sectigo_search_cert_url), "validityStartDate", property_get(props, CERTIFIER_OPT_SECTIGO_VALIDITY_START_DATE), &first_param);
    append_query_param(sectigo_search_cert_url, sizeof(sectigo_search_cert_url), "validityEndDate", property_get(props, CERTIFIER_OPT_SECTIGO_VALIDITY_END_DATE), &first_param);
    append_query_param(sectigo_search_cert_url, sizeof(sectigo_search_cert_url), "certOrder", property_get(props, CERTIFIER_OPT_SECTIGO_CERTIFICATE_ORDER), &first_param);
    append_query_param(sectigo_search_cert_url, sizeof(sectigo_search_cert_url), "isCNinSAN", property_get(props, CERTIFIER_OPT_SECTIGO_IS_CN_IN_SAN), &first_param);
    append_query_param(sectigo_search_cert_url, sizeof(sectigo_search_cert_url), "requestType", property_get(props, CERTIFIER_OPT_SECTIGO_REQUEST_TYPE), &first_param);
    append_query_param(sectigo_search_cert_url, sizeof(sectigo_search_cert_url), "timestamp", property_get(props, CERTIFIER_OPT_SECTIGO_TIMESTAMP), &first_param);
    append_query_param(sectigo_search_cert_url, sizeof(sectigo_search_cert_url), "devhubId", property_get(props, CERTIFIER_OPT_SECTIGO_DEVHUB_ID), &first_param);
    append_query_param(sectigo_search_cert_url, sizeof(sectigo_search_cert_url), "keyType", property_get(props, CERTIFIER_OPT_SECTIGO_KEY_TYPE), &first_param);

    // certificateId is numeric for this endpoint, but a string for others, so handle separately
    const char *cert_id_str = property_get(props, CERTIFIER_OPT_SECTIGO_CERTIFICATE_ID);
    if (cert_id_str && strlen(cert_id_str) > 0) {
        size_t cert_id_num = (size_t)atol(cert_id_str);
        append_query_param_num(sectigo_search_cert_url, sizeof(sectigo_search_cert_url), "certificateId", cert_id_num, &first_param);
    }

    log_debug("Sectigo URL: %s\n", sectigo_search_cert_url);

    resp = http_get(props, sectigo_search_cert_url, headers);
    if (resp == NULL)
    {
        goto cleanup;
    }

    // Give Mutex
    if (pthread_mutex_unlock(&lock) != 0)
    {
        rc.application_error_code = 18;
        rc.application_error_msg = "sectigo_client_search_certificates: pthread_mutex_unlock failed";
        goto cleanup;
    }
    
    rc.application_error_code = resp->error;

    // Check for errors
    if (resp->error != 0)
    {
        rc.application_error_msg = util_format_curl_error("sectigo_client_search_certificates", resp->http_code, resp->error,
                                                          resp->error_msg, resp->payload, __FILE__, __LINE__);
        goto cleanup;
    }

    if (resp->payload == NULL)
    {
        log_error("ERROR: Failed to populate payload");
        goto cleanup;
    }

// Cleanup
cleanup:

    http_free_response(resp);

    return rc;
}

CertifierError sectigo_client_renew_certificate(CertifierPropMap * props)
{
    CertifierError rc = CERTIFIER_ERROR_INITIALIZER;
    JSON_Value *root_value = NULL;
    JSON_Object *root_obj = NULL;
    char *json_body = NULL;
    
    char auth_header[VERY_LARGE_STRING_SIZE * 4] = "";
    char tracking_header[LARGE_STRING_SIZE]      = "";
    char source_header[SMALL_STRING_SIZE]        = "";
    http_response * resp                         = NULL;
    const char * tracking_id                     = property_get(props, CERTIFIER_OPT_TRACKING_ID);
    const char * bearer_token                    = property_get(props, CERTIFIER_OPT_SECTIGO_AUTH_TOKEN);
    const char * source                          = "libcertifier";
    const char * sectigo_base_url                = property_get(props, CERTIFIER_OPT_SECTIGO_URL);

    if (!bearer_token) {
        log_error("Missing CERTIFIER_OPT_SECTIGO_AUTH_TOKEN");
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg  = util_format_error_here("Bearer token is missing");
        goto cleanup;
    }
    if (!sectigo_base_url) {
        log_error("Missing CERTIFIER_OPT_SECTIGO_URL");
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg  = util_format_error_here("Sectigo base URL is missing");
        goto cleanup;
    }

    // Build full URL: base + endpoint
    char sectigo_renew_cert_url[256];
    char renew_cert_endpoint[] = "/api/renewCertificate";
    strncpy(sectigo_renew_cert_url, sectigo_base_url, sizeof(sectigo_renew_cert_url) - 1);
    strncpy(sectigo_renew_cert_url + strlen(sectigo_base_url), renew_cert_endpoint,
            sizeof(sectigo_renew_cert_url) - 1 - strlen(sectigo_base_url));
    log_debug("Tracking ID is: %s\n", tracking_id);
    log_debug("Sectigo URL: %s\n", sectigo_renew_cert_url);

    if (bearer_token != NULL) {
        snprintf(auth_header, sizeof(auth_header), "Authorization: %s", bearer_token);
    }
    snprintf(tracking_header, sizeof(tracking_header), "x-xpki-request-id: %s", tracking_id);
    snprintf(source_header, sizeof(source_header), "x-xpki-source: %s", source);

    const char *headers[] = {
        "Accept: */*",
        "Connection: keep-alive",
        "cache-control: no-cache",
        "Content-Type: application/json",
        source_header,
        tracking_header,
        "x-xpki-partner-id: comcast",
        auth_header,
        NULL
    };

    // Take Mutex
    if (pthread_mutex_lock(&lock) != 0)
    {
        rc.application_error_code = 17;
        rc.application_error_msg = "sectigo_client_renew_certificate: pthread_mutex_lock failed";
        goto cleanup;
    }

    sectigo_renew_cert_param_t params;
    xc_sectigo_get_default_renew_cert_param(&params);

    // Build JSON body
    root_value = json_value_init_object();
    root_obj = json_value_get_object(root_value);

    json_object_set_string(root_obj, "commonName", params.common_name ? params.common_name : "");
    
    json_object_set_string(root_obj, "requestorEmail", params.requestor_email);

    // The following parameters are optional (one required). Only include if set
    if (params.serial_number) {
        json_object_set_string(root_obj, "serialNumber", params.serial_number);
    }
    
    if (params.certificate_id) {
        json_object_set_string(root_obj, "certificateId", params.certificate_id);
    }

    json_body = json_serialize_to_string(root_value);
    if (!json_body) {
        log_error("Failed to serialize JSON body");
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg = util_format_error_here("Failed to serialize JSON body");
        goto cleanup;
    }

    resp = http_post(props, sectigo_renew_cert_url, headers, json_body);
    if (resp == NULL)
    {
        goto cleanup;
    }

    // Give Mutex
    if (pthread_mutex_unlock(&lock) != 0)
    {
        rc.application_error_code = 18;
        rc.application_error_msg = "sectigo_client_renew_certificate: pthread_mutex_unlock failed";
        goto cleanup;
    }
    
    rc.application_error_code = resp->error;

    // Check for errors
    if (resp->error != 0)
    {
        rc.application_error_msg = util_format_curl_error("sectigo_client_renew_certificate", resp->http_code, resp->error,
                                                          resp->error_msg, resp->payload, __FILE__, __LINE__);
        goto cleanup;
    }

    if (resp->payload == NULL)
    {
        log_error("ERROR: Failed to populate payload");
        goto cleanup;
    }

// Cleanup
cleanup:

    http_free_response(resp);

    if (json_body) {
        json_free_serialized_string(json_body);
    }
    if (root_value) {
        json_value_free(root_value);
    }

    return rc;
}

CertifierError sectigo_client_revoke_certificate(CertifierPropMap * props)
{
    CertifierError rc = CERTIFIER_ERROR_INITIALIZER;
    JSON_Value *root_value = NULL;
    JSON_Object *root_obj = NULL;
    char *json_body = NULL;
    
    char auth_header[VERY_LARGE_STRING_SIZE * 4] = "";
    char tracking_header[LARGE_STRING_SIZE]      = "";
    char source_header[SMALL_STRING_SIZE]        = "";
    http_response * resp                         = NULL;
    const char * tracking_id                     = property_get(props, CERTIFIER_OPT_TRACKING_ID);
    const char * bearer_token                    = property_get(props, CERTIFIER_OPT_SECTIGO_AUTH_TOKEN);
    const char * source                          = "libcertifier";
    const char * sectigo_base_url                = property_get(props, CERTIFIER_OPT_SECTIGO_URL);

    if (!bearer_token) {
        log_error("Missing CERTIFIER_OPT_SECTIGO_AUTH_TOKEN");
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg  = util_format_error_here("Bearer token is missing");
        goto cleanup;
    }
    if (!sectigo_base_url) {
        log_error("Missing CERTIFIER_OPT_SECTIGO_URL");
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg  = util_format_error_here("Sectigo base URL is missing");
        goto cleanup;
    }

    // Build full URL: base + endpoint
    char sectigo_revoke_cert_url[256];
    char revoke_cert_endpoint[] = "/api/revokeCertificate";
    strncpy(sectigo_revoke_cert_url, sectigo_base_url, sizeof(sectigo_revoke_cert_url) - 1);
    strncpy(sectigo_revoke_cert_url + strlen(sectigo_base_url), revoke_cert_endpoint,
            sizeof(sectigo_revoke_cert_url) - 1 - strlen(sectigo_base_url));
    log_debug("Tracking ID is: %s\n", tracking_id);
    log_debug("Sectigo URL: %s\n", sectigo_revoke_cert_url);

    if (bearer_token != NULL) {
    snprintf(auth_header, sizeof(auth_header), "Authorization: %s", bearer_token);
    }
    snprintf(tracking_header, sizeof(tracking_header), "x-xpki-request-id: %s", tracking_id);
    snprintf(source_header, sizeof(source_header), "x-xpki-source: %s", source);

    const char *headers[] = {
        "Accept: */*",
        "Connection: keep-alive",
        "cache-control: no-cache",
        "Content-Type: application/json",
        source_header,
        tracking_header,
        "x-xpki-partner-id: comcast",
        auth_header,
        NULL
    };

    // Take Mutex
    if (pthread_mutex_lock(&lock) != 0)
    {
        rc.application_error_code = 17;
        rc.application_error_msg = "sectigo_client_revoke_certificate: pthread_mutex_lock failed";
        goto cleanup;
    }

    sectigo_revoke_cert_param_t params;
    xc_sectigo_get_default_revoke_cert_param(&params);

    // Build JSON body
    root_value = json_value_init_object();
    root_obj = json_value_get_object(root_value);

    json_object_set_string(root_obj, "commonName", params.common_name ? params.common_name : "");
    
    json_object_set_string(root_obj, "requestorEmail", params.requestor_email);

    json_object_set_string(root_obj, "revocationRequestReason", params.revocation_request_reason);
   
    // The following parameters are optional (one required). Only include if set
    if (params.serial_number) {
        json_object_set_string(root_obj, "serialNumber", params.serial_number);
    }
    
    if (params.certificate_id) {
        json_object_set_string(root_obj, "certificateId", params.certificate_id);
    }

    json_body = json_serialize_to_string(root_value);
    if (!json_body) {
        log_error("Failed to serialize JSON body");
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg = util_format_error_here("Failed to serialize JSON body");
        goto cleanup;
    }

    resp = http_put(props, sectigo_revoke_cert_url, headers, json_body);
    if (resp == NULL)
    {
        goto cleanup;
    }

    // Give Mutex
    if (pthread_mutex_unlock(&lock) != 0)
    {
        rc.application_error_code = 18;
        rc.application_error_msg = "sectigo_client_revoke_certificate: pthread_mutex_unlock failed";
        goto cleanup;
    }
    
    rc.application_error_code = resp->error;

    // Check for errors
    if (resp->error != 0)
    {
        rc.application_error_msg = util_format_curl_error("sectigo_client_revoke_certificate", resp->http_code, resp->error,
                                                          resp->error_msg, resp->payload, __FILE__, __LINE__);
        goto cleanup;
    }

    if (resp->payload == NULL)
    {
        log_error("ERROR: Failed to populate payload");
        goto cleanup;
    }

// Cleanup
cleanup:

    http_free_response(resp);

    if (json_body) {
        json_free_serialized_string(json_body);
    }
    if (root_value) {
        json_value_free(root_value);
    }

    return rc;
}   

CertifierError sectigo_client_ocsp_status(CertifierPropMap * props)
{
    CertifierError rc = CERTIFIER_ERROR_INITIALIZER;
    const char *pem_path = property_get(props, CERTIFIER_OPT_SECTIGO_CERT_PATH);
    if (!pem_path) {
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg = util_format_error_here("Missing cert_path property");
        return rc;
    }

    // Read PEM file into memory
    FILE *fp = fopen(pem_path, "rb");
    if (!fp) {
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        char err_msg[512];
        snprintf(err_msg, sizeof(err_msg), "Unable to open PEM file: %s (errno=%d: %s)", 
                 pem_path, errno, strerror(errno));
        rc.application_error_msg = util_format_error_here(err_msg);
        log_error("%s", err_msg);
        return rc;
    }
    log_info("PEM file opened successfully, reading content...");
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *pem_buf = (char *)XMALLOC(fsize + 1);
    if (!pem_buf) {
        fclose(fp);
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg = util_format_error_here("Memory allocation failed");
        return rc;
    }
    fread(pem_buf, 1, fsize, fp);
    pem_buf[fsize] = '\0';
    fclose(fp);

    // Load certs from PEM
    log_info("Parsing PEM buffer...");
    X509_LIST *certs = NULL;
    rc = security_load_certs_from_pem(pem_buf, &certs, true);
    XFREE(pem_buf);
    if (rc.application_error_code != 0 || !certs) {
        if (!rc.application_error_msg)
            rc.application_error_msg = util_format_error_here("Failed to parse PEM certs");
        log_error("Failed to load certs from PEM: error_code=%d", rc.application_error_code);
        return rc;
    }

    // Extract leaf and intermediate certs
    log_info("Extracting leaf and intermediate certificates...");
    int cert_count = sk_X509_num(certs);
    X509 *leaf = sk_X509_value(certs, cert_count - 1);
    X509 *issuer = cert_count > 1 ? sk_X509_value(certs, cert_count - 2) : NULL;
    if (!leaf || !issuer) {
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg = util_format_error_here("PEM must contain at least leaf and intermediate cert");
        security_free_cert_list(certs);
        return rc;
    }

    // Extract AIA OCSP URL from leaf cert
    log_info("Extracting OCSP URL from AIA extension...");
    STACK_OF(OPENSSL_STRING) *ocsp_urls = X509_get1_ocsp(leaf);
    if (!ocsp_urls || sk_OPENSSL_STRING_num(ocsp_urls) == 0) {
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg = util_format_error_here("No OCSP URL found in AIA extension");
        if (ocsp_urls) X509_email_free(ocsp_urls); // X509_email_free works for OCSP URLs too
        security_free_cert_list(certs);
        return rc;
    }
    const char *ocsp_url = sk_OPENSSL_STRING_value(ocsp_urls, 0);
    log_info("OCSP URL extracted from AIA: %s", ocsp_url);

    // Build OCSP request
    OCSP_CERTID *id = OCSP_cert_to_id(NULL, leaf, issuer);
    if (!id) {
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg = util_format_error_here("Failed to create OCSP_CERTID");
        X509_email_free(ocsp_urls);
        security_free_cert_list(certs);
        return rc;
    }
    OCSP_REQUEST *req = OCSP_REQUEST_new();
    if (!req || !OCSP_request_add0_id(req, id)) {
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg = util_format_error_here("Failed to create OCSP_REQUEST");
        if (req) OCSP_REQUEST_free(req);
        OCSP_CERTID_free(id);
        X509_email_free(ocsp_urls);
        security_free_cert_list(certs);
        return rc;
    }

    // Serialize OCSP request
    unsigned char *req_der = NULL;
    int req_der_len = i2d_OCSP_REQUEST(req, &req_der);
    if (req_der_len <= 0) {
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg = util_format_error_here("Failed to encode OCSP request");
        OCSP_REQUEST_free(req);
        X509_email_free(ocsp_urls);
        security_free_cert_list(certs);
        return rc;
    }

    // Base64 encode the OCSP request
    int base64_len = base64_encode_len(req_der_len);
    char *base64_req = (char *)XMALLOC(base64_len + 1);
    if (!base64_req) {
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg = util_format_error_here("Memory allocation failed for base64 encoding");
        OPENSSL_free(req_der);
        OCSP_REQUEST_free(req);
        X509_email_free(ocsp_urls);
        security_free_cert_list(certs);
        return rc;
    }
    base64_encode(base64_req, req_der, req_der_len);
    base64_req[base64_len] = '\0';
    
    // URL-encode the base64 string using curl_easy_escape
    CURL *curl = curl_easy_init();
    if (!curl) {
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg = util_format_error_here("Failed to initialize CURL for URL encoding");
        XFREE(base64_req);
        OPENSSL_free(req_der);
        OCSP_REQUEST_free(req);
        X509_email_free(ocsp_urls);
        security_free_cert_list(certs);
        return rc;
    }
    
    char *url_encoded = curl_easy_escape(curl, base64_req, 0);
    curl_easy_cleanup(curl);
    
    if (!url_encoded) {
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg = util_format_error_here("URL encoding failed");
        XFREE(base64_req);
        OPENSSL_free(req_der);
        OCSP_REQUEST_free(req);
        X509_email_free(ocsp_urls);
        security_free_cert_list(certs);
        return rc;
    }
    
    // Build OCSP GET URL
    char ocsp_get_url[4096];
    snprintf(ocsp_get_url, sizeof(ocsp_get_url), "%s/%s", ocsp_url, url_encoded);

    // Send OCSP GET request 
    http_response *resp = NULL;
    resp = http_get(props, ocsp_get_url, NULL);
    curl_free(url_encoded);  // Free the curl-allocated string
    XFREE(base64_req);
    
    if (!resp || !resp->payload) {
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg = util_format_error_here("Failed to get OCSP response");
        if (req_der) OPENSSL_free(req_der);
        OCSP_REQUEST_free(req);
        X509_email_free(ocsp_urls);
        security_free_cert_list(certs);
        return rc;
    }

    // Parse OCSP response (response is binary DER)
    const unsigned char *p = (const unsigned char *)resp->payload;
    long resp_len = (long)resp->payload_len;
    
    if (resp->http_code != 200) {
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        char err_msg[512];
        snprintf(err_msg, sizeof(err_msg), "Invalid OCSP response: HTTP %d", resp->http_code);
        rc.application_error_msg = util_format_error_here(err_msg);
        if (req_der) OPENSSL_free(req_der);
        OCSP_REQUEST_free(req);
        X509_email_free(ocsp_urls);
        security_free_cert_list(certs);
        http_free_response(resp);
        return rc;
    }
    
    OCSP_RESPONSE *ocsp_resp = d2i_OCSP_RESPONSE(NULL, &p, resp_len);
    if (!ocsp_resp) {
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg = util_format_error_here("Failed to parse OCSP response");
        if (req_der) OPENSSL_free(req_der);
        OCSP_REQUEST_free(req);
        X509_email_free(ocsp_urls);
        security_free_cert_list(certs);
        http_free_response(resp);
        return rc;
    }

    int status = OCSP_response_status(ocsp_resp);
    if (status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg = util_format_error_here("OCSP response not successful");
    } else {
        OCSP_BASICRESP *basic = OCSP_response_get1_basic(ocsp_resp);
        if (!basic) {
            rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
            rc.application_error_msg = util_format_error_here("Failed to parse OCSP_BASICRESP");
        } else {
            int cert_status, crl_reason;
            ASN1_GENERALIZEDTIME *revtime, *thisupd, *nextupd;
            cert_status = OCSP_single_get0_status(
                OCSP_resp_get0(basic, 0), &crl_reason, &revtime, &thisupd, &nextupd);
            
            const char *status_str = OCSP_cert_status_str(cert_status);
            char msg[512];
            
            if (cert_status == V_OCSP_CERTSTATUS_GOOD) {
                rc.application_error_code = 0;
                snprintf(msg, sizeof(msg), "Certificate status: %s", status_str);
                rc.application_error_msg = util_format_error_here(msg);
                log_info("%s", msg);
            } else if (cert_status == V_OCSP_CERTSTATUS_REVOKED) {
                rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
                snprintf(msg, sizeof(msg), "Certificate status: %s (reason=%d)", status_str, crl_reason);
                rc.application_error_msg = util_format_error_here(msg);
                log_error("%s", msg);
            } else {
                rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
                snprintf(msg, sizeof(msg), "Certificate status: %s", status_str);
                rc.application_error_msg = util_format_error_here(msg);
                log_warn("%s", msg);
            }
            OCSP_BASICRESP_free(basic);
        }
    }

    OCSP_RESPONSE_free(ocsp_resp);
    if (req_der) OPENSSL_free(req_der);
    OCSP_REQUEST_free(req);
    X509_email_free(ocsp_urls);
    security_free_cert_list(certs);
    http_free_response(resp);
    return rc;
}

SECTIGO_CLIENT_ERROR_CODE xc_sectigo_get_cert(sectigo_get_cert_param_t * params)
{
    Certifier *certifier = get_sectigo_certifier_instance();

    // Build JSON body
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_obj = json_value_get_object(root_value);

    // Add all parameters to JSON body using passed-in params
    if (params->common_name)
        json_object_set_string(root_obj, "commonName", params->common_name);
    if (params->group_name)
        json_object_set_string(root_obj, "groupName", params->group_name);
    if (params->group_email)
        json_object_set_string(root_obj, "groupEmailAddress", params->group_email);
    if (params->id)
        json_object_set_string(root_obj, "id", params->id);
    if (params->owner_first_name)
        json_object_set_string(root_obj, "ownerFirstName", params->owner_first_name);
    if (params->owner_last_name)
        json_object_set_string(root_obj, "ownerLastName", params->owner_last_name);
    if (params->project_name)
        json_object_set_string(root_obj, "projectName", params->project_name);
    if (params->business_justification)
        json_object_set_string(root_obj, "businessJustification", params->business_justification);
    
    // subjectAltNames as array
    JSON_Value *san_array = json_value_init_array();
    JSON_Array *san_json_array = json_value_get_array(san_array);
    if (params->subject_alt_names && strlen(params->subject_alt_names) > 0) {
        char *san_copy = XSTRDUP(params->subject_alt_names);
        char *token = strtok(san_copy, ",");
        while (token) {
            json_array_append_value(san_json_array, json_value_init_string(token));
            token = strtok(NULL, ",");
        }
        XFREE(san_copy);
    }
    json_object_set_value(root_obj, "subjectAltNames", san_array);

    json_object_set_string(root_obj, "certificateType", "comodo");  // Always "comodo"

    if (params->owner_email)
        json_object_set_string(root_obj, "ownerEmailAddress", params->owner_email);
    
    // Generate CSR and add to body
    char *csr_pem = NULL;
    CertifierError csr_rc = sectigo_generate_certificate_signing_request(certifier, &csr_pem);
    if (csr_rc.application_error_code != 0 || csr_pem == NULL) {
        log_error("Failed to generate CSR: %s\n", csr_rc.application_error_msg);
        if (csr_pem) XFREE(csr_pem);
        json_value_free(root_value);
        return csr_rc.application_error_code;
    }
    json_object_set_string(root_obj, "certificateSigningRequest", csr_pem);

    // Serialize JSON body
    char *json_body = json_serialize_to_string(root_value);

    // Call the request function
    CertifierPropMap *props = certifier_get_prop_map(certifier);
    char *cert_output = NULL;
    CertifierError req_rc = sectigo_client_request_certificate(
        props,
        (unsigned char *)csr_pem,
        NULL, // node_address
        NULL, // certifier_id
        &cert_output
    );

    // Cleanup
    if (csr_pem) XFREE(csr_pem);
    if (json_body) json_free_serialized_string(json_body);
    if (root_value) json_value_free(root_value);

    return req_rc.application_error_code;
}

SECTIGO_CLIENT_ERROR_CODE xc_sectigo_search_cert(sectigo_search_cert_param_t * params)
{
    Certifier *certifier = get_sectigo_certifier_instance();

    // Call the request function
    CertifierPropMap *props = certifier_get_prop_map(certifier);
    CertifierError req_rc = sectigo_client_search_certificates(props);

    return req_rc.application_error_code;
}

SECTIGO_CLIENT_ERROR_CODE xc_sectigo_renew_cert(sectigo_renew_cert_param_t * params)
{
    Certifier *certifier = get_sectigo_certifier_instance();

    // Call the request function
    CertifierPropMap *props = certifier_get_prop_map(certifier);
    CertifierError req_rc = sectigo_client_renew_certificate(props);

    return req_rc.application_error_code;
}

SECTIGO_CLIENT_ERROR_CODE xc_sectigo_revoke_cert(sectigo_revoke_cert_param_t * params)
{
    Certifier *certifier = get_sectigo_certifier_instance();

    // Call the request function
    CertifierPropMap *props = certifier_get_prop_map(certifier);
    CertifierError req_rc = sectigo_client_revoke_certificate(props);

    return req_rc.application_error_code;
}

SECTIGO_CLIENT_ERROR_CODE xc_sectigo_ocsp_status(sectigo_ocsp_status_param_t * params)
{
    Certifier *certifier = get_sectigo_certifier_instance();

    // Call the request function
    CertifierPropMap *props = certifier_get_prop_map(certifier);
    CertifierError req_rc = sectigo_client_ocsp_status(props);

    return req_rc.application_error_code;
}
