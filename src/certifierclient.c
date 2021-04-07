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

#include "certifier/http.h"
#include "certifier/log.h"
#include "certifier/certifier_internal.h"
#include "certifier/certifierclient.h"
#include "certifier/util.h"
#include "certifier/parson.h"

// Functions
int
certifierclient_init() {
    return http_init();
}

int
certifierclient_destroy() {
    return http_destroy();
}

CertifierError
certifierclient_request_x509_certificate(CertifierPropMap *props,
                                         const unsigned char *csr,
                                         const char *node_address,
                                         const char *certifier_id,
                                         char **out_cert) {
    CertifierError rc = CERTIFIER_ERROR_INITIALIZER;
    if (out_cert == NULL) {
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg = util_format_error_here("out cert cannot be null");
        return rc;
    }

    char auth_header[VERY_LARGE_STRING_SIZE * 4] = "";
    char tracking_header[LARGE_STRING_SIZE] = "";
    char source_header[SMALL_STRING_SIZE] = "";
    JSON_Object *parsed_json_object_value = NULL;
    JSON_Value *parsed_json_root_value = NULL;

    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    char *serialized_string = NULL;

    const char *certificate_chain = NULL;
    http_response *resp = NULL;
    const char *tracking_id = property_get(props, CERTIFIER_OPT_TRACKING_ID);
    const char *bearer_token = property_get(props, CERTIFIER_OPT_CRT);
    const char *source = property_get(props, CERTIFIER_OPT_SOURCE);
    const char *certifier_url = property_get(props, CERTIFIER_OPT_CERTIFIER_URL);
    const char *system_id = property_get(props, CERTIFIER_OPT_SYSTEM_ID);
    const char *mac_address = property_get(props, CERTIFIER_OPT_MAC_ADDRESS);
    size_t  num_days   = (size_t) property_get(props, CERTIFIER_OPT_NUM_DAYS);
    bool is_certificate_lite = property_is_option_set(props, CERTIFIER_OPTION_CERTIFICATE_LITE);


    log_debug("Tracking ID is: %s", tracking_id);

    if (util_is_empty(source)) {
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg = util_format_error_here("CERTIFIER_OPT_SOURCE must be set to a non-empty string!");
        goto cleanup;
    }

    if (bearer_token != NULL) {
        snprintf(auth_header, VERY_LARGE_STRING_SIZE * 4, "Authorization: Bearer %s", bearer_token);
    }
    snprintf(tracking_header, SMALL_STRING_SIZE, "x-xpki-tracking-id: %s", tracking_id);
    snprintf(source_header, SMALL_STRING_SIZE, "x-xpki-source: %s", source);

    const char *headers[] = {
            "Accept: application/json",
            "Content-Type: application/json; charset=utf-8",
            auth_header,
            tracking_header,
            source_header,
            NULL
    };

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

    resp = http_post(props, certifier_url, headers, serialized_string);
    if (resp == NULL) {
        goto cleanup;
    }

    rc.application_error_code = resp->error;

    // Check for errors
    if (resp->error != 0) {
        rc.application_error_msg = util_format_curl_error("certifierclient_request_x509_certificate",
                                                          resp->http_code, resp->error, resp->error_msg, resp->payload,
                                                          __FILE__, __LINE__);
        goto cleanup;
    }

    if (resp->payload == NULL) {
        log_error("ERROR: Failed to populate payload");
        goto cleanup;
    }

    /* print result */
    log_debug("CURL Returned: \n%s\n", resp->payload);

    parsed_json_root_value = json_parse_string_with_comments(resp->payload);
    if (json_value_get_type(parsed_json_root_value) != JSONObject) {
        rc.application_error_msg = util_format_curl_error("certifierclient_request_x509_certificate", resp->http_code,
                                                          resp->error,
                                                          "Could not parse JSON.  Expected it to be an array.",
                                                          resp->payload, __FILE__, __LINE__);
        goto cleanup;
    }

    parsed_json_object_value = json_value_get_object(parsed_json_root_value);

    if (parsed_json_object_value == NULL) {
        rc.application_error_msg = util_format_curl_error("certifierclient_request_x509_certificate",
                                                          resp->http_code, resp->error,
                                                          "Could not parse JSON.  parsed_json_object_value is NULL!.",
                                                          resp->payload, __FILE__, __LINE__);
        goto cleanup;
    }

    certificate_chain = json_object_get_string(parsed_json_object_value, "certificateChain");

    if (certificate_chain == NULL) {
        rc.application_error_msg = util_format_curl_error("certifierclient_request_x509_certificate",
                                                          resp->http_code, resp->error,
                                                          "Could not parse JSON.  certificate_chain is NULL!",
                                                          resp->payload, __FILE__, __LINE__);
        goto cleanup;
    }

    log_debug("Certificate Chain=%s\n", certificate_chain);

    *out_cert = XSTRDUP(certificate_chain);

    // Cleanup
    cleanup:

    http_free_response(resp);

    if (root_value) {
        json_value_free(root_value);
    }

    if (parsed_json_root_value) {
        json_value_free(parsed_json_root_value);
    }

    XFREE(serialized_string);
    return rc;
}

