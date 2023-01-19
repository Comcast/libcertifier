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

#include <sys/ipc.h>
#include <sys/sem.h>
#include <errno.h>
#include <stdbool.h>

#define SEM_MUTEX_KEY "/tmp/sem-mutex-key"

static int mutex_sem;

// Functions
int
certifierclient_init() {
    key_t s_key;
    bool sem_exists = false;

    if (open(SEM_MUTEX_KEY, O_EXCL | O_CREAT, 0600) == -1) {
        if (errno == EEXIST) {
            sem_exists = true;
        } else {
            return 1;
        }
    }

    s_key = ftok(SEM_MUTEX_KEY, 'a');
    if (s_key == -1) {
        return 1;
    }

    mutex_sem = semget(s_key, 1, sem_exists ? 0 : (0666 | IPC_CREAT));
    if (mutex_sem == -1) {
        return 1;
    }

    if (sem_exists == false) {
        union semun {
            int              val;    /* Value for SETVAL */
            struct semid_ds *buf;    /* Buffer for IPC_STAT, IPC_SET */
            unsigned short  *array;  /* Array for GETALL, SETALL */
            struct seminfo  *__buf;  /* Buffer for IPC_INFO
                                        (Linux-specific) */
        } sem_attr;

        sem_attr.val = 1; // start sem unlocked
        int rc = semctl(mutex_sem, 0, SETVAL, sem_attr);
        if (rc == -1) {
            return 1;
        }
    }

    return http_init();
}

int
certifierclient_destroy() {
    semctl(mutex_sem, 0, IPC_RMID);
    unlink(SEM_MUTEX_KEY);

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

    struct sembuf asem [1] = { 0 };

    char auth_header[VERY_LARGE_STRING_SIZE * 4] = "";
    char tracking_header[LARGE_STRING_SIZE] = "";
    char source_header[SMALL_STRING_SIZE] = "";
    JSON_Object *parsed_json_object_value = NULL;
    JSON_Value *parsed_json_root_value = NULL;
    char *serialized_string = NULL;
    const char *certificate_chain = NULL;
    http_response *resp = NULL;
    const char *tracking_id = property_get(props, CERTIFIER_OPT_TRACKING_ID);
    const char *bearer_token = property_get(props, CERTIFIER_OPT_CRT);
    const char *source = property_get(props, CERTIFIER_OPT_SOURCE);
    const char *certifier_url = property_get(props, CERTIFIER_OPT_CERTIFIER_URL);
    log_debug("Tracking ID is: %s", tracking_id);
    log_debug("Source ID is: %s", source);

    char certifier_certificate_url[256];
    char certificate_url[] = "/certificate";
    strncpy(certifier_certificate_url, certifier_url, sizeof(certifier_certificate_url));
    strncpy(certifier_certificate_url + strlen(certifier_url), certificate_url, sizeof(certifier_certificate_url) - strlen(certifier_url));

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

    serialized_string = certifier_create_csr_post_data(props, csr, node_address, certifier_id);

    // Take Mutex
    asem[0].sem_op = -1;
    // undo mutex-take if app crashes during http_post
    asem[0].sem_flg = SEM_UNDO;
    if (semop(mutex_sem, asem, 1) == -1) {
        rc.application_error_code = 1;
        goto cleanup;
    }

    resp = http_post(props, certifier_certificate_url, headers, serialized_string);
    if (resp == NULL) {
        goto cleanup;
    }

    // Give Mutex
    asem[0].sem_op = 1;
    if (semop(mutex_sem, asem, 1) == -1) {
        rc.application_error_code = 1;
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

    if (parsed_json_root_value) {
        json_value_free(parsed_json_root_value);
    }

    XFREE(serialized_string);
    return rc;
}

static int dtoa(const unsigned char *digest, const size_t digest_len, char * array, const size_t array_len) {
    if (digest == NULL || array == NULL) {
        return 1;
    }
    if (digest_len != CERTIFIER_SHA1_DIGEST_LENGTH || digest_len * 2 + 1 != array_len) {
        return 2;
    }

    for (size_t i = 0; i < digest_len; ++i) {
        snprintf(&array[i * 2], sizeof(char) * 2 + 1, "%02x", digest[i]);
    }

    return 0;
}

CertifierError
certifierclient_revoke_x509_certificate(CertifierPropMap *props,
                                        const unsigned char *digest,
                                        const size_t digest_len) {
    CertifierError rc = CERTIFIER_ERROR_INITIALIZER;

    struct sembuf asem [1] = { 0 };

    char auth_header[VERY_LARGE_STRING_SIZE * 4] = "";
    char tracking_header[LARGE_STRING_SIZE] = "";
    char source_header[SMALL_STRING_SIZE] = "";
    JSON_Object *parsed_json_object_value = NULL;
    JSON_Value *parsed_json_root_value = NULL;
    char *serialized_string = NULL;
    http_response *resp = NULL;
    const char *tracking_id = property_get(props, CERTIFIER_OPT_TRACKING_ID);
    const char *bearer_token = property_get(props, CERTIFIER_OPT_CRT);
    const char *source = property_get(props, CERTIFIER_OPT_SOURCE);
    const char *certifier_url = property_get(props, CERTIFIER_OPT_CERTIFIER_URL);
    log_debug("Tracking ID is: %s", tracking_id);

    char array_digest[CERTIFIER_SHA1_DIGEST_LENGTH * 2 + 1];
    char certifier_revoke_url[256];
    char revoke_url[] = "/revoke";
    strncpy(certifier_revoke_url, certifier_url, sizeof(certifier_revoke_url));
    strncpy(certifier_revoke_url + strlen(certifier_url), revoke_url, sizeof(certifier_revoke_url) - strlen(certifier_url));

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
            "Content-Type: application/json",
            auth_header,
            tracking_header,
            source_header,
            NULL
    };

    if (dtoa(digest, digest_len, array_digest, sizeof(array_digest)) != 0) {
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg = util_format_error_here("digest length invalid");
        return rc;
    }

    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);

    json_object_set_string(root_object, "revokeReason", "UNSPECIFIED");
    json_object_set_string(root_object, "certificateId", array_digest);

    serialized_string = json_serialize_to_string_pretty(root_value);

    log_debug("\nCertificate Revoke Request:\n%s\n", serialized_string);

    // Take Mutex
    asem[0].sem_op = -1;
    // undo mutex-take if app crashes during http_post
    asem[0].sem_flg = SEM_UNDO;
    if (semop(mutex_sem, asem, 1) == -1) {
        rc.application_error_code = 1;
        goto cleanup;
    }

    resp = http_post(props, certifier_revoke_url, headers, serialized_string);
    if (resp == NULL) {
        goto cleanup;
    }

    // Give Mutex
    asem[0].sem_op = 1;
    if (semop(mutex_sem, asem, 1) == -1) {
        rc.application_error_code = 1;
        goto cleanup;
    }

    rc.application_error_code = resp->error;

    // Check for errors
    if (resp->error != 0) {
        rc.application_error_msg = util_format_curl_error("certifierclient_revoke_x509_certificate",
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
        rc.application_error_msg = util_format_curl_error("certifierclient_revoke_x509_certificate", resp->http_code,
                                                          resp->error,
                                                          "Could not parse JSON.  Expected it to be an array.",
                                                          resp->payload, __FILE__, __LINE__);
        goto cleanup;
    }

    parsed_json_object_value = json_value_get_object(parsed_json_root_value);

    if (parsed_json_object_value == NULL) {
        rc.application_error_msg = util_format_curl_error("certifierclient_revoke_x509_certificate",
                                                          resp->http_code, resp->error,
                                                          "Could not parse JSON.  parsed_json_object_value is NULL!.",
                                                          resp->payload, __FILE__, __LINE__);
        goto cleanup;
    }

    // Cleanup
    cleanup:

    http_free_response(resp);

    if (parsed_json_root_value) {
        json_value_free(parsed_json_root_value);
    }

    if (root_value) {
        json_value_free(root_value);
    }

    XFREE(serialized_string);
    return rc;
}

CertifierError
certifierclient_renew_x509_certificate(CertifierPropMap *props,
                                       const unsigned char *digest,
                                       const size_t digest_len,
                                       char** out_cert) {
    CertifierError rc = CERTIFIER_ERROR_INITIALIZER;

    struct sembuf asem [1] = { 0 };

    char auth_header[VERY_LARGE_STRING_SIZE * 4] = "";
    char tracking_header[LARGE_STRING_SIZE] = "";
    char source_header[SMALL_STRING_SIZE] = "";
    JSON_Object *parsed_json_object_value = NULL;
    JSON_Value *parsed_json_root_value = NULL;
    char *serialized_string = NULL;
    const char *certificate_chain = NULL;
    http_response *resp = NULL;
    const char *tracking_id = property_get(props, CERTIFIER_OPT_TRACKING_ID);
    const char *bearer_token = property_get(props, CERTIFIER_OPT_CRT);
    const char *source = property_get(props, CERTIFIER_OPT_SOURCE);
    const char *certifier_url = property_get(props, CERTIFIER_OPT_CERTIFIER_URL);
    log_debug("Tracking ID is: %s", tracking_id);

    char array_digest[CERTIFIER_SHA1_DIGEST_LENGTH * 2 + 1];
    char certifier_renew_url[256];
    char renew_url[] = "/renew";
    strncpy(certifier_renew_url, certifier_url, sizeof(certifier_renew_url));
    strncpy(certifier_renew_url + strlen(certifier_url), renew_url, sizeof(certifier_renew_url) - strlen(certifier_url));

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
            "Content-Type: application/json",
            auth_header,
            tracking_header,
            source_header,
            NULL
    };

    if (dtoa(digest, digest_len, array_digest, sizeof(array_digest)) != 0) {
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg = util_format_error_here("digest length invalid");
        return rc;
    }

    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);

    json_object_set_string(root_object, "certificateId", array_digest);

    serialized_string = json_serialize_to_string_pretty(root_value);

    log_debug("\nCertificate Renew Request:\n%s\n", serialized_string);

    // Take Mutex
    asem[0].sem_op = -1;
    // undo mutex-take if app crashes during http_post
    asem[0].sem_flg = SEM_UNDO;
    if (semop(mutex_sem, asem, 1) == -1) {
        rc.application_error_code = 1;
        goto cleanup;
    }

    resp = http_post(props, certifier_renew_url, headers, serialized_string);
    if (resp == NULL) {
        goto cleanup;
    }

    // Give Mutex
    asem[0].sem_op = 1;
    if (semop(mutex_sem, asem, 1) == -1) {
        rc.application_error_code = 1;
        goto cleanup;
    }

    rc.application_error_code = resp->error;

    // Check for errors
    if (resp->error != 0) {
        rc.application_error_msg = util_format_curl_error("certifierclient_renew_x509_certificate",
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
        rc.application_error_msg = util_format_curl_error("certifierclient_renew_x509_certificate", resp->http_code,
                                                          resp->error,
                                                          "Could not parse JSON.  Expected it to be an array.",
                                                          resp->payload, __FILE__, __LINE__);
        goto cleanup;
    }

    parsed_json_object_value = json_value_get_object(parsed_json_root_value);

    if (parsed_json_object_value == NULL) {
        rc.application_error_msg = util_format_curl_error("certifierclient_renew_x509_certificate",
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

    if (parsed_json_root_value) {
        json_value_free(parsed_json_root_value);
    }

    if (root_value) {
        json_value_free(root_value);
    }

    XFREE(serialized_string);
    return rc;
}

CertifierError
certifierclient_check_certificate_status(CertifierPropMap *props,
                                         const unsigned char *digest,
                                         const size_t digest_len) {
    CertifierError rc = CERTIFIER_ERROR_INITIALIZER;
    if (digest == NULL) {
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg = util_format_error_here("digest cannot be null");
        return rc;
    }

    struct sembuf asem [1] = { 0 };

    JSON_Object *parsed_json_object_value = NULL;
    JSON_Value *parsed_json_root_value = NULL;
    const char *certificate_status = NULL;
    http_response *resp = NULL;
    const char *certifier_url = property_get(props, CERTIFIER_OPT_CERTIFIER_URL);
    char certifier_status_url[256];
    char status_url[] = "/certificate/status/";
    char array_digest[CERTIFIER_SHA1_DIGEST_LENGTH * 2 + 1];
    strncpy(certifier_status_url, certifier_url, sizeof(certifier_status_url));
    strncpy(certifier_status_url + strlen(certifier_url), status_url, sizeof(certifier_status_url) - strlen(certifier_url));

    if (dtoa(digest, digest_len, array_digest, sizeof(array_digest)) != 0) {
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg = util_format_error_here("digest length invalid");
        return rc;
    }

    strncpy(certifier_status_url + strlen(certifier_url) + sizeof(status_url) - 1,
            array_digest, sizeof(certifier_status_url) - strlen(certifier_url) - strlen(status_url));

    // Take Mutex
    asem[0].sem_op = -1;
    // undo mutex-take if app crashes during http_post
    asem[0].sem_flg = SEM_UNDO;
    if (semop(mutex_sem, asem, 1) == -1) {
        rc.application_error_code = 1;
        goto cleanup;
    }

    resp = http_post(props, certifier_status_url, NULL, NULL);
    if (resp == NULL) {
        goto cleanup;
    }

    // Give Mutex
    asem[0].sem_op = 1;
    if (semop(mutex_sem, asem, 1) == -1) {
        rc.application_error_code = 1;
        goto cleanup;
    }

    rc.application_error_code = resp->error;

    // Check for errors
    if (resp->error != 0) {
        rc.application_error_msg = util_format_curl_error("certifierclient_check_certificate_status",
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
        rc.application_error_msg = util_format_curl_error("certifierclient_check_certificate_status", resp->http_code,
                                                          resp->error,
                                                          "Could not parse JSON.  Expected it to be an array.",
                                                          resp->payload, __FILE__, __LINE__);
        goto cleanup;
    }

    parsed_json_object_value = json_value_get_object(parsed_json_root_value);

    if (parsed_json_object_value == NULL) {
        rc.application_error_msg = util_format_curl_error("certifierclient_check_certificate_status",
                                                          resp->http_code, resp->error,
                                                          "Could not parse JSON.  parsed_json_object_value is NULL!.",
                                                          resp->payload, __FILE__, __LINE__);
        goto cleanup;
    }

    certificate_status = json_object_get_string(parsed_json_object_value, "status");

    if (certificate_status == NULL) {
        rc.application_error_msg = util_format_curl_error("certifierclient_check_certificate_status",
                                                          resp->http_code, resp->error,
                                                          "Could not parse JSON.  certificate_status is NULL!",
                                                          resp->payload, __FILE__, __LINE__);
        goto cleanup;
    }

    log_debug("Certificate Status=%s\n", certificate_status);

    if (strncmp(certificate_status, "GOOD", strlen("GOOD")) == 0) {
        goto cleanup;
    } else if (strncmp(certificate_status, "UNKNOWN", strlen("UNKNOWN")) == 0) {
        rc.application_error_code = CERTIFIER_ERR_GET_CERT_STATUS_UNKOWN;
        rc.application_error_msg = util_format_error_here("Certificate Unknown");
        goto cleanup;
    } else if (strncmp(certificate_status, "REVOKED", strlen("REVOKED")) == 0) {
        rc.application_error_code = CERTIFIER_ERR_GET_CERT_STATUS_REVOKED;
        rc.application_error_msg = util_format_error_here("Certificate Revoked");
        goto cleanup;
    } else {
        rc.application_error_code = CERTIFIER_ERR_GET_CERT_STATUS_UNKOWN;
        rc.application_error_msg = util_format_error_here("Certificate Unknown");
        goto cleanup;
    }

    // Cleanup
    cleanup:

    http_free_response(resp);

    if (parsed_json_root_value) {
        json_value_free(parsed_json_root_value);
    }

    return rc;
}
