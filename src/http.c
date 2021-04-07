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

#include <curl/curl.h>
#include "certifier/http.h"
#include "certifier/log.h"
#include "certifier/httpdebug.h"
#include "certifier/property.h"
#include "certifier/types.h"

static void
set_curl_options(CURL *curl, CertifierPropMap *prop_map) {
    int host_validation = property_is_option_set(prop_map, CERTIFIER_OPTION_TLS_INSECURE_HOST) ? 0 : 2;
    int peer_validation = property_is_option_set(prop_map, CERTIFIER_OPTION_TLS_INSECURE_PEER) ? 0 : 1;
    int is_debug_http_enabled = property_is_option_set(prop_map, CERTIFIER_OPTION_DEBUG_HTTP);
    int is_trace_http_enabled = property_is_option_set(prop_map, CERTIFIER_OPTION_TRACE_HTTP);
    long http_timeout = (long) property_get(prop_map, CERTIFIER_OPT_HTTP_TIMEOUT);
    long http_connect_timeout = (long) property_get(prop_map, CERTIFIER_OPT_HTTP_CONNECT_TIMEOUT);

    log_debug("[set_curl_options] - Host Validation=%i", host_validation);
    log_debug("[set_curl_options] - Peer Validation=%i", peer_validation);
    log_debug("[set_curl_options] - Debug HTTP Enabled=%i", is_debug_http_enabled);
    log_debug("[set_curl_options] - Trace HTTP Enabled=%i", is_trace_http_enabled);


    // First set the URL that is about to receive our POST.
    http_set_curlopt(curl, CURLOPT_ACCEPT_ENCODING, "");
    http_set_curlopt(curl, CURLOPT_VERBOSE, is_debug_http_enabled);
    http_set_curlopt(curl, CURLOPT_CAINFO, property_get(prop_map, CERTIFIER_OPT_CA_INFO));
    http_set_curlopt(curl, CURLOPT_CAPATH, property_get(prop_map, CERTIFIER_OPT_CA_PATH));
    http_set_curlopt(curl, CURLOPT_SSL_VERIFYHOST, host_validation);
    http_set_curlopt(curl, CURLOPT_SSL_VERIFYPEER, peer_validation);
    http_set_curlopt(curl, CURLOPT_FAILONERROR, 1L);

    http_set_curlopt(curl, CURLOPT_TIMEOUT, http_timeout);
    http_set_curlopt(curl, CURLOPT_CONNECTTIMEOUT, http_connect_timeout);

    http_set_curlopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);

    if (is_trace_http_enabled) {
        http_set_curlopt(curl, CURLOPT_DEBUGFUNCTION, http_debug_trace);
    }
}


// Holder for curl fetch
struct curl_fetch_st {
    char *payload;
    size_t size;
    int return_code;
};

/* callback for curl fetch */
static size_t
http_curl_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;                            /* calculate buffer size */
    struct curl_fetch_st *p = (struct curl_fetch_st *) userp; /* cast pointer to fetch struct */

    /* expand buffer */
    p->payload = (char *) XREALLOC(p->payload, p->size + realsize + 1);

    /* check buffer */
    if (p->payload == NULL) {
        /* this isn't good */
        log_error("ERROR: Failed to expand buffer in http_curl_callback");
        /* free buffer */
        XFREE(p->payload);
        /* return */
        return -1;
    }

    /* copy contents to buffer */
    XMEMCPY(&(p->payload[p->size]), contents, realsize);

    /* set new buffer size */
    p->size += realsize;

    /* ensure null termination */
    p->payload[p->size] = 0;

    /* return size */
    return realsize;
}

static http_response *http_error_response(const char *msg, int error_code, int http_code) {
    http_response *resp = XCALLOC(1, sizeof(http_response));
    if (resp != NULL) {
        resp->error = error_code;
        resp->error_msg = XSTRDUP(msg);
        resp->http_code = http_code;
    }
    return resp;
}

static http_response *http_success_response(const char *payload,
                                            int http_code,
                                            const char *errbuf,
                                            int err_code) {
    http_response *resp = XCALLOC(1, sizeof(http_response));
    if (resp != NULL) {
        resp->error = err_code;
        resp->error_msg = XSTRDUP(errbuf);
        resp->http_code = http_code;
        resp->payload = payload; // struct takes ownership of payload
    }
    return resp;
}

static http_response *do_http(const CertifierPropMap *props,
                              const char *url,
                              const char *http_headers[],
                              const char *body) {
    char errbuf[CURL_ERROR_SIZE] = {0};

    struct curl_slist *chunk = NULL;
    struct curl_fetch_st curl_fetch;         /* curl fetch struct */
    struct curl_fetch_st *cf = &curl_fetch; /* pointer to fetch struct */
    CURL *curl = NULL;
    CURLcode res;
    long http_code = 0;
    const char *error_message;
    int i;

    /* init payload */
    cf->payload = (char *) XMALLOC(1);

    /* check payload */
    if (cf->payload == NULL) {
        return http_error_response("do_http malloc failed", 0, 0);
    }
    cf->size = 0;
    cf->return_code = 0;

    // Get a curl handle
    curl = curl_easy_init();
    if (curl == NULL)
        return http_error_response("curl_easy_init failed", 0, 0);

    for (i = 0; http_headers[i]; ++i) {
        chunk = curl_slist_append(chunk, http_headers[i]);
    }

    set_curl_options(curl, (CertifierPropMap *) props);

    errbuf[0] = 0;

    http_set_curlopt(curl, CURLOPT_URL, url);

    // post
    if ((body != NULL) && (XSTRLEN(body) > 0)) {
        http_set_curlopt(curl, CURLOPT_POSTFIELDS, body);
    }


    http_set_curlopt(curl, CURLOPT_HTTPHEADER, chunk);
    http_set_curlopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    http_set_curlopt(curl, CURLOPT_WRITEFUNCTION, http_curl_callback);
    http_set_curlopt(curl, CURLOPT_WRITEDATA, cf);

    // Perform the request, res will get the return code
    res = curl_easy_perform(curl);

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    if (res != CURLE_OK) {
        size_t len = XSTRLEN(errbuf);
        log_error("libcurl: (%d) ", res);
        if (len) {
            log_error("%s%s", errbuf,
                      ((errbuf[len - 1] != '\n') ? "\n" : ""));
        } else {
            log_error("%s\n", curl_easy_strerror(res));
        }

        log_error("curl_easy_perform() failed with curl error: %s and http return code: %ld\n",
                  curl_easy_strerror(res), http_code);
        
        // do these two functions return an error and check for it?
        curl_easy_cleanup(curl);
        curl_slist_free_all(chunk);
        
        if (res != CURLE_OK) { // could the two functions above ever get an error, and if so, should this be checked
            error_message = curl_easy_strerror(res);
            if (error_message != NULL) {
                free(cf->payload);
                return http_error_response(error_message, res, http_code);
            }
        }
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all(chunk);

    log_debug("do_http returned: %s", cf->payload);

    return http_success_response(cf->payload, http_code, errbuf, res);
}

int
http_init() {
    return 0;
}

int
http_destroy() {
    return 0;
}

http_response *http_get(const CertifierPropMap *props, const char *url,
                        const char *http_headers[]) {
    return do_http(props, url, http_headers, NULL);
}


http_response *http_post(const CertifierPropMap *props, const char *url,
                         const char *http_headers[],
                         const char *body) {

    return do_http(props, url, http_headers, body);
}

void http_free_response(http_response *resp) {
    if (resp) {
        XFREE((char *) resp->payload);
        XFREE((char *) resp->error_msg);
        XFREE(resp);
    }
}
