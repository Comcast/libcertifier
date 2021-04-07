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

#include "certifier/base64.h"
#include "certifier/certifier.h"
#include "certifier/certifier_internal.h"
#include "certifier/log.h"
#include "certifier/util.h"
#include "certifier/certifier_api_easy.h"
#include "certifier/types.h"
#include "certifier/security.h"
#include "certifier/http.h"

// Defines
#define DEFAULT_PASSWORD             "changeit"
#define VERY_SMALL_STRING_SIZE 32
#define VERY_LARGE_STRING_SIZE 2048

#define NULL_CHECK(p)                                                   \
if (p == NULL)                                                          \
    return CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1

#define safe_exit(le, rc) finish_operation(le, rc, NULL)

static void finish_operation(CERTIFIER *easy, int return_code, const char *operation_output);

// Private data

typedef struct CERTIFIERInfo {
    char *json;
    char *operation_result;
    int error_code;
} CERTIFIERInfo;

struct CERTIFIER {
    Certifier *certifier;
    CERTIFIER_MODE mode;
    bool is_client_app;
    int argc;
    char **argv;
    CERTIFIERInfo last_info;
};

static void free_easy_info(CERTIFIERInfo *info) {
    XFREE(info->json);
    XFREE(info->operation_result);
    info->json = NULL;
    info->operation_result = NULL;
    info->error_code = 0;
}

CERTIFIER *certifier_api_easy_new(void) {
    CERTIFIER *easy = NULL;
    Certifier *certifier = certifier_new();
    if (certifier == NULL) {
        log_error("Received a null certifier.");
        return NULL;
    }
    easy = XCALLOC(1, sizeof(CERTIFIER));
    if (easy == NULL) {
        log_error("Could not allocate enough memory to allocate a new Certifier");
        certifier_destroy(certifier);
        return NULL;
    }
    easy->certifier = certifier;
    easy->mode = CERTIFIER_MODE_REGISTER;
    return easy;
}

Certifier * certifier_get_sertifier_instance(const CERTIFIER *easy)
{
    return easy->certifier;
}

CERTIFIER *certifier_api_easy_new_cfg(char *libcertifier_cfg) {
    CERTIFIER *easy = NULL;
    easy = certifier_api_easy_new();
    if (util_file_exists(libcertifier_cfg))
    {
        certifier_api_easy_set_opt(easy, CERTIFIER_OPT_CFG_FILENAME, libcertifier_cfg);
        int error_code = certifier_load_cfg_file(certifier_get_sertifier_instance(easy));
        if (error_code)
        {
            log_error("[FATAL] Failed to load config file %s.\n", libcertifier_cfg);
            goto cleanup;
        }
    }
    else if (libcertifier_cfg)
        {
            log_error("[FATAL] File %s does not exist.\n", libcertifier_cfg);
            goto cleanup;
        }
    return easy;
cleanup:
    certifier_api_easy_destroy(easy);
    return NULL;
}

void certifier_api_easy_destroy(CERTIFIER *easy) {
    if (easy != NULL) {
        certifier_destroy(easy->certifier);
        free_easy_info(&easy->last_info);
    }

    XFREE(easy);
}

void certifier_api_easy_set_is_client(CERTIFIER *easy, bool is_app) {
    easy->is_client_app = is_app;
}

void *certifier_api_easy_get_opt(CERTIFIER *easy, CERTIFIER_OPT option) {
    if(!easy)
        return NULL;

    return certifier_get_property(easy->certifier, option);
}

int certifier_api_easy_set_opt(CERTIFIER *easy, CERTIFIER_OPT option, void *value) {
    NULL_CHECK(easy);

    return certifier_set_property(easy->certifier, option, value);
}

int certifier_api_easy_set_mode(CERTIFIER *easy, CERTIFIER_MODE local_mode) {
    NULL_CHECK(easy);

    easy->mode = local_mode;
    return 0;
}

const char *certifier_api_easy_get_result_json(CERTIFIER *easy) {
    if (easy == NULL) {
        return NULL;
    }

    return easy->last_info.json;
}

const char *certifier_api_easy_get_result(CERTIFIER *easy) {
    if (easy == NULL) {
        return NULL;
    }

    return easy->last_info.operation_result;
}

int certifier_api_easy_set_cli_args(CERTIFIER *easy, int argc, char **argv) {
    NULL_CHECK(easy);

    int rc = 0;

    if (argc < 0) {
        log_error("argc invalid");
        rc = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
    } else if (argc != 0) {
        if (argv == NULL) {
            log_error("argc nonzero but argv is NULL");
            return CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        } else if (argv[argc] != NULL) {
            log_error("argv not NULL terminated");
            return (CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1);
        } else {
            easy->argc = argc;
            easy->argv = argv;
        }
    } else {
        easy->argc = 0;
        easy->argv = NULL;
    }

    return rc;
}

/**
 * Collect the last operation info and clean up
 * @param easy
 * @param return_code
 * @param operation_output Any output to include with certifier_api_easy_get_info (e.g., a generated CRT)
 * @note 'operation_output' is copied and can be safely discarded after calling this.
 */
static void finish_operation(CERTIFIER *easy, int return_code, const char *operation_output) {
    if (easy == NULL) {
        return;
    }

    free_easy_info(&easy->last_info);
    easy->last_info.json = certifier_create_info(easy->certifier, return_code, operation_output);
    easy->last_info.error_code = return_code;

    if (operation_output != NULL) {
        easy->last_info.operation_result = XSTRDUP(operation_output);
    }
}

static int auto_renew_cert(CERTIFIER *easy) {
    NULL_CHECK(easy);

    int registration_mode = CERTIFIER_DEVICE_REGISTRATION;

    if (easy->is_client_app) {
        registration_mode = CERTIFIER_APP_REGISTRATION;
    }

    return certifier_register(easy->certifier, registration_mode);
}

static int do_create_x509_crt(CERTIFIER *easy) {
    int return_code = 0;

    char *tmp_crt = NULL;

    return_code = auto_renew_cert(easy);
    if (return_code) {
        return_code = CERTIFIER_ERR_CREATE_X509_CERT_1 + return_code;
        goto cleanup;
    }

    return_code = certifier_setup_keys(easy->certifier);
    if (return_code) {
        return_code = CERTIFIER_ERR_CREATE_X509_CERT_2 + return_code;
        goto cleanup;
    }

    return_code = certifier_create_x509_crt(easy->certifier, &tmp_crt);
    if (return_code) {
        log_error("Received an error code: <%i> while calling certifier_create_x509_crt().  Exiting.",
                  return_code);
        if (tmp_crt != NULL) {
            XFREE(tmp_crt);
        }
        goto cleanup;
    } else {
        if (tmp_crt != NULL) {
            const int cert_len = (int) XSTRLEN(tmp_crt);
            char *cert = XMALLOC(base64_encode_len(cert_len));
            base64_encode(cert, (const unsigned char *) tmp_crt, cert_len);

            finish_operation(easy, return_code, cert);

            XFREE(cert);
            XFREE(tmp_crt);
            return return_code;
        }
    }

    cleanup:
    
    safe_exit(easy, return_code);

    return return_code;
}

/**
 * Create a Certificate Request Token by wrapping the value in CERTIFIER_OPT_AUTH_TOKEN.
 * @note This will automatically set CERTIFIER_OPT_CRT.
 * @param outputbuf Any error messages
 * @param crt the CRT; caller must free
 * @return an error code if a CRT cannot be created with the current configuration.
 */
static int do_create_crt(CERTIFIER *easy) {
    int return_code = 0;

    char *crt = NULL;
    char *tmp_crt = NULL;
    char *crt_type = certifier_get_property(easy->certifier, CERTIFIER_OPT_CRT_TYPE);

    if (util_is_empty(crt_type)) {
        return_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        log_error("certifier opt type parameter was not set.",
                  return_code);
        safe_exit(easy, return_code);
        goto cleanup;
    }

    if (XSTRCMP(crt_type, "X509") == 0) {
        return do_create_x509_crt(easy);
    }

    return_code = certifier_create_crt(easy->certifier, &tmp_crt, crt_type);

    if (return_code) {
        log_error("Received an error code: <%i> while calling certifier_create_crt().  Exiting.",
                  return_code);
        safe_exit(easy, return_code);
        goto cleanup;
    } else {
        if (tmp_crt != NULL) {
            log_info("Successfully called certifier_create_crt()!");
            int crt_len = (int) XSTRLEN(tmp_crt);
            crt = XMALLOC(base64_encode_len(crt_len));
            if (crt == NULL) {
                log_error("Could not allocate enough memory for CRT!");
                return_code = CERTIFIER_ERR_CREATE_CRT_6;
                safe_exit(easy, return_code);
                goto cleanup;
            }
            base64_encode(crt, (unsigned char *) tmp_crt, crt_len);
            return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_CRT, crt);
            if (return_code != 0) {
                log_error("Received return_code %i from setting property CERTIFIER_OPT_CRT", return_code);
                safe_exit(easy, return_code);
            } else {
                finish_operation(easy, return_code, crt);
                goto cleanup;
            }
        }

        cleanup:
        if (tmp_crt != NULL) {
            XFREE(tmp_crt);
        }
        if (crt != NULL) {
            XFREE(crt);
        }
    }
    return return_code;
}

static int do_create_node_address(CERTIFIER *easy) {

    int return_code = 0;
    char *node_address = NULL;

    const char *output_node = certifier_get_property(easy->certifier, CERTIFIER_OPT_OUTPUT_NODE);

    if (util_is_empty(output_node)) {
        log_warn("No Output Node was set..");
        return_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        goto cleanup;
    }

    return_code = certifier_create_node_address((const unsigned char *) output_node,
                                                XSTRLEN(output_node), &node_address);
    if (return_code != 0) {
        log_info("Failed called certifier_create_node_address with code: %i", return_code);
        goto cleanup;
    }

    log_info("Successfully called certifier_create_node_address!");

    cleanup:
    finish_operation(easy, return_code, node_address);
    XFREE(node_address);

    return return_code;
}


static int do_app_registration(CERTIFIER *easy) {

    int return_code = 0;

    if (util_is_empty(certifier_get_property(easy->certifier, CERTIFIER_OPT_AUTH_TOKEN))) {
        log_warn("No Auth Token was set..");
        return_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        safe_exit(easy, return_code);
        return return_code;
    }

    return_code = do_create_crt(easy);
    if (return_code != 0) {
        log_error("An error occurred while attempting to create a CRT.");
        safe_exit(easy, return_code);
        return return_code;
    }

    return return_code;
}

static int do_registration(CERTIFIER *easy) {
    int return_code = 0;
    int registration_mode;
    const char *certifier_id = NULL;

    if (easy->is_client_app) {
        return_code = do_app_registration(easy);
        if (return_code != 0) {
            return return_code;
        }
        registration_mode = CERTIFIER_APP_REGISTRATION;
    } else {
        registration_mode = CERTIFIER_DEVICE_REGISTRATION;
    }

    log_info("Calling certifier_register_device()");
    return_code = certifier_register(easy->certifier, registration_mode);

    if (return_code != 0) {
        log_error("Received an error code: <%i> while calling certifier_register_device().  Exiting.",
                  return_code);

    } else {
        certifier_id = certifier_get_node_address(easy->certifier);
        if (!util_is_empty(certifier_id)) {
            log_info("The device has been registered!  Node ID is: %s", certifier_id);
        } else {
            log_error("The device FAILED to register.  No Node ID was returned!");
            return_code = CERTIFIER_ERR_REGISTER_UNKNOWN;
        }
        log_info("The device has been registered!  Node ID is: %s", certifier_id);
    }
    finish_operation(easy, return_code, certifier_id);
    return return_code;
}

static int do_get_cert_status(CERTIFIER *easy) {
    int return_code = 0;
    const char *certifier_id = NULL;

    return_code = certifier_get_device_registration_status(easy->certifier);
    if (return_code == 0) {
        certifier_id = certifier_get_node_address(easy->certifier);
    } else {
        return_code = CERTIFIER_ERR_GET_CERT_STATUS_1 + return_code;
    }

    finish_operation(easy, return_code, certifier_id);

    return return_code;

}

static int do_renew_cert(CERTIFIER *easy) {
    int return_code = 0;
    const char *certifier_id = NULL;

    return_code = auto_renew_cert(easy);

    if (return_code == 0) {
        certifier_id = certifier_get_node_address(easy->certifier);
    } else {
        return_code = CERTIFIER_ERR_RENEW_CERT_1 + return_code;
    }

    finish_operation(easy, return_code, certifier_id);

    return return_code;
}

static int do_print_cert(CERTIFIER *easy) {
    int return_code = 0;
    char *pem = NULL;

    return_code = auto_renew_cert(easy);
    if (return_code) {
        return_code = CERTIFIER_ERR_PRINT_CERT_1 + return_code;
        goto cleanup;
    }

    return_code = certifier_setup_keys(easy->certifier);

    if (return_code) {
        return_code = CERTIFIER_ERR_PRINT_CERT_2 + return_code;
        goto cleanup;
    }

    pem = certifier_get_x509_pem(easy->certifier);

    if (pem == NULL) {
        return_code = CERTIFIER_ERR_PRINT_CERT_4;
        goto cleanup;
    }

    cleanup:

    finish_operation(easy, return_code, pem);

    XFREE(pem);

    return return_code;
}

char *certifier_api_easy_get_version(CERTIFIER *easy) {
    if (easy == NULL) {
        return NULL;
    }

    return certifier_get_version(easy->certifier);
}

const char *certifier_api_easy_get_node_address(CERTIFIER *easy) {
    if (easy == NULL) {
        return NULL;
    }

    return certifier_get_node_address(easy->certifier);
}


static CERTIFIER_OPT parse_CERTIFIER_OPT(char *str) {
    if (XSTRCMP("CERTIFIER_OPT_CFG_FILENAME", str) == 0) return CERTIFIER_OPT_CFG_FILENAME;
    else if (XSTRCMP("CERTIFIER_OPT_CERTIFIER_URL", str) == 0) return CERTIFIER_OPT_CERTIFIER_URL;
    else if (XSTRCMP("CERTIFIER_OPT_HTTP_TIMEOUT", str) == 0) return CERTIFIER_OPT_HTTP_TIMEOUT;
    else if (XSTRCMP("CERTIFIER_OPT_HTTP_CONNECT_TIMEOUT", str) == 0) return CERTIFIER_OPT_HTTP_CONNECT_TIMEOUT;
    else if (XSTRCMP("CERTIFIER_OPT_P12_FILENAME", str) == 0) return CERTIFIER_OPT_KEYSTORE;
    else if (XSTRCMP("CERTIFIER_OPT_PASSWORD", str) == 0) return CERTIFIER_OPT_PASSWORD;
    else if (XSTRCMP("CERTIFIER_OPT_CA_INFO", str) == 0) return CERTIFIER_OPT_CA_INFO;
    else if (XSTRCMP("CERTIFIER_OPT_CA_PATH", str) == 0) return CERTIFIER_OPT_CA_PATH;
    else if (XSTRCMP("CERTIFIER_OPT_CRT", str) == 0) return CERTIFIER_OPT_CRT;
    else if (XSTRCMP("CERTIFIER_OPT_CRT_TYPE", str) == 0) return CERTIFIER_OPT_CRT_TYPE;
    else if (XSTRCMP("CERTIFIER_OPT_OPTIONS", str) == 0) return CERTIFIER_OPT_OPTIONS;
    else if (XSTRCMP("CERTIFIER_OPT_ECC_CURVE_ID", str) == 0) return CERTIFIER_OPT_ECC_CURVE_ID;
    else if (XSTRCMP("CERTIFIER_OPT_SYSTEM_ID", str) == 0) return CERTIFIER_OPT_SYSTEM_ID;
    else if (XSTRCMP("CERTIFIER_OPT_SIMULATION_CERT_EXP_DATE_BEFORE", str) == 0)
        return CERTIFIER_OPT_SIMULATION_CERT_EXP_DATE_BEFORE;
    else if (XSTRCMP("CERTIFIER_OPT_SIMULATION_CERT_EXP_DATE_AFTER", str) == 0)
        return CERTIFIER_OPT_SIMULATION_CERT_EXP_DATE_AFTER;
    else if (XSTRCMP("CERTIFIER_OPT_ROOT_CA", str) == 0) return CERTIFIER_OPT_ROOT_CA;
    else if (XSTRCMP("CERTIFIER_OPT_INT_CA", str) == 0) return CERTIFIER_OPT_INT_CA;
    else if (XSTRCMP("CERTIFIER_OPT_LOG_FILENAME", str) == 0) return CERTIFIER_OPT_LOG_FILENAME;
    else if (XSTRCMP("CERTIFIER_OPT_LOG_LEVEL", str) == 0) return CERTIFIER_OPT_LOG_LEVEL;
    else if (XSTRCMP("CERTIFIER_OPT_LOG_MAX_SIZE", str) == 0) return CERTIFIER_OPT_LOG_MAX_SIZE;
    else if (XSTRCMP("CERTIFIER_OPT_AUTH_TOKEN", str) == 0) return CERTIFIER_OPT_AUTH_TOKEN;
    else if (XSTRCMP("CERTIFIER_OPT_OUTPUT_NODE", str) == 0) return CERTIFIER_OPT_OUTPUT_NODE;
    else if (XSTRCMP("CERTIFIER_OPT_TARGET_NODE", str) == 0) return CERTIFIER_OPT_TARGET_NODE;
    else if (XSTRCMP("CERTIFIER_OPT_ACTION", str) == 0) return CERTIFIER_OPT_ACTION;
    else if (XSTRCMP("CERTIFIER_OPT_INPUT_NODE", str) == 0) return CERTIFIER_OPT_INPUT_NODE;
    else if (XSTRCMP("CERTIFIER_OPT_SOURCE", str) == 0) return CERTIFIER_OPT_SOURCE;
    else if (XSTRCMP("CERTIFIER_OPT_CN_PREFIX", str) == 0) return CERTIFIER_OPT_CN_PREFIX;
    else if (XSTRCMP("CERTIFIER_OPT_NUM_DAYS", str) == 0) return CERTIFIER_OPT_NUM_DAYS;
    else if (XSTRCMP("CERTIFIER_OPT_EXT_KEY_USAGE", str) == 0) return CERTIFIER_OPT_EXT_KEY_USAGE;
    else return -1;
}

static int process_command_line(CERTIFIER *easy) {
    int return_code = 0;

    if (easy->argc == 0 || easy->argv == NULL) {
        return return_code;
    }

    static const struct option long_opts[] = {
            {"help",           no_argument,       NULL, 'h'},
            {"version",        no_argument,       NULL, 'V'},
            {"remove-pkcs12",  no_argument,       NULL, 'f'},
            {"client",         no_argument,       NULL, 'c'},
            {"pkcs12-password",required_argument, NULL, 'p'},
            {"config",         required_argument, NULL, 'L'},
            {"mode",           required_argument, NULL, 'm'},
            {"crt-type",       required_argument, NULL, 'X'},
            {"crt",            required_argument, NULL, 'T'},
            {"system-id",      required_argument, NULL, 'M'},
            {"auth-token",     required_argument, NULL, 'S'},
            {"output-node",    required_argument, NULL, 'O'},
            {"target-node",    required_argument, NULL, 't'},
            {"action",         required_argument, NULL, 'a'},
            {"input-node",     required_argument, NULL, 'i'},
            {"pkcs12-path",    required_argument, NULL, 'k'},
            {"macaddress",     required_argument, NULL, 'z'},
            {NULL, 0,                             NULL, 0}
    };

    int i = 0;
    char buf1[VERY_LARGE_STRING_SIZE], buf2[VERY_LARGE_STRING_SIZE];
    size_t c1, c2;
    char *arr1[VERY_SMALL_STRING_SIZE] = {0};
    char *arr2[VERY_SMALL_STRING_SIZE] = {0};

    char *version_string = certifier_api_easy_get_version(easy);

    for (;;) {
        int option_index;
        int opt = XGETOPT_LONG(easy->argc, easy->argv, "hVfcp:L:m:T:X:M:S:O:t:D:a:i:k:z:",
                              long_opts, &option_index);

        if (opt == -1 || return_code != 0) {
            break;
        }

        switch (opt) {
            case 'h':
                log_info("%s\nUsage:  certifierUtil [OPTIONS]\n"
                         "--help (-h)\n"
                         "--version (-V)\n"
                         "--overwrite-p12-file (-f)\n"
                         "--client (-c) \n"
                         "--pkcs12-password (-p)\n"
                         "--config [value] (-L)\n"
                         "--mode [integer value] (-m)\n"
                         "--crt [value] (-T)\n"
                         "--crt-type [value] (-X)\n"
                         "--system-id [value] (-M)\n"
                         "--auth-token [value] (-S)\n"
                         "--output-node [value] (-O)\n"
                         "--target-node [value] (-t)\n"
                         "--action [value] (-a)\n"
                         "--input-node [value] (-i)\n"
                         "--pkcs12-path [PKCS12 Path] (-k)\n"
                         "--custom-property [name=value] (-D)\n"
                         "\n",
                         version_string);
                exit(1);
            case 'V':
                if (version_string == NULL) {
                    XPUTS("Error getting version string as it was NULL!");
                } else {
                    XPUTS(version_string);
                }
                XEXIT(0);
            case 'f':
                return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_FORCE_REGISTRATION, (void *) true);
                break;
            case 'p':
                return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_PASSWORD, optarg);
                break;
            case 'L':
                return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_CFG_FILENAME, optarg);
                break;
            case 'm':
                if (optarg == NULL) {
                    break;
                }
                //TODO: these should be symbolic and validated
                easy->mode = XATOI(optarg);
                break;
            case 'c':
                certifier_api_easy_set_is_client(easy, true);
                break;
            case 'T':
                if (optarg == NULL) {
                    break;
                }

                return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_CRT, optarg);

                break;
            case 'X':
                if (optarg == NULL) {
                    break;
                }

                return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_CRT_TYPE, optarg);

                break;
            case 'M':
                return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_SYSTEM_ID, optarg);
                break;
            case 'S':
                if (optarg == NULL) {
                    break;
                }
                return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_AUTH_TOKEN, optarg);

                break;
            case 'O':
                if (optarg == NULL) {
                    break;
                }

                return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_OUTPUT_NODE, optarg);

                break;
            case 'D':
                if (optarg == NULL) {
                    break;
                }

                XSTRNCPY(buf1, optarg,
                        sizeof(buf1) - 1);
                buf1[sizeof(buf1) - 1] = '\0';

                c1 = util_split(buf1, arr1, 20, ',');
                if (c1 > 0) {
                    for (i = 0; i < (int) c1; i++) {
                        XSTRNCPY(buf2, arr1[i],
                                sizeof(buf2) - 1);
                        buf2[sizeof(buf2) - 1] = '\0';

                        c2 = util_split(buf2, arr2, 20, '=');
                        if (c2 == 2) {
                            return_code = certifier_set_property(easy->certifier, parse_CERTIFIER_OPT(arr2[0]),
                                                                 arr2[1]);
                            if (return_code != 0) {
                                break;
                            }

                        }
                    }
                }
                break;
            case 't':
                if (optarg == NULL) {
                    break;
                }

                return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_TARGET_NODE, optarg);

                break;
            case 'a':
                if (optarg == NULL) {
                    break;
                }

                return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_ACTION, optarg);

                break;
            case 'i':
                if (optarg == NULL) {
                    break;
                }

                return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_INPUT_NODE, optarg);

                break;
            case 'k':

                if (optarg == NULL) {
                    break;
                }
                return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_KEYSTORE, optarg);

                break;
            case 'z':
                break;
            case '?':
                /* Case when user enters the command as
                 * $ ./libCertifier -p
                 */
                if (optopt == 'p') {
                    log_info("Missing mandatory password option");
                    return_code = 1;
                    break;
                } else if (optopt == 'L') {
                    log_info("Missing mandatory cfg filename option");
                    return_code = 1;
                    break;
                } else if (optopt == 'T') {
                    log_info("Missing mandatory crt option");
                    return_code = 1;
                    break;
                } else if (optopt == 'X') {
                    log_info("Missing mandatory crt type option");
                    return_code = 1;
                    break;
                } else if (optopt == 'm') {
                    log_info("Missing mandatory Mode option");
                    return_code = 1;
                    break;
                } else if (optopt == 'M') {
                    log_info("Missing mandatory system id option");
                    return_code = 1;
                    break;
                } else if (optopt == 'S') {
                    log_info("Missing mandatory auth token option");
                    return_code = 1;
                    break;
                } else if (optopt == 'O') {
                    log_info("Missing mandatory output node option");
                    return_code = 1;
                    break;
                } else if (optopt == 't') {
                    log_info("Missing mandatory target node option");
                    return_code = 1;
                    break;
                } else if (optopt == 'D') {
                    log_info("Missing mandatory custom property  option");
                    return_code = 1;
                    break;
                } else if (optopt == 'a') {
                    log_info("Missing mandatory action property  option");
                    return_code = 1;
                    break;
                } else if (optopt == 'i') {
                    log_info("Missing mandatory input node property  option");
                    return_code = 1;
                    break;
                } else if (optopt == 'k') {
                    log_info("Missing mandatory keystore property option");
                    return_code = 1;
                    break;
                } else {
                    log_info("Invalid option received");
                    return_code = 1;
                    break;
                }
        }
    }

    XFREE(version_string);
    XOPTIND = 0;
    return return_code;
} /* process_command_line */

int certifier_api_easy_perform(CERTIFIER *easy) {
    NULL_CHECK(easy);

    free_easy_info(&easy->last_info);
    int return_code;


    if (easy->mode == CERTIFIER_MODE_NONE) {
        easy->mode = CERTIFIER_MODE_REGISTER;
    }

    return_code = process_command_line(easy);
    if (return_code != 0) {
        log_error("Received return_code: <%i> while calling process_command_line.  Exiting.", return_code);
        safe_exit(easy, return_code);
        goto cleanup;
    }

    const char *password = certifier_get_property(easy->certifier, CERTIFIER_OPT_PASSWORD);
    if (util_is_empty(password)) {
        return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_PASSWORD, DEFAULT_PASSWORD);
        if (return_code != 0) {
            log_error("Received return_code: <%i> while setting default CERTIFIER_OPT_PASSWORD.  Exiting.",
                      return_code);
            safe_exit(easy, return_code);
            goto cleanup;
        }
        log_info("Default CERTIFIER_OPT_PASSWORD was set.");
    }

    switch (easy->mode) {
        case CERTIFIER_MODE_NONE:
            break;

        case CERTIFIER_MODE_REGISTER:
            do_registration(easy);
            break;

        case CERTIFIER_MODE_CREATE_NODE_ADDRESS:
            do_create_node_address(easy);
            break;

        case CERTIFIER_MODE_CREATE_CRT:
            do_create_crt(easy);
            break;
        case CERTIFIER_MODE_GET_CERT_STATUS:
            do_get_cert_status(easy);
            break;

        case CERTIFIER_MODE_RENEW_CERT:
            do_renew_cert(easy);
            break;

        case CERTIFIER_MODE_PRINT_CERT:
            do_print_cert(easy);
            break;

        default:
            finish_operation(easy, -1, "Invalid mode");
            break;

    }

    cleanup:
    return easy->last_info.error_code;
}

http_response *certifier_api_easy_http_post(const CERTIFIER *easy,
                         const char *url,
                         const char *http_headers[],
                         const char *csr)
{
    return http_post(certifier_easy_api_get_props(certifier_get_sertifier_instance(easy)), url, http_headers, csr);
}


int certifier_api_easy_set_keys_and_node_address(CERTIFIER *easy, ECC_KEY *new_key)
{
    CertifierError rc = {0};
    return certifier_set_keys_and_node_address_with_cn_prefix(certifier_get_sertifier_instance(easy), new_key, NULL, rc);
}

int certifier_api_easy_create_json_csr(CERTIFIER *easy, unsigned char *csr, char *node_address, char **json_csr)
{
    int return_value = 0;
    int free_node_address = 0;
    char *serialized_string = NULL;

    if (json_csr == NULL) {
        return return_value;
    }
    if (!node_address)
    {
        node_address = XMALLOC(SMALL_STRING_SIZE);
        certifier_easy_api_get_node_address(certifier_get_sertifier_instance(easy), node_address);
        free_node_address = 1;
    }

    serialized_string = certifier_create_csr_post_data(
            certifier_easy_api_get_props(certifier_get_sertifier_instance(easy)),
            csr,
            node_address,
            NULL);
    *json_csr = XSTRDUP(serialized_string);

    if (free_node_address)
        XFREE(node_address);
    XFREE(serialized_string);
    return 1;
}

void certifier_api_easy_set_ecc_key(CERTIFIER *easy, const ECC_KEY *key)
{
    _certifier_set_ecc_key(certifier_get_sertifier_instance(easy), key);
}


const ECC_KEY *certifier_api_easy_get_priv_key(CERTIFIER *easy)
{
    return (_certifier_get_privkey(certifier_get_sertifier_instance(easy)));
}
