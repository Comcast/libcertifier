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

#include "certifier/certifier_api_easy.h"
#include "certifier/base64.h"
#include "certifier/certifier.h"
#include "certifier/certifier_api_easy_internal.h"
#include "certifier/certifier_internal.h"
#include "certifier/http.h"
#include "certifier/log.h"
#include "certifier/security.h"
#include "certifier/types.h"
#include "certifier/util.h"
#include "certifier/sectigo_client.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// Defines
#define DEFAULT_PASSWORD "changeit"
#define VERY_SMALL_STRING_SIZE 32
#define SMALL_STRING_SIZE 64
#define VERY_LARGE_STRING_SIZE 2048

#define PRODUCT_ID_LENGTH 4ul
#define CASE_AUTH_TAG_LENGTH 8ul
#define NODE_ID_LENGTH 16ul
#define FABRIC_ID_LENGTH 16ul

#define MAX_PKCS12_PASSWORD_LENGTH 32

#define NULL_CHECK(p)                                                                                                              \
    if (p == NULL)                                                                                                                 \
    return CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1

#define safe_exit(le, rc) finish_operation(le, rc, NULL)

#define BASE_SHORT_OPTIONS "hp:L:k:vm"
#define GET_CRT_TOKEN_SHORT_OPTIONS "X:S:"
#define GET_CERT_SHORT_OPTIONS "fT:P:o:i:n:F:a:w:"
#define VALIDITY_DAYS_SHORT_OPTION "t:"
#define CA_PATH_SHORT_OPTION "c:"
#define SECTIGO_GET_CERT_SHORT_OPTIONS "C:I:e:s:N:r:b:A:x:K:u:G:E:O:J:Z:U:T:l:W:S:h"

#define BASE_LONG_OPTIONS                                                                                                          \
    { "help", no_argument, NULL, 'h' }, { "input-p12-path", required_argument, NULL, 'k' },                                        \
        { "input-p12-password", required_argument, NULL, 'p' }, { "key-xchange-mode", no_argument, NULL, 'm' },                    \
        { "config", required_argument, NULL, 'L' },                                                                                \
    {                                                                                                                              \
        "verbose", no_argument, NULL, 'v'                                                                                          \
    }

#define GET_CRT_TOKEN_LONG_OPTIONS                                                                                                 \
    { "auth-type", required_argument, NULL, 'X' },                                                                                 \
    {                                                                                                                              \
        "auth-token", required_argument, NULL, 'S'                                                                                 \
    }

#define GET_CERT_LONG_OPTIONS                                                                                                      \
    { "overwrite-p12", no_argument, NULL, 'f' }, { "crt", required_argument, NULL, 'T' },                                          \
        { "profile-name", required_argument, NULL, 'P' }, { "output-p12-path", required_argument, NULL, 'o' },                     \
        { "output-p12-password", required_argument, NULL, 'w' }, { "product-id", required_argument, NULL, 'i' },                   \
        { "node-id", required_argument, NULL, 'n' }, { "fabric-id", required_argument, NULL, 'F' },                                \
    {                                                                                                                              \
        "case-auth-tag", required_argument, NULL, 'a'                                                                              \
    }

#define VALIDITY_DAYS_LONG_OPTION                                                                                                  \
    {                                                                                                                              \
        "validity-days", required_argument, NULL, 't'                                                                              \
    }

#define CA_PATH_LONG_OPTION                                                                                                        \
    {                                                                                                                              \
        "ca-path", required_argument, NULL, 'c'                                                                                    \
    }

#define SECTIGO_GET_CERT_LONG_OPTIONS                                                                                              \
    { "common-name", required_argument, NULL, 'C' }, \
    { "id", required_argument, NULL, 'I' }, \
    { "employee-type", required_argument, NULL, 'e' }, \
    { "server-platform", required_argument, NULL, 's' }, \
    { "sensitive", no_argument, NULL, 'N' }, \
    { "project-name", required_argument, NULL, 'r' }, \
    { "business-justification", required_argument, NULL, 'b' }, \
    { "subject-alt-names", required_argument, NULL, 'A' }, \
    { "ip-addresses", required_argument, NULL, 'x' }, \
    {"url", required_argument, NULL, 'u'}, \
    { "auth-token", required_argument, NULL, 'K' }, \
    { "group-name", required_argument, NULL, 'G' }, \
    { "group-email", required_argument, NULL, 'E' }, \
    { "owner-fname", required_argument, NULL, 'O' }, \
    { "owner-lname", required_argument, NULL, 'J' }, \
    { "owner-email", required_argument, NULL, 'Z' }, \
    { "owner-phonenum", required_argument, NULL, 'U' }, \
    { "cert-type", required_argument, NULL, 'T' }, \
    { "config", required_argument, NULL, 'l' }, \
    { "tracking-id", required_argument, NULL, 'W' }, \
    { NULL, 0, NULL, 0 }
    //make default arg '*' for san and ip 
    //only take in choices=['fte', 'contractor', 'associate']
    
static void finish_operation(CERTIFIER * easy, int return_code, const char * operation_output);

// Private data

typedef struct CERTIFIERInfo
{
    char * json;
    char * operation_result;
    int error_code;
} CERTIFIERInfo;

struct CERTIFIER
{
    Certifier * certifier;
    CERTIFIER_MODE mode;
    int argc;
    char ** argv;
    CERTIFIERInfo last_info;
    key_exchange_t key_exchange;
};

typedef struct
{
    CERTIFIER_MODE mode;
    const char * short_opts;
    const struct option * long_opts;
} command_opt_lut_t;

static size_t get_command_opt_index(command_opt_lut_t * command_opt_lut, size_t n_entries, CERTIFIER_MODE mode)
{
    for (size_t i = 0; i < n_entries; ++i)
    {
        if ((mode & command_opt_lut[i].mode) == command_opt_lut[i].mode)
        {
            return i;
        }
    }
    return -1;
}

static const char * get_command_opt_helper(CERTIFIER_MODE mode)
{
#define BASE_HELPER                                                                                                                \
    "Usage:  certifierUtil %s [OPTIONS]\n"                                                                                         \
    "--help (-h)\n"                                                                                                                \
    "--input-p12-path [PKCS12 Path] (-k)\n"                                                                                        \
    "--input-p12-password (-p)\n"                                                                                                  \
    "--key-xchange-mode (-m)\n"                                                                                                    \
    "--config [value] (-L)\n"                                                                                                      \
    "--verbose (-v)\n"

#define GET_CRT_TOKEN_HELPER                                                                                                       \
    "--auth-type [value] (-X)\n"                                                                                                   \
    "--auth-token [value] (-S)\n"

#define GET_CERT_HELPER                                                                                                            \
    "--crt [value] (-T)\n"                                                                                                         \
    "--overwrite-p12 (-f)\n"                                                                                                       \
    "--profile-name (-P)\n"                                                                                                        \
    "--output-p12-path (-o)\n"                                                                                                     \
    "--output-p12-password (-w)\n"                                                                                                 \
    "--product-id (-i)\n"                                                                                                          \
    "--node-id (-n)\n"                                                                                                             \
    "--fabric-id (-F)\n"                                                                                                           \
    "--case-auth-tag (-a)\n"

#define VALIDITY_DAYS_HELPER "--validity-days (-t)\n"

#define CA_PATH_HELPER "--ca-path (-c)\n"

    switch (mode)
    {
    case CERTIFIER_MODE_REGISTER:
        return BASE_HELPER GET_CRT_TOKEN_HELPER GET_CERT_HELPER VALIDITY_DAYS_HELPER CA_PATH_HELPER;
    case CERTIFIER_MODE_CREATE_CRT:
        return BASE_HELPER GET_CRT_TOKEN_HELPER;
    case CERTIFIER_MODE_GET_CERT_STATUS:
        return BASE_HELPER CA_PATH_HELPER;
    case CERTIFIER_MODE_RENEW_CERT:
        return BASE_HELPER CA_PATH_HELPER;
    case CERTIFIER_MODE_PRINT_CERT:
        return BASE_HELPER;
    case CERTIFIER_MODE_REVOKE_CERT:
        return BASE_HELPER CA_PATH_HELPER;
    default:
        return "";
    }
}

static void free_easy_info(CERTIFIERInfo * info)
{
    XFREE(info->json);
    XFREE(info->operation_result);
    info->json             = NULL;
    info->operation_result = NULL;
    info->error_code       = 0;
}

CERTIFIER * certifier_api_easy_new(void)
{
    CERTIFIER * easy = NULL;

    Certifier * certifier = certifier_new();
    if (certifier == NULL)
    {
        log_error("Received a null certifier.");
        return NULL;
    }
    easy = XCALLOC(1, sizeof(CERTIFIER));
    if (easy == NULL)
    {
        log_error("Could not allocate enough memory to allocate a new Certifier");
        certifier_destroy(certifier);
        return NULL;
    }
    easy->certifier    = certifier;
    easy->mode         = CERTIFIER_MODE_REGISTER;
    easy->key_exchange = NULL;
    return easy;
}

void certifier_set_key_exchange_method(CERTIFIER * easy, key_exchange_t key_exchange)
{
    easy->key_exchange = key_exchange;
}

/**
 * Get Certifier instance
 * @param easy
 * @return certifier instance
 */
static Certifier * certifier_get_certifier_instance(const CERTIFIER * easy)
{
    return easy->certifier;
}

CERTIFIER * certifier_api_easy_new_cfg(char * libcertifier_cfg)
{
    CERTIFIER * easy = NULL;
    easy             = certifier_api_easy_new();
    if (util_file_exists(libcertifier_cfg))
    {
        certifier_api_easy_set_opt(easy, CERTIFIER_OPT_CFG_FILENAME, libcertifier_cfg);
        int error_code = certifier_load_cfg_file(certifier_get_certifier_instance(easy));
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

void certifier_api_easy_destroy(CERTIFIER * easy)
{
    if (easy != NULL)
    {
        certifier_destroy(easy->certifier);
        free_easy_info(&easy->last_info);
    }

    XFREE(easy);
}

void * certifier_api_easy_get_opt(CERTIFIER * easy, CERTIFIER_OPT option)
{
    if (!easy)
        return NULL;

    return certifier_get_property(easy->certifier, option);
}

int certifier_api_easy_set_opt(CERTIFIER * easy, CERTIFIER_OPT option, void * value)
{
    NULL_CHECK(easy);

    return certifier_set_property(easy->certifier, option, value);
}

CERTIFIER_MODE certifier_api_easy_get_mode(CERTIFIER * easy)
{
    if (!easy)
    {
        return CERTIFIER_MODE_NONE;
    }

    if (easy->argc <= 1 && easy->argv[1] == NULL)
    {
        return CERTIFIER_MODE_NONE;
    }

    typedef struct
    {
        char * name;
        CERTIFIER_MODE mode;
    } command_map_t;

    command_map_t command_map[] = {
        { "help", CERTIFIER_MODE_PRINT_HELP },
        { "version", CERTIFIER_MODE_PRINT_VER },
        { "get-cert", CERTIFIER_MODE_REGISTER },
        { "get-crt-token", CERTIFIER_MODE_CREATE_CRT },
        { "get-cert-status", CERTIFIER_MODE_GET_CERT_STATUS },
        { "renew-cert", CERTIFIER_MODE_RENEW_CERT },
        { "print-cert", CERTIFIER_MODE_PRINT_CERT },
        { "revoke", CERTIFIER_MODE_REVOKE_CERT },
        { "sectigo-get-cert", CERTIFIER_MODE_SECTIGO_GET_CERT}
    };

    for (int i = 0; i < sizeof(command_map) / sizeof(command_map_t); ++i)
    {
        if (strcmp(easy->argv[1], command_map[i].name) == 0)
        {
            easy->argc = easy->argc - 1;
            easy->argv = &easy->argv[1];
            return command_map[i].mode;
        }
    }

    return CERTIFIER_MODE_NONE;
}

int certifier_api_easy_set_mode(CERTIFIER * easy, CERTIFIER_MODE local_mode)
{
    NULL_CHECK(easy);

    if (easy->mode == CERTIFIER_MODE_NONE)
    {
        return 1;
    }

    easy->mode = local_mode;

    return 0;
}

const char * certifier_api_easy_get_result_json(CERTIFIER * easy)
{
    if (easy == NULL)
    {
        return NULL;
    }

    return easy->last_info.json;
}

const char * certifier_api_easy_get_result(CERTIFIER * easy)
{
    if (easy == NULL)
    {
        return NULL;
    }

    return easy->last_info.operation_result;
}

int certifier_api_easy_set_cli_args(CERTIFIER * easy, int argc, char ** argv)
{
    NULL_CHECK(easy);

    int rc = 0;

    if (argc < 0)
    {
        log_error("argc invalid");
        rc = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
    }
    else if (argc != 0)
    {
        if (argv == NULL)
        {
            log_error("argc nonzero but argv is NULL");
            return CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        }
        else if (argv[argc] != NULL)
        {
            log_error("argv not NULL terminated");
            return (CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1);
        }
        else
        {
            easy->argc = argc;
            easy->argv = argv;
        }
    }
    else
    {
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
static void finish_operation(CERTIFIER * easy, int return_code, const char * operation_output)
{
    if (easy == NULL)
    {
        return;
    }

    free_easy_info(&easy->last_info);
    easy->last_info.json       = certifier_create_info(easy->certifier, return_code, operation_output);
    easy->last_info.error_code = return_code;

    if (operation_output != NULL)
    {
        easy->last_info.operation_result = XSTRDUP(operation_output);
    }
}

static int do_create_x509_crt(CERTIFIER * easy)
{
    int return_code = 0;

    char * tmp_crt = NULL;

    return_code = certifier_setup_keys(easy->certifier);
    if (return_code)
    {
        return_code = CERTIFIER_ERR_CREATE_X509_CERT_2 + return_code;
        goto cleanup;
    }

    return_code = certifier_create_x509_crt(easy->certifier, &tmp_crt);
    if (return_code)
    {
        log_error("Received an error code: <%i> while calling certifier_create_x509_crt().  Exiting.", return_code);
        if (tmp_crt != NULL)
        {
            XFREE(tmp_crt);
        }
        goto cleanup;
    }
    else
    {
        if (tmp_crt != NULL)
        {
            const int cert_len = (int) XSTRLEN(tmp_crt);
            char * cert        = XMALLOC(base64_encode_len(cert_len));
            base64_encode(cert, (const unsigned char *) tmp_crt, cert_len);
            return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_CRT, cert);
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
static int do_create_crt(CERTIFIER * easy)
{
    int return_code = 0;

    char * crt      = NULL;
    char * tmp_crt  = NULL;
    char * crt_type = certifier_get_property(easy->certifier, CERTIFIER_OPT_AUTH_TYPE);

    if (util_is_empty(crt_type))
    {
        return_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        log_error("certifier opt type parameter was not set. Received error code: <%i>", return_code);
        safe_exit(easy, return_code);
        goto cleanup;
    }

    if (XSTRCMP(crt_type, "X509") == 0)
    {
        return do_create_x509_crt(easy);
    }

    return_code = certifier_create_crt(easy->certifier, &tmp_crt, crt_type);

    if (return_code)
    {
        log_error("Received an error code: <%i> while calling certifier_create_crt().  Exiting.", return_code);
        safe_exit(easy, return_code);
        goto cleanup;
    }
    else
    {
        if (tmp_crt != NULL)
        {
            log_info("Successfully called certifier_create_crt()!");
            int crt_len = (int) XSTRLEN(tmp_crt);
            crt         = XMALLOC(base64_encode_len(crt_len));
            if (crt == NULL)
            {
                log_error("Could not allocate enough memory for CRT!");
                return_code = CERTIFIER_ERR_CREATE_CRT_6;
                safe_exit(easy, return_code);
                goto cleanup;
            }
            base64_encode(crt, (unsigned char *) tmp_crt, crt_len);
            return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_CRT, crt);
            if (return_code != 0)
            {
                log_error("Received return_code %i from setting property CERTIFIER_OPT_CRT", return_code);
                safe_exit(easy, return_code);
            }
            else
            {
                finish_operation(easy, return_code, crt);
                goto cleanup;
            }
        }

    cleanup:
        if (tmp_crt != NULL)
        {
            XFREE(tmp_crt);
        }
        if (crt != NULL)
        {
            XFREE(crt);
        }
    }
    return return_code;
}

static int do_create_node_address(CERTIFIER * easy)
{

    int return_code     = 0;
    char * node_address = NULL;

    const char * output_node = certifier_get_property(easy->certifier, CERTIFIER_OPT_OUTPUT_NODE);

    if (util_is_empty(output_node))
    {
        log_warn("No Output Node was set..");
        return_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        goto cleanup;
    }

    return_code = certifier_create_node_address((const unsigned char *) output_node, XSTRLEN(output_node), &node_address);
    if (return_code != 0)
    {
        log_info("Failed called certifier_create_node_address with code: %i", return_code);
        goto cleanup;
    }

    log_info("Successfully called certifier_create_node_address!");

cleanup:
    finish_operation(easy, return_code, node_address);
    XFREE(node_address);

    return return_code;
}

static int do_registration(CERTIFIER * easy)
{
    int return_code           = 0;
    const char * certifier_id = NULL;

    log_info("Calling certifier_register_device()");
    return_code = certifier_register(easy->certifier);

    if (return_code != 0)
    {
        log_error("Received an error code: <%i> while calling certifier_register_device().  Exiting.", return_code);
    }
    else
    {
        certifier_id = certifier_get_node_address(easy->certifier);
        if (!util_is_empty(certifier_id))
        {
            log_info("The device has been registered!  Node ID is: %s", certifier_id);
        }
        else
        {
            log_error("The device FAILED to register.  No Node ID was returned!");
            return_code = CERTIFIER_ERR_REGISTER_UNKNOWN;
        }
        log_info("The device has been registered!  Node ID is: %s", certifier_id);
    }
    finish_operation(easy, return_code, certifier_id);
    return return_code;
}

static int do_revoke(CERTIFIER * easy)
{
    int return_code           = 0;
    const char * certifier_id = NULL;

    return_code = certifier_revoke_certificate(easy->certifier);
    if (return_code != 0)
    {
        return_code = CERTIFIER_ERR_REVOKE_CERT_STATUS_1 + return_code;
    }
    else
    {
        certifier_id = certifier_get_node_address(easy->certifier);
    }

    finish_operation(easy, return_code, certifier_id);

    return return_code;
}

static int do_get_cert_status(CERTIFIER * easy)
{
    int return_code           = 0;
    const char * certifier_id = NULL;

    return_code = certifier_get_device_certificate_status(easy->certifier);
    if (return_code != 0 && return_code != CERTIFIER_ERR_REGISTRATION_STATUS_CERT_ABOUT_TO_EXPIRE)
    {
        return_code |= CERTIFIER_ERR_GET_CERT_STATUS_1;
    }
    else
    {
        return_code |= certifier_get_device_registration_status(easy->certifier);
        certifier_print_certificate_validity(easy->certifier);
        if (return_code == 0)
        {
            certifier_id = certifier_get_node_address(easy->certifier);
        }
        else
        {
            return_code |= CERTIFIER_ERR_GET_CERT_STATUS_1;
        }
    }

    switch (return_code)
    {
    case CERTIFIER_ERR_GET_CERT_STATUS_1 | CERTIFIER_ERR_REGISTRATION_STATUS_CERT_ABOUT_TO_EXPIRE:
        XFPRINTF(stdout, "Warning! This certificate is about to expire. Please renew it using the 'renew-cert' command.\n");
        // fall through
    case 0:
        XFPRINTF(stdout, "Status: Valid\n");
        break;
    case CERTIFIER_ERR_GET_CERT_STATUS_1 | CERTIFIER_ERR_REGISTRATION_STATUS_CERT_EXPIRED_2:
        XFPRINTF(stdout, "Status: Expired\n");
        break;
    case CERTIFIER_ERR_GET_CERT_STATUS_1 | CERTIFIER_ERR_REGISTRATION_STATUS_CERT_EXPIRED_1:
        XFPRINTF(stdout, "Status: Not Yet Valid\n");
        break;
    case CERTIFIER_ERR_GET_CERT_STATUS_1 | CERTIFIER_ERR_GET_CERT_STATUS_REVOKED:
        XFPRINTF(stdout, "Status: Revoked\n");
        break;
    case CERTIFIER_ERR_GET_CERT_STATUS_1 | CERTIFIER_ERR_GET_CERT_STATUS_UNKNOWN |
        CERTIFIER_ERR_REGISTRATION_STATUS_CERT_ABOUT_TO_EXPIRE:
        XFPRINTF(stdout, "Warning! This certificate is about to expire. Please renew it using the 'renew-cert' command.\n");
        // fall through
    case CERTIFIER_ERR_GET_CERT_STATUS_1 | CERTIFIER_ERR_GET_CERT_STATUS_UNKNOWN:
    default:
        XFPRINTF(stdout, "Status: Unknown\n");
        break;
    }

    finish_operation(easy, return_code, certifier_id);

    return return_code;
}

static int do_renew_cert(CERTIFIER * easy)
{
    int return_code           = 0;
    const char * certifier_id = NULL;

    return_code = certifier_get_device_registration_status(easy->certifier);
    if (return_code == CERTIFIER_ERR_REGISTRATION_STATUS_CERT_ABOUT_TO_EXPIRE ||
        return_code == CERTIFIER_ERR_REGISTRATION_STATUS_CERT_EXPIRED_1)
    {
        return_code = do_create_x509_crt(easy);
        return_code |= certifier_renew_certificate(easy->certifier);
    }
    else
    {
        log_error("Certificate has not yet expired and already exists.  Returning.  No need to register again.");
        return_code = CERTIFIER_ERR_RENEW_CERT_1 + CERTIFIER_ERR_GET_CERT_STATUS_GOOD;
    }

    if (return_code == 0)
    {
        certifier_id = certifier_get_node_address(easy->certifier);
    }
    else
    {
        return_code = CERTIFIER_ERR_RENEW_CERT_1 + return_code;
    }

    finish_operation(easy, return_code, certifier_id);

    return return_code;
}

static int do_print_cert(CERTIFIER * easy)
{
    int return_code = 0;
    char * pem      = NULL;

    return_code = certifier_setup_keys(easy->certifier);

    if (return_code)
    {
        return_code = CERTIFIER_ERR_PRINT_CERT_2 + return_code;
        goto cleanup;
    }

    pem = certifier_get_x509_pem(easy->certifier);

    if (pem == NULL)
    {
        return_code = CERTIFIER_ERR_PRINT_CERT_4;
        goto cleanup;
    }

    certifier_print_certificate(easy->certifier, pem, strlen(pem));

cleanup:

    finish_operation(easy, return_code, pem);

    XFREE(pem);

    return return_code;
}

static int do_sectigo_get_cert(CERTIFIER * easy)
{
    int return_code = 0;
    char * csr_pem = NULL;
    char * cert = NULL;

    // Check for required Sectigo properties
    const char *common_name = certifier_get_property(easy->certifier, CERTIFIER_OPT_SECTIGO_COMMON_NAME);
    const char *employee_type = certifier_get_property(easy->certifier, CERTIFIER_OPT_SECTIGO_EMPLOYEE_TYPE);
    const char *server_platform = certifier_get_property(easy->certifier, CERTIFIER_OPT_SECTIGO_SERVER_PLATFORM);
    const char *project_name = certifier_get_property(easy->certifier, CERTIFIER_OPT_SECTIGO_PROJECT_NAME);
    const char *business_justification = certifier_get_property(easy->certifier, CERTIFIER_OPT_SECTIGO_BUSINESS_JUSTIFICATION);

    if (util_is_empty(common_name) || util_is_empty(employee_type) ||
        util_is_empty(server_platform) || util_is_empty(project_name) ||
        util_is_empty(business_justification)) {
        finish_operation(easy, CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1,
            "Missing required Sectigo flags (common-name, employee-type, server-platform, project-name, business-justification)");
        return CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
    }


    return_code = certifier_setup_keys(easy->certifier);
    if (return_code != 0) {
        finish_operation(easy, return_code, NULL);
        return return_code;
    }

    //Generate CSR 
    CertifierError rc = sectigo_generate_certificate_signing_request(easy->certifier, &csr_pem);
    if (rc.application_error_code != 0 || csr_pem == NULL) {
        finish_operation(easy, rc.application_error_code, NULL);
        return rc.application_error_code;
    }
    
    // Call Sectigo client to request certificate
    CertifierPropMap * props = certifier_easy_api_get_props(easy->certifier);
    rc = sectigo_client_request_certificate(props, (unsigned char *)csr_pem, certifier_get_node_address(easy->certifier), NULL, &cert);

    
    XFREE(csr_pem);

    //Handle result
    if (rc.application_error_code == 0 && cert != NULL) {
        finish_operation(easy, 0, cert);
        XFREE(cert);
        return 0;
    } else {
        finish_operation(easy, rc.application_error_code, rc.application_error_msg);
        if (cert) XFREE(cert);
        return rc.application_error_code;
    }
}


char * certifier_api_easy_get_version(CERTIFIER * easy)
{
    if (easy == NULL)
    {
        return NULL;
    }

    return certifier_get_version(easy->certifier);
}

int certifier_api_easy_print_helper(CERTIFIER * easy)
{
    if (easy->mode == CERTIFIER_MODE_PRINT_VER)
    {
        char * version_string = certifier_api_easy_get_version(easy);

        if (version_string == NULL)
        {
            log_error("Error getting version string as it was NULL!\n");
            return 1;
        }

        XFPRINTF(stdout, "%s\n", version_string);

        XFREE(version_string);
    }
    else if (easy->mode == CERTIFIER_MODE_PRINT_HELP || easy->mode == CERTIFIER_MODE_NONE)
    {
        XFPRINTF(stdout,
                 "Usage:  certifierUtil [COMMANDS] [OPTIONS]\n"
                 "Commands:\n"
                 "help\n"
                 "version\n"
                 "get-cert\n"
                 "get-crt-token\n"
                 "get-cert-status\n"
                 "renew-cert\n"
                 "print-cert\n"
                 "revoke\n"
                 "get-sectigo-cert");
    }

    return 0;
}

const char * certifier_api_easy_get_node_address(CERTIFIER * easy)
{
    if (easy == NULL)
    {
        return NULL;
    }

    return certifier_get_node_address(easy->certifier);
}

static bool is_valid_id(const char * id, const size_t id_length)
{
    if (id == NULL)
    {
        return false;
    }

    for (size_t idx = 0; idx < id_length; ++idx)
    {
        if (isxdigit(id[idx]) == 0)
        {
            return false;
        }
    }

    return true;
}

static int process_command_line(CERTIFIER * easy)
{
    int return_code = 0;

    if (easy->argc == 0 || easy->argv == NULL)
    {
        return return_code;
    }

    static const char * const get_cert_short_options =
        BASE_SHORT_OPTIONS GET_CRT_TOKEN_SHORT_OPTIONS GET_CERT_SHORT_OPTIONS VALIDITY_DAYS_SHORT_OPTION CA_PATH_SHORT_OPTION;
    static const char * const get_crt_token_short_options   = BASE_SHORT_OPTIONS GET_CRT_TOKEN_SHORT_OPTIONS;
    static const char * const get_cert_status_short_options = BASE_SHORT_OPTIONS CA_PATH_SHORT_OPTION;
    static const char * const renew_cert_short_options      = BASE_SHORT_OPTIONS CA_PATH_SHORT_OPTION;
    static const char * const print_cert_short_options      = BASE_SHORT_OPTIONS;
    static const char * const revoke_cert_short_options     = BASE_SHORT_OPTIONS;
    static const char * const sectigo_get_cert_short_options      = BASE_SHORT_OPTIONS CA_PATH_SHORT_OPTION;

    static const struct option get_cert_long_opts[]      = { BASE_LONG_OPTIONS,     GET_CRT_TOKEN_LONG_OPTIONS,
                                                             GET_CERT_LONG_OPTIONS, VALIDITY_DAYS_LONG_OPTION,
                                                             CA_PATH_LONG_OPTION,   { NULL, 0, NULL, 0 } };
    static const struct option get_crt_token_long_opts[] = { BASE_LONG_OPTIONS, GET_CRT_TOKEN_LONG_OPTIONS, { NULL, 0, NULL, 0 } };
    static const struct option get_cert_status_long_opts[] = { BASE_LONG_OPTIONS, CA_PATH_LONG_OPTION, { NULL, 0, NULL, 0 } };
    static const struct option renew_cert_long_opts[]      = { BASE_LONG_OPTIONS, CA_PATH_LONG_OPTION, { NULL, 0, NULL, 0 } };
    static const struct option print_cert_long_opts[]      = { BASE_LONG_OPTIONS, { NULL, 0, NULL, 0 } };
    static const struct option revoke_cert_long_opts[]     = { BASE_LONG_OPTIONS, CA_PATH_LONG_OPTION, { NULL, 0, NULL, 0 } };
    static const struct option sectigo_get_cert_long_opts[] = {BASE_LONG_OPTIONS, SECTIGO_GET_CERT_LONG_OPTIONS, {NULL, 0, NULL, 0}};

    static command_opt_lut_t command_opt_lut[] = {
        { CERTIFIER_MODE_REGISTER, get_cert_short_options, get_cert_long_opts },
        { CERTIFIER_MODE_CREATE_CRT, get_crt_token_short_options, get_crt_token_long_opts },
        { CERTIFIER_MODE_GET_CERT_STATUS, get_cert_status_short_options, get_cert_status_long_opts },
        { CERTIFIER_MODE_RENEW_CERT, renew_cert_short_options, renew_cert_long_opts },
        { CERTIFIER_MODE_PRINT_CERT, print_cert_short_options, print_cert_long_opts },
        { CERTIFIER_MODE_REVOKE_CERT, revoke_cert_short_options, revoke_cert_long_opts },
        {CERTIFIER_MODE_SECTIGO_GET_CERT, sectigo_get_cert_short_options, sectigo_get_cert_long_opts}
    };

    char * version_string = certifier_api_easy_get_version(easy);

    char id_array[NODE_ID_LENGTH + 1] = { 0 };
    char * end_id_array               = &id_array[NODE_ID_LENGTH];
    // keep last index as \0. We want this to be a null terminated string.
    memset(id_array, '0', sizeof(id_array) - 1);

    for (;;)
    {
        int command_opt_index =
            get_command_opt_index(command_opt_lut, sizeof(command_opt_lut) / sizeof(*command_opt_lut), easy->mode);
        int option_index;
        int opt = XGETOPT_LONG(easy->argc, easy->argv, command_opt_lut[command_opt_index].short_opts,
                               command_opt_lut[command_opt_index].long_opts, &option_index);

        if (opt == -1 || return_code != 0)
        {
            break;
        }

        switch (opt)
        {
        case 'h':
            XFPRINTF(stdout, get_command_opt_helper(easy->mode), easy->argv[0]);
            exit(1);
        case 'c':
            return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_CA_PATH, optarg);
            break;
        case 'f':
            return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_FORCE_REGISTRATION, (void *) true);
            break;
        case 'p':
            return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_INPUT_P12_PASSWORD, optarg);
            break;
        case 'w':
            return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_OUTPUT_P12_PASSWORD, optarg);
            break;
        case 'Q':
            return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_MTLS_P12_PASSWORD, optarg);
            break;
        case 'L':
            return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_CFG_FILENAME, optarg);
            break;
        case 'T':
            if (optarg == NULL)
            {
                break;
            }

            return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_CRT, optarg);

            break;
        case 'X':
            if (optarg == NULL)
            {
                break;
            }

            return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_AUTH_TYPE, optarg);

            break;
        case 'S':
            if (optarg == NULL)
            {
                break;
            }
            return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_AUTH_TOKEN, optarg);

            break;
        case 'k':
            if (optarg == NULL)
            {
                break;
            }
            return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_INPUT_P12_PATH, optarg);

            break;
        case 'o':
            if (optarg == NULL)
            {
                break;
            }
            return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_OUTPUT_P12_PATH, optarg);

            break;
        case 'q':
            if (optarg == NULL)
            {
                break;
            }
            return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_MTLS_P12_PATH, optarg);

            break;
        case 'P':
            if (optarg == NULL)
            {
                break;
            }
            return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_PROFILE_NAME, optarg);

            break;
        case 'i':
            if (optarg == NULL)
            {
                break;
            }

            if (strlen(optarg) > PRODUCT_ID_LENGTH)
            {
                log_error("Product ID is expected to be a 16-bit hex number");
                return_code = 1;
                break;
            }

            memcpy(end_id_array - strlen(optarg), optarg, strlen(optarg));

            if (is_valid_id(end_id_array - PRODUCT_ID_LENGTH, PRODUCT_ID_LENGTH) == false)
            {
                log_error("Product ID is expected to be a 16-bit hex number");
                return_code = 1;
                break;
            }
            return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_PRODUCT_ID, end_id_array - PRODUCT_ID_LENGTH);

            break;
        case 'n':
            if (optarg == NULL)
            {
                break;
            }

            if (strlen(optarg) > NODE_ID_LENGTH)
            {
                log_error("Node ID is expected to be a 64-bit hex number");
                return_code = 1;
                break;
            }

            memcpy(end_id_array - strlen(optarg), optarg, strlen(optarg));

            if (is_valid_id(end_id_array - NODE_ID_LENGTH, NODE_ID_LENGTH) == false)
            {
                log_error("Node ID is expected to be a 64-bit hex number");
                return_code = 1;
                break;
            }
            return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_NODE_ID, end_id_array - NODE_ID_LENGTH);

            break;
        case 'F':
            if (optarg == NULL)
            {
                break;
            }

            if (strlen(optarg) > FABRIC_ID_LENGTH)
            {
                log_error("Fabric ID is expected to be a 64-bit hex number");
                return_code = 1;
                break;
            }

            memcpy(end_id_array - strlen(optarg), optarg, strlen(optarg));

            if (is_valid_id(end_id_array - FABRIC_ID_LENGTH, FABRIC_ID_LENGTH) == false)
            {
                log_error("Fabric ID is expected to be a 64-bit hex number");
                return_code = 1;
                break;
            }
            return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_FABRIC_ID, end_id_array - FABRIC_ID_LENGTH);

            break;
        case 'a':
            if (optarg == NULL)
            {
                break;
            }

            if (strlen(optarg) > CASE_AUTH_TAG_LENGTH)
            {
                log_error("CASE Authentication Tag is expected to be a 32-bit hex number");
                return_code = 1;
                break;
            }

            memcpy(end_id_array - strlen(optarg), optarg, strlen(optarg));

            if (is_valid_id(end_id_array - CASE_AUTH_TAG_LENGTH, CASE_AUTH_TAG_LENGTH) == false)
            {
                log_error("CASE Authentication Tag is expected to be a 32-bit hex number");
                return_code = 1;
                break;
            }
            return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_AUTH_TAG_1, end_id_array - CASE_AUTH_TAG_LENGTH);

            break;
        case 't':
            if (optarg == NULL)
            {
                break;
            }

            if (atoi(optarg) > 0)
            {
                return_code =
                    certifier_set_property(easy->certifier, CERTIFIER_OPT_VALIDITY_DAYS, (const void *) (size_t) atoi(optarg));
            }
            else
            {
                log_error("Expected input to be of positive integer type");
                return_code = 1;
            }

            break;
        case 'm':
            easy->mode |= CERTIFIER_MODE_KEY_EXCHANGE;
            break;
        case 'v':
            return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_LOG_LEVEL, (void *) (size_t) 0);
            break;
        case 'C': // common-name
        if (optarg) {
        return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_SECTIGO_COMMON_NAME, optarg);
        }
            break;
        case 'I': // id
        if (optarg) {
        return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_SECTIGO_ID, optarg);
        }
            break;
        case 'e': // employee-type
        if (optarg) {
        // Validate allowed values: "fte", "contractor", "associate"
        if (strcmp(optarg, "fte") && strcmp(optarg, "contractor") && strcmp(optarg, "associate")) {
            log_error("Invalid employee-type: %s. Allowed: fte, contractor, associate.", optarg);
            return_code = 1;
            break;
        }
        return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_SECTIGO_EMPLOYEE_TYPE, optarg);
        }
            break;
        case 's': // server-platform
        if (optarg) {
        return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_SECTIGO_SERVER_PLATFORM, optarg);
        }
            break;
        case 'N': // sensitive
        return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_SECTIGO_SENSITIVE, (void *)true);
            break;
        case 'r': // project-name
        if (optarg) {
        return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_SECTIGO_PROJECT_NAME, optarg);
        }
            break;
        case 'b': // business-justification
        if (optarg) {
        return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_SECTIGO_BUSINESS_JUSTIFICATION, optarg);
        }
            break;
        case 'A': // subject-alt-names
        if (optarg) {
        return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_SECTIGO_SUBJECT_ALT_NAMES, optarg);
        }
            break;
        case 'x': // ip-addresses
        if (optarg) {
        return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_SECTIGO_IP_ADDRESSES, optarg);
        }
            break;
        case 'K': // auth-token
        if (optarg) {
        return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_SECTIGO_AUTH_TOKEN, optarg);
        }
            break;
        case 'u': // sectigo url
        if (optarg) {
        return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_SECTIGO_CERTIFIER_URL, optarg);
        }
        case 'G': // group-name
            if (optarg) {
                return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_SECTIGO_GROUP_NAME, optarg);
            }
            break;
        case 'E': // group-email
            if (optarg) {
                return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_SECTIGO_GROUP_EMAIL, optarg);
            }
            break;
        case 'O': // owner-fname
            if (optarg) {
                return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_SECTIGO_OWNER_FNAME, optarg);
            }
            break;
        case 'J': // owner-lname
            if (optarg) {
                return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_SECTIGO_OWNER_LNAME, optarg);
            }
            break;
        case 'M': // owner-email
            if (optarg) {
                return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_SECTIGO_OWNER_EMAIL, optarg);
            }
            break;
        case 'Z': // owner-phonenum
            if (optarg) {
                return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_SECTIGO_OWNER_PHONENUM, optarg);
            }
            break;
        case 'U': // cert-type
            if (optarg) {
                return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_SECTIGO_CERT_TYPE, optarg);
            }
            break;
        case 'Y': //source
            if(optarg){
                return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_SECTIGO_SOURCE, optarg);
            }
        case '?':
            /* Case when user enters the command as
             * $ ./libCertifier -p
             */
            if (optopt == 'p')
            {
                log_info("Missing mandatory password option");
                return_code = 1;
                break;
            }
            else if (optopt == 'L')
            {
                log_info("Missing mandatory cfg filename option");
                return_code = 1;
                break;
            }
            else if (optopt == 'T')
            {
                log_info("Missing mandatory crt option");
                return_code = 1;
                break;
            }
            else if (optopt == 'X')
            {
                log_info("Missing mandatory crt type option");
                return_code = 1;
                break;
            }
            else if (optopt == 'S')
            {
                log_info("Missing mandatory auth token option");
                return_code = 1;
                break;
            }
            else if (optopt == 'D')
            {
                log_info("Missing mandatory custom property  option");
                return_code = 1;
                break;
            }
            else if (optopt == 'k')
            {
                log_info("Missing mandatory keystore property option");
                return_code = 1;
                break;
            }
            else if (optopt == 'P')
            {
                log_info("Missing mandatory Profile Name option");
                return_code = 1;
                break;
            }
            else if (optopt == 'o')
            {
                log_info("Missing mandatory output keystore property option");
                return_code = 1;
                break;
            }
            else if (optopt == 'i')
            {
                log_info("Missing mandatory Product Id option (16-bit hex)");
                return_code = 1;
                break;
            }
            else if (optopt == 'n')
            {
                log_info("Missing mandatory Node Id option (64-bit hex)");
                return_code = 1;
                break;
            }
            else if (optopt == 'F')
            {
                log_info("Missing mandatory Fabric Id option (64-bit hex)");
                return_code = 1;
                break;
            }
            else if (optopt == 'v')
            {
                log_info("Missing mandatory number of validity days");
                return_code = 1;
                break;
            }
            else
            {
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

int certifier_api_easy_perform(CERTIFIER * easy)
{
    NULL_CHECK(easy);

    free_easy_info(&easy->last_info);
    int return_code;
    bool force_registration;
    const char * password = NULL;

    if (easy->mode == CERTIFIER_MODE_NONE || easy->mode == CERTIFIER_MODE_PRINT_VER || easy->mode == CERTIFIER_MODE_PRINT_HELP)
    {
        return certifier_api_easy_print_helper(easy);
    }

    return_code = process_command_line(easy);
    if (return_code != 0)
    {
        log_error("Received return_code: <%i> while calling process_command_line.  Exiting.", return_code);
        safe_exit(easy, return_code);
        goto cleanup;
    }

    if (easy->key_exchange && ((easy->mode & CERTIFIER_MODE_KEY_EXCHANGE) == CERTIFIER_MODE_KEY_EXCHANGE))
    {
        uint8_t pw_in[MAX_PKCS12_PASSWORD_LENGTH];
        uint8_t pw_out[MAX_PKCS12_PASSWORD_LENGTH];

        // revert cast done during certifier_set_property - int storing in property.c needs to be refactored.
        int log_level = (int) (size_t) certifier_get_property(easy->certifier, CERTIFIER_OPT_LOG_LEVEL);

        int error = easy->key_exchange(pw_in, sizeof(pw_in), pw_out, sizeof(pw_out), log_level == 0);

        if (error != 0)
        {
            easy->last_info.error_code = error;
            goto cleanup;
        }

        return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_INPUT_P12_PASSWORD, pw_in);
        if (XSTRLEN((const char *) pw_out) > 0 && pw_out[0] != '\0')
        {
            return_code |= certifier_set_property(easy->certifier, CERTIFIER_OPT_OUTPUT_P12_PASSWORD, pw_out);
        }

        if (return_code != 0)
        {
            log_error("Received return_code: <%i> while setting CERTIFIER_OPT_INPUT_P12_PASSWORD from KeyBarrier. Exiting.",
                      return_code);
            safe_exit(easy, return_code);
            goto cleanup;
        }

        easy->mode &= ~CERTIFIER_MODE_KEY_EXCHANGE;
    }

    if (easy->mode == CERTIFIER_MODE_REGISTER && certifier_get_property(easy->certifier, CERTIFIER_OPT_CRT) == NULL)
    {
        easy->mode = CERTIFIER_MODE_COMBO_REGISTER;
    }

    force_registration = certifier_is_option_set(easy->certifier, CERTIFIER_OPTION_FORCE_REGISTRATION);

    password = certifier_get_property(easy->certifier, CERTIFIER_OPT_INPUT_P12_PASSWORD);
    if (util_is_empty(password))
    {
        return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_INPUT_P12_PASSWORD, DEFAULT_PASSWORD);
        if (return_code != 0)
        {
            log_error("Received return_code: <%i> while setting default CERTIFIER_OPT_INPUT_P12_PASSWORD.  Exiting.", return_code);
            safe_exit(easy, return_code);
            goto cleanup;
        }
        log_info("Default CERTIFIER_OPT_INPUT_P12_PASSWORD was set.");
    }
    if (util_is_empty(certifier_get_property(easy->certifier, CERTIFIER_OPT_OUTPUT_P12_PASSWORD)))
    {
        return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_OUTPUT_P12_PASSWORD, password);
        if (return_code != 0)
        {
            log_error("Received return_code: <%i> while setting CERTIFIER_OPT_OUTPUT_P12_PASSWORD.  Exiting.", return_code);
            safe_exit(easy, return_code);
            goto cleanup;
        }
        log_info("CERTIFIER_OPT_OUTPUT_P12_PASSWORD was set with the same value as the input Password.");
    }

    switch (easy->mode)
    {
    case CERTIFIER_MODE_NONE:
        break;

    case CERTIFIER_MODE_REGISTER: {
        return_code = 0;
        if (certifier_get_property(easy->certifier, CERTIFIER_OPT_OUTPUT_P12_PATH) != NULL)
        {
            return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_INPUT_P12_PATH,
                                                 certifier_get_property(easy->certifier, CERTIFIER_OPT_OUTPUT_P12_PATH));
        }
        return_code |= certifier_set_property(easy->certifier, CERTIFIER_OPT_INPUT_P12_PASSWORD,
                                              certifier_get_property(easy->certifier, CERTIFIER_OPT_OUTPUT_P12_PASSWORD));
        if (return_code != 0)
        {
            log_error("Received return_code: <%i> while setting CERTIFIER_OPT_INPUT_P12_PASSWORD and CERTIFIER_OPT_INPUT_P12_PATH. "
                      " Exiting.",
                      return_code);
            safe_exit(easy, return_code);
            goto cleanup;
        }

        do_registration(easy);
        break;
    }
    case CERTIFIER_MODE_REVOKE_CERT:
        do_create_crt(easy);
        do_revoke(easy);
        break;

    case CERTIFIER_MODE_CREATE_NODE_ADDRESS:
        do_create_node_address(easy);
        break;

    case CERTIFIER_MODE_CREATE_CRT: {
        do_create_crt(easy);
        const char * generated_crt = certifier_get_property(easy->certifier, CERTIFIER_OPT_CRT);
        XFPRINTF(stdout, "%s\n", generated_crt);
        break;
    }
    case CERTIFIER_MODE_COMBO_REGISTER: {
        return_code = 0;

        if (force_registration)
        {
            return_code |= certifier_set_property(easy->certifier, CERTIFIER_OPT_FORCE_REGISTRATION, (void *) false);
            if (return_code != 0)
            {
                log_error("Received return_code: <%i> while setting CERTIFIER_OPT_FORCE_REGISTRATION.  Exiting.", return_code);
                safe_exit(easy, return_code);
                goto cleanup;
            }
        }

        do_create_crt(easy);

        if (certifier_get_property(easy->certifier, CERTIFIER_OPT_OUTPUT_P12_PATH) != NULL)
        {
            return_code |= certifier_set_property(easy->certifier, CERTIFIER_OPT_INPUT_P12_PATH,
                                                  certifier_get_property(easy->certifier, CERTIFIER_OPT_OUTPUT_P12_PATH));
        }
        return_code |= certifier_set_property(easy->certifier, CERTIFIER_OPT_FORCE_REGISTRATION, (void *) force_registration);
        return_code |= certifier_set_property(easy->certifier, CERTIFIER_OPT_INPUT_P12_PASSWORD,
                                              certifier_get_property(easy->certifier, CERTIFIER_OPT_OUTPUT_P12_PASSWORD));
        if (return_code != 0)
        {
            log_error("Received return_code: <%i> while setting CERTIFIER_OPT_INPUT_P12_PASSWORD, CERTIFIER_OPT_INPUT_P12_PATH and "
                      "CERTIFIER_OPT_FORCE_REGISTRATION.  Exiting.",
                      return_code);
            safe_exit(easy, return_code);
            goto cleanup;
        }

        do_registration(easy);
        break;
    }
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

    //For SECTIGO MODE
switch(easy -> mode){
    case CERTIFIER_MODE_NONE:
    break;

    case CERTIFIER_MODE_SECTIGO_GET_CERT:
        do_sectigo_get_cert(easy);
        break;

    default:
        finish_operation(easy, -1, "Invalid mode");
        break;
}

cleanup:
    return easy->last_info.error_code;
}



http_response * certifier_api_easy_http_post(const CERTIFIER * easy, const char * url, const char * http_headers[],
                                             const char * csr)
{
    return http_post(certifier_easy_api_get_props(certifier_get_certifier_instance(easy)), url, http_headers, csr);
}

int certifier_api_easy_set_keys_and_node_address(CERTIFIER * easy, ECC_KEY * new_key)
{
    CertifierError rc = { 0 };
    return certifier_set_keys_and_node_address_with_cn_prefix(certifier_get_certifier_instance(easy), new_key, NULL, rc);
}

int certifier_api_easy_create_json_csr(CERTIFIER * easy, unsigned char * csr, char * node_address, char ** json_csr)
{
    int return_value         = 0;
    int free_node_address    = 0;
    char * serialized_string = NULL;

    if (json_csr == NULL)
    {
        return return_value;
    }
    if (!node_address)
    {
        node_address = XMALLOC(SMALL_STRING_SIZE);
        certifier_easy_api_get_node_address(certifier_get_certifier_instance(easy), node_address);
        free_node_address = 1;
    }

    serialized_string = certifier_create_csr_post_data(certifier_easy_api_get_props(certifier_get_certifier_instance(easy)), csr,
                                                       node_address, NULL);
    *json_csr         = XSTRDUP(serialized_string);

    if (free_node_address)
        XFREE(node_address);
    XFREE(serialized_string);
    return 1;
}

void certifier_api_easy_set_ecc_key(CERTIFIER * easy, const ECC_KEY * key)
{
    _certifier_set_ecc_key(certifier_get_certifier_instance(easy), key);
}

const ECC_KEY * certifier_api_easy_get_priv_key(CERTIFIER * easy)
{
    return (_certifier_get_privkey(certifier_get_certifier_instance(easy)));
}
