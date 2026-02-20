/**
 * Copyright 2024 Comcast Cable Communications Management, LLC
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

#include "certifier/code_utils.h"
#include "certifier/log.h"
#include "certifier/xpki_client.h"
#include "certifier/xpki_client_internal.h"
#include "certifier/sectigo_client.h"
#include "certifier/certifier_api_easy.h"
#include "certifier/certifier_internal.h"
#include "certifier/certifier.h"

typedef enum
{
    XPKI_MODE_NONE = 0,
    XPKI_MODE_PRINT_HELP,
    XPKI_MODE_PRINT_VERSION,
    XPKI_MODE_GET_CERT,
    XPKI_MODE_GET_CERT_STATUS,
    XPKI_MODE_RENEW_CERT,
    XPKI_MODE_PRINT_CERT,
    XPKI_MODE_REVOKE_CERT,
} XPKI_MODE;

typedef enum
{
    SECTIGO_MODE_NONE,
    SECTIGO_MODE_GET_CERT,
    SECTIGO_MODE_SEARCH_CERT,
    SECTIGO_MODE_RENEW_CERT,
    SECTIGO_MODE_REVOKE_CERT,
    SECTIGO_MODE_OCSP_STATUS,
    SECTIGO_MODE_PRINT_HELP
    
} SECTIGO_MODE;

typedef union
{
    get_cert_param_t get_cert_param;
    get_cert_status_param_t get_cert_status_param;
    renew_cert_param_t renew_cert_param;
} xc_parameter_t;

typedef union 
{
  sectigo_get_cert_param_t get_cert_param;
  sectigo_search_cert_param_t search_cert_param;
  sectigo_renew_cert_param_t renew_cert_param;
  sectigo_revoke_cert_param_t revoke_cert_param;  
  sectigo_ocsp_status_param_t ocsp_status_param;
} sectigo_parameter_t;


XPKI_CLIENT_ERROR_CODE process(XPKI_MODE mode, xc_parameter_t * xc_parameter, int argc, char ** argv);
XPKI_CLIENT_ERROR_CODE xpki_perform(int argc, char ** argv);
SECTIGO_CLIENT_ERROR_CODE sectigo_perform(int argc, char ** argv);

int main(int argc, char **argv)
{
     pthread_mutex_init(&lock, NULL);
    // check for "sectigo-get-cert" as the first argument
    if (argc > 1 && strncmp(argv[1], "sectigo", strlen("sectigo")) == 0) {
        // Call Sectigo mode
        return sectigo_perform(argc, argv);
    } else {
        // Default to XPKI mode
        return xpki_perform(argc, argv);
    }
}

XPKI_MODE xpki_get_mode(int argc, char ** argv)
{
    if (argc <= 1 && argv[1] == NULL)
    {
        return XPKI_MODE_NONE;
    }

    typedef struct
    {
        char * name;
        XPKI_MODE mode;
    } command_map_t;

    command_map_t command_map[] = {
        { "help", XPKI_MODE_PRINT_HELP },       { "version", XPKI_MODE_PRINT_VERSION },
        { "get-cert", XPKI_MODE_GET_CERT },     { "get-cert-status", XPKI_MODE_GET_CERT_STATUS },
        { "renew-cert", XPKI_MODE_RENEW_CERT }, { "print-cert", XPKI_MODE_PRINT_CERT },
        { "revoke", XPKI_MODE_REVOKE_CERT },
    };

    for (int i = 0; i < sizeof(command_map) / sizeof(command_map_t); ++i)
    {
        if (strcmp(argv[1], command_map[i].name) == 0)
        {
            return command_map[i].mode;
        }
    }

    return XPKI_MODE_NONE;
}

SECTIGO_MODE sectigo_get_mode(int argc, char ** argv){
    typedef struct{
        char * name;
        SECTIGO_MODE mode;
    } command_map_t;

    command_map_t command_map[] = {
        {"sectigo-get-cert", SECTIGO_MODE_GET_CERT},
        {"sectigo-search-cert", SECTIGO_MODE_SEARCH_CERT},
        {"sectigo-renew-cert", SECTIGO_MODE_RENEW_CERT},
        {"sectigo-revoke-cert", SECTIGO_MODE_REVOKE_CERT},
        {"sectigo-ocsp-status", SECTIGO_MODE_OCSP_STATUS}
    };
    
    for(int i = 0; i < sizeof(command_map) / sizeof(command_map_t); ++i){
        if (strcmp(argv[1], command_map[i].name) == 0){
            return command_map[i].mode;
        }
    
    }
    
    
    return SECTIGO_MODE_NONE;
}

XPKI_CLIENT_ERROR_CODE xpki_print_helper(XPKI_MODE mode)
{
    if (mode == XPKI_MODE_PRINT_VERSION)
    {
        char * version_string = certifier_get_version(get_certifier_instance());

        if (version_string == NULL)
        {
            log_error("Error getting version string as it was NULL!\n");
            return XPKI_CLIENT_ERROR_INTERNAL;
        }

        XFPRINTF(stdout, "%s\n", version_string);

        XFREE(version_string);
    }
    else if (mode == XPKI_MODE_PRINT_HELP || mode == XPKI_MODE_NONE)
    {
        XFPRINTF(stdout,
                 "Usage:  certifierUtil [COMMANDS] [OPTIONS]\n"
                 "Commands:\n"
                 "help\n"
                 "version\n"
                 "get-cert\n"
                 "get-cert-status\n"
                 "renew-cert\n"
                 "print-cert\n"
                 "revoke\n"
                 "sectigo-get-cert\n"
                 "sectigo-search-cert\n"
                 "sectigo-renew-cert\n"
                 "sectigo-revoke-cert\n"
                 "sectigo-ocsp-status\n"
                );
    }

    return XPKI_CLIENT_SUCCESS;
}

SECTIGO_CLIENT_ERROR_CODE sectigo_print_helper(SECTIGO_MODE mode)
{
    if (mode == SECTIGO_MODE_PRINT_HELP || mode == SECTIGO_MODE_NONE)
    {
        XFPRINTF(stdout,
                 "Usage:  certifierUtil [COMMANDS] [OPTIONS]\n"
                 "Commands:\n"
                 "help\n"
                 "sectigo-get-cert\n");
    }

    return SECTIGO_CLIENT_SUCCESS;
}

#define BASE_SHORT_OPTIONS "hp:L:k:vm"
#define GET_CRT_TOKEN_SHORT_OPTIONS "X:S:"
#define GET_CERT_SHORT_OPTIONS "fT:P:o:i:n:F:a:w:"
#define VALIDITY_DAYS_SHORT_OPTION "t:"
#define CA_PATH_SHORT_OPTION "c:"

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
    { "common-name", required_argument, NULL, 'C' },                                                          \
    { "id", required_argument, NULL, 'I' }, \
    { "project-name", required_argument, NULL, 'r' }, \
    { "business-justification", required_argument, NULL, 'b' }, \
    { "subject-alt-names", required_argument, NULL, 'A' }, \
    {"url", required_argument, NULL, 'u'}, \
    { "auth-token", required_argument, NULL, 'K' }, \
    { "group-name", required_argument, NULL, 'G' }, \
    { "group-email", required_argument, NULL, 'E' }, \
    { "owner-first-name", required_argument, NULL, 'O' }, \
    { "owner-last-name", required_argument, NULL, 'J' }, \
    { "owner-email", required_argument, NULL, 'Z' }, \
    { "config", required_argument, NULL, 'l' }, \
    { NULL, 0, NULL, 0 }                                                                                       \
    //make default arg '*' for san and ip 
    //only take in choices=['fte', 'contractor', 'associate']

typedef struct
{
    XPKI_MODE mode;
    const char * short_opts;
    const struct option * long_opts;
} command_opt_lut_t;

typedef struct 
{
    SECTIGO_MODE mode;
    const char * short_opts;
    const struct option * long_opts;
} sectigo_command_opt_lut_t;

static size_t get_command_opt_index(command_opt_lut_t * command_opt_lut, size_t n_entries, XPKI_MODE mode)
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

static const char * get_sectigo_command_opt_helper(SECTIGO_MODE mode)
{

#define SECTIGO_BASE_HELPER                         \
    "Usage:  certifierUtil sectigo-get-cert [OPTIONS]\n"
   
#define SECTIGO_GET_CERT_HELPER                     \
    "--common-name [value] (-C)\n"                  \
    "--id [value] (-I)\n"                           \
    "--project-name [value] (-r)\n"                 \
    "--business-justification [value] (-b)\n"       \
    "--subject-alt-names [value] (-A)\n"            \
    "--group-name [value] (-G)\n"                   \
    "--group-email [value] (-E)\n"                  \
    "--owner-first-name [value] (-O)\n"             \
    "--owner-last-name [value] (-J)\n"              \
    "--owner-email [value] (-Z)\n"                  \
    "--devhub-id [value] (-D)\n"                    \
    "--validity-days [value] (-V)\n"                \
    "--key-type [value] (-W)\n"                     \
    "--auth-token [value] (-K)\n"                   \
    "--url [value] (-u)\n"                          \
    "--config [value] (-l)\n"                       \

#define SECTIGO_SEARCH_CERT_HELPER                  \
    "--auth-token [value] (-K)\n"                   \
    "--common-name [value] (-C)\n"                  \
    "--group-name [value] (-G)\n"                   \
    "--group-email [value] (-E)\n"                  \
    "--status [value] (-S)\n"                       \
    "--offset [value] (-o)\n"                       \
    "--limit [value] (-L)\n" \
    "--start-date [value] (-f)\n" \
    "--end-date [value] (-t)\n" \
    "--certificate-id [value] (-i)\n" \
    "--validity-start-date [value] (-p)\n" \
    "--validity-end-date [value] (-q)\n" \
    "--cert-order [value] (-c)\n" \
    "--is-cn-in-san [value] (-a)\n" \
    "--request-type [value] (-y)\n" \
    "--timestamp [value] (-m)\n" \
    "--devhub-id [value] (-D)\n" \
    "--key-type [value] (-W)\n" \
    "--config [value] (-l)\n" \

#define SECTIGO_RENEW_CERT_HELPER                   \
    "--auth-token [value] (-K)\n"                   \
   "--common-name [value] (-C)\n"                   \
    "--serial-number [value] (-N)\n"                \
    "--certificate-id [value] (-i)\n"               \
    "--requestor-email [value] (-s)\n"              \
    "--config [value] (-l)\n" \

#define SECTIGO_REVOKE_CERT_HELPER                  \
    "--auth-token [value] (-K)\n"                   \
    "--common-name [value] (-C)\n"                  \
    "--serial-number [value] (-N)\n"                \
    "--certificate-id [value] (-i)\n"               \
    "--requestor-email [value] (-s)\n"              \
    "--revocation-request-reason [value] (-R)\n"    \
    "--config [value] (-l)\n"                       \

#define SECTIGO_OCSP_STATUS_HELPER                  \
    "--cert-path [value] (-j)\n"                    \
    "--config [value] (-l)\n"                       \

    switch (mode)
    {
    case SECTIGO_MODE_GET_CERT:
        return SECTIGO_BASE_HELPER SECTIGO_GET_CERT_HELPER;
    case SECTIGO_MODE_SEARCH_CERT:
        return SECTIGO_BASE_HELPER SECTIGO_SEARCH_CERT_HELPER;
    case SECTIGO_MODE_RENEW_CERT:
        return SECTIGO_BASE_HELPER SECTIGO_RENEW_CERT_HELPER;
    case SECTIGO_MODE_REVOKE_CERT:
        return SECTIGO_BASE_HELPER SECTIGO_REVOKE_CERT_HELPER;
    case SECTIGO_MODE_OCSP_STATUS:
        return SECTIGO_BASE_HELPER SECTIGO_OCSP_STATUS_HELPER;
    case SECTIGO_MODE_PRINT_HELP:
        return SECTIGO_BASE_HELPER;
    default:
        return "";
    }
}

static const char * get_xpki_command_opt_helper(XPKI_MODE mode)
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
    case XPKI_MODE_GET_CERT:
        return BASE_HELPER GET_CRT_TOKEN_HELPER GET_CERT_HELPER VALIDITY_DAYS_HELPER CA_PATH_HELPER;
    case XPKI_MODE_GET_CERT_STATUS:
        return BASE_HELPER CA_PATH_HELPER;
    case XPKI_MODE_RENEW_CERT:
        return BASE_HELPER CA_PATH_HELPER;
    case XPKI_MODE_PRINT_CERT:
        return BASE_HELPER;
    case XPKI_MODE_REVOKE_CERT:
        return BASE_HELPER CA_PATH_HELPER;
    default:
        return "";
    }
}

XPKI_CLIENT_ERROR_CODE process(XPKI_MODE mode, xc_parameter_t * xc_parameter, int argc, char ** argv)
{
    VerifyOrReturnError(xc_parameter != NULL, XPKI_CLIENT_INVALID_ARGUMENT);
    VerifyOrReturnError(argv != NULL, XPKI_CLIENT_INVALID_ARGUMENT);

    switch (mode)
    {
    case XPKI_MODE_GET_CERT:
        ReturnErrorOnFailure(xc_get_default_cert_param(&xc_parameter->get_cert_param));
        break;
    case XPKI_MODE_GET_CERT_STATUS:
        ReturnErrorOnFailure(xc_get_default_cert_status_param(&xc_parameter->get_cert_status_param));
        break;
    case XPKI_MODE_RENEW_CERT:
        ReturnErrorOnFailure(xc_get_default_renew_cert_param(&xc_parameter->renew_cert_param));
        break;
    default:
        return XPKI_CLIENT_NOT_IMPLEMENTED;
    }   
    static const char * const get_cert_short_options =
        BASE_SHORT_OPTIONS GET_CRT_TOKEN_SHORT_OPTIONS GET_CERT_SHORT_OPTIONS VALIDITY_DAYS_SHORT_OPTION CA_PATH_SHORT_OPTION;
    static const char * const get_cert_status_short_options = BASE_SHORT_OPTIONS CA_PATH_SHORT_OPTION;
    static const char * const renew_cert_short_options      = BASE_SHORT_OPTIONS CA_PATH_SHORT_OPTION;

    static const struct option get_cert_long_opts[]        = { BASE_LONG_OPTIONS,     GET_CRT_TOKEN_LONG_OPTIONS,
                                                               GET_CERT_LONG_OPTIONS, VALIDITY_DAYS_LONG_OPTION,
                                                               CA_PATH_LONG_OPTION,   { NULL, 0, NULL, 0 } };
    static const struct option get_cert_status_long_opts[] = { BASE_LONG_OPTIONS, CA_PATH_LONG_OPTION, { NULL, 0, NULL, 0 } };
    static const struct option renew_cert_long_opts[]      = { BASE_LONG_OPTIONS, CA_PATH_LONG_OPTION, { NULL, 0, NULL, 0 } };

    static command_opt_lut_t command_opt_lut[] = {
        { XPKI_MODE_GET_CERT, get_cert_short_options, get_cert_long_opts },
        { XPKI_MODE_GET_CERT_STATUS, get_cert_status_short_options, get_cert_status_long_opts },
        { XPKI_MODE_RENEW_CERT, renew_cert_short_options, renew_cert_long_opts },
    };

    XPKI_CLIENT_ERROR_CODE error_code = XPKI_CLIENT_SUCCESS;

    for (;;)
    {
        int command_opt_index = get_command_opt_index(command_opt_lut, sizeof(command_opt_lut) / sizeof(*command_opt_lut), mode);
        int option_index;
        int opt = XGETOPT_LONG(argc, argv, command_opt_lut[command_opt_index].short_opts,
                               command_opt_lut[command_opt_index].long_opts, &option_index);

        if (opt == -1 || error_code != XPKI_CLIENT_SUCCESS)
        {
            break;
        }

        switch (opt)
        {
        case 'h':
            XFPRINTF(stdout, get_xpki_command_opt_helper(mode), argv[0]);
            exit(0);
        case 'c':
            // return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_CA_PATH, optarg);
            break;
        case 'f':
            xc_parameter->get_cert_param.overwrite_p12 = true;
            break;
        case 'p':
            if (mode == XPKI_MODE_GET_CERT)
            {
                xc_parameter->get_cert_param.input_p12_password = optarg;
            }
            else
            {
                xc_parameter->get_cert_status_param.p12_password = optarg;
            }
            break;
        case 'w':
            xc_parameter->get_cert_param.output_p12_password = optarg;
            break;
        case 'L':
            // skip
            // return_code = certifier_set_property(easy->certifier, CERTIFIER_OPT_CFG_FILENAME, optarg);
            break;
        case 'T':
            xc_parameter->get_cert_param.crt = optarg;
            break;
        case 'X':
            if (mode == XPKI_MODE_GET_CERT)
            {
                xc_parameter->get_cert_param.auth_type = map_to_xpki_auth_type(optarg);
            }
            else
            {
                xc_parameter->get_cert_status_param.auth_type = map_to_xpki_auth_type(optarg);
            }
            break;
        case 'S':
            if (mode == XPKI_MODE_GET_CERT)
            {
                xc_parameter->get_cert_param.auth_token = optarg;
            }
            else
            {
                xc_parameter->get_cert_status_param.auth_token = optarg;
            }
            break;
        case 'k':
            if (mode == XPKI_MODE_GET_CERT)
            {
                xc_parameter->get_cert_param.input_p12_path = optarg;
            }
            else
            {
                xc_parameter->get_cert_status_param.p12_path = optarg;
            }
            break;
        case 'o':
            xc_parameter->get_cert_param.output_p12_path = optarg;
            break;
        case 'P':
            xc_parameter->get_cert_param.profile_name = optarg;
            break;
        case 'i':
            xc_parameter->get_cert_param.product_id = atoi(optarg);
            break;
        case 'n':
            xc_parameter->get_cert_param.node_id = atol(optarg);
            break;
        case 'F':
            xc_parameter->get_cert_param.fabric_id = atol(optarg);
            break;
        case 'a':
            xc_parameter->get_cert_param.case_auth_tag = atoi(optarg);
            break;
        case 't':
            xc_parameter->get_cert_param.validity_days = atol(optarg);
            break;
        case 'm':
            // skip
            // easy->mode |= CERTIFIER_MODE_KEY_EXCHANGE;
            break;
        case 'v':
            certifier_set_property(get_certifier_instance(), CERTIFIER_OPT_LOG_LEVEL, (void *) (size_t) 0);
            break;
        case '?':
            /* Case when user enters the command as
             * $ ./certifierUtil -p
             */
            if (optopt == 'p')
            {
                log_info("Missing mandatory password option");
                error_code = XPKI_CLIENT_INVALID_ARGUMENT;
                break;
            }
            else if (optopt == 'L')
            {
                log_info("Missing mandatory cfg filename option");
                error_code = XPKI_CLIENT_INVALID_ARGUMENT;
                break;
            }
            else if (optopt == 'T')
            {
                log_info("Missing mandatory crt option");
                error_code = XPKI_CLIENT_INVALID_ARGUMENT;
                break;
            }
            else if (optopt == 'X')
            {
                log_info("Missing mandatory crt type option");
                error_code = XPKI_CLIENT_INVALID_ARGUMENT;
                break;
            }
            else if (optopt == 'S')
            {
                log_info("Missing mandatory auth token option");
                error_code = XPKI_CLIENT_INVALID_ARGUMENT;
                break;
            }
            else if (optopt == 'D')
            {
                log_info("Missing mandatory custom property option");
                error_code = XPKI_CLIENT_INVALID_ARGUMENT;
                break;
            }
            else if (optopt == 'k')
            {
                log_info("Missing mandatory keystore property option");
                error_code = XPKI_CLIENT_INVALID_ARGUMENT;
                break;
            }
            else if (optopt == 'P')
            {
                log_info("Missing mandatory Profile Name option");
                error_code = XPKI_CLIENT_INVALID_ARGUMENT;
                break;
            }
            else if (optopt == 'o')
            {
                log_info("Missing mandatory output keystore property option");
                error_code = XPKI_CLIENT_INVALID_ARGUMENT;
                break;
            }
            else if (optopt == 'i')
            {
                log_info("Missing mandatory Product Id option (16-bit hex)");
                error_code = XPKI_CLIENT_INVALID_ARGUMENT;
                break;
            }
            else if (optopt == 'n')
            {
                log_info("Missing mandatory Node Id option (64-bit hex)");
                error_code = XPKI_CLIENT_INVALID_ARGUMENT;
                break;
            }
            else if (optopt == 'F')
            {
                log_info("Missing mandatory Fabric Id option (64-bit hex)");
                error_code = XPKI_CLIENT_INVALID_ARGUMENT;
                break;
            }
            else if (optopt == 'v')
            {
                log_info("Missing mandatory number of validity days");
                error_code = XPKI_CLIENT_INVALID_ARGUMENT;
                break;
            }
            else
            {
                log_info("Invalid option received");
                error_code = XPKI_CLIENT_INVALID_ARGUMENT;
                break;
            }
        }
    }

    return error_code;
}

// --- Sectigo Option Table ---
static const char * const sectigo_get_cert_short_options = "C:I:r:b:A:K:u:G:E:O:J:Z:W:V:D:l:h";
static const char * const sectigo_search_cert_short_options = "K:C:G:E:S:o:L:f:t:i:p:q:c:a:y:m:D:W:l:h";
static const char * const sectigo_renew_cert_short_options = "K:C:N:i:s:l:h";
static const char * const sectigo_revoke_cert_short_options = "K:C:N:i:s:R:l:h";
static const char * const sectigo_ocsp_status_short_options = "j:l:h";

static const struct option sectigo_get_cert_long_opts[] = {
    { "common-name", required_argument, NULL, 'C' },
    { "id", required_argument, NULL, 'I' },
    { "project-name", required_argument, NULL, 'r' },
    { "business-justification", required_argument, NULL, 'b' },
    { "subject-alt-names", required_argument, NULL, 'A' },
    { "url", required_argument, NULL, 'u'},
    { "auth-token", required_argument, NULL, 'K' },
    { "group-name", required_argument, NULL, 'G' },
    { "group-email", required_argument, NULL, 'E' },
    { "owner-first-name", required_argument, NULL, 'O' },
    { "owner-last-name", required_argument, NULL, 'J' },
    { "owner-email", required_argument, NULL, 'Z' },
    { "devhub-id", required_argument, NULL, 'D' },
    { "validity-days", required_argument, NULL, 'V' },
    { "key-type", required_argument, NULL, 'W' },
    { "config", required_argument, NULL, 'l' },
    { "help", no_argument, NULL, 'h' },
    { NULL, 0, NULL, 0 }
};

static const struct option sectigo_search_cert_long_opts[] = {
    { "auth-token", required_argument, NULL, 'K' },
    { "common-name", required_argument, NULL, 'C' },
    { "group-name", required_argument, NULL, 'G' },
    { "group-email", required_argument, NULL, 'E' },
    { "status", required_argument, NULL, 'S' },
    { "offset", required_argument, NULL, 'o' },
    { "limit", required_argument, NULL, 'L' },
    { "start-date", required_argument, NULL, 'f' },
    { "end-date", required_argument, NULL, 't' },
    { "certificate-id", required_argument, NULL, 'i' },
    { "validity-start-date", required_argument, NULL, 'p' },
    { "validity-end-date", required_argument, NULL, 'q' },
    { "cert-order", required_argument, NULL, 'c' },
    { "is-cn-in-san", required_argument, NULL, 'a' },
    { "request-type", required_argument, NULL, 'y' },
    { "timestamp", required_argument, NULL, 'm' },
    { "devhub-id", required_argument, NULL, 'D' },
    { "key-type", required_argument, NULL, 'W' },
    { "config", required_argument, NULL, 'l' },
    { "help", no_argument, NULL, 'h' },
    { NULL, 0, NULL, 0 }
};

static const struct option sectigo_renew_cert_long_opts[] = {
    { "auth-token", required_argument, NULL, 'K' },
    { "common-name", required_argument, NULL, 'C' },
    { "serial-number", required_argument, NULL, 'N' },
    { "certificate-id", required_argument, NULL, 'i' },
    { "requestor-email", required_argument, NULL, 's' },
    { "config", required_argument, NULL, 'l' },
    { "help", no_argument, NULL, 'h' },
    { NULL, 0, NULL, 0 }
};

static const struct option sectigo_revoke_cert_long_opts[] = {
    { "auth-token", required_argument, NULL, 'K' },
    { "common-name", required_argument, NULL, 'C' },
    { "serial-number", required_argument, NULL, 'N' },
    { "certificate-id", required_argument, NULL, 'i' },
    { "requestor-email", required_argument, NULL, 's' },
    { "revocation-request-reason", required_argument, NULL, 'R' },
    { "config", required_argument, NULL, 'l' },
    { "help", no_argument, NULL, 'h' },
    { NULL, 0, NULL, 0 }
};

static const struct option sectigo_ocsp_status_long_opts[] = {
    { "cert-path", required_argument, NULL, 'j' },
    { "config", required_argument, NULL, 'l' },
    { "help", no_argument, NULL, 'h' },
    { NULL, 0, NULL, 0 }
};

static sectigo_command_opt_lut_t sectigo_command_opt_lut[] = {
    { SECTIGO_MODE_GET_CERT, sectigo_get_cert_short_options, sectigo_get_cert_long_opts },
    { SECTIGO_MODE_SEARCH_CERT, sectigo_search_cert_short_options, sectigo_search_cert_long_opts },
    { SECTIGO_MODE_RENEW_CERT, sectigo_renew_cert_short_options, sectigo_renew_cert_long_opts },
    { SECTIGO_MODE_REVOKE_CERT, sectigo_revoke_cert_short_options, sectigo_revoke_cert_long_opts },
    { SECTIGO_MODE_OCSP_STATUS, sectigo_ocsp_status_short_options, sectigo_ocsp_status_long_opts },
};

static size_t get_sectigo_command_opt_index(sectigo_command_opt_lut_t * lut, size_t n_entries, SECTIGO_MODE mode)
{
    for (size_t i = 0; i < n_entries; ++i)
    {
        if (lut[i].mode == mode)
        {
            return i;
        }
    }
    return 0; // fallback
}

// --- Sectigo Option Parsing ---
SECTIGO_CLIENT_ERROR_CODE sectigo_process(SECTIGO_MODE mode, sectigo_parameter_t * sectigo_parameter, int argc, char ** argv)
{
    VerifyOrReturnError(sectigo_parameter != NULL, SECTIGO_CLIENT_INVALID_ARGUMENT);
    VerifyOrReturnError(argv != NULL, SECTIGO_CLIENT_INVALID_ARGUMENT);

    SECTIGO_CLIENT_ERROR_CODE error_code = SECTIGO_CLIENT_SUCCESS;
    switch (mode)
    {
    case SECTIGO_MODE_GET_CERT:
        ReturnErrorOnFailure(xc_sectigo_get_default_cert_param(&sectigo_parameter->get_cert_param));
        break;
    case SECTIGO_MODE_SEARCH_CERT:
    case SECTIGO_MODE_OCSP_STATUS:
        // No default parameters to set for search cert or OCSP status, so just break
        break;
    case SECTIGO_MODE_RENEW_CERT:
        ReturnErrorOnFailure(xc_sectigo_get_default_renew_cert_param(&sectigo_parameter->renew_cert_param));
        break;
    case SECTIGO_MODE_REVOKE_CERT:
        ReturnErrorOnFailure(xc_sectigo_get_default_revoke_cert_param(&sectigo_parameter->revoke_cert_param));
        break;
    default:
        return SECTIGO_CLIENT_NOT_IMPLEMENTED;
    }

    for (;;)
    {
        int option_index = 0;
        int sectigo_opt_index = get_sectigo_command_opt_index(
            sectigo_command_opt_lut, 
            sizeof(sectigo_command_opt_lut) / sizeof(*sectigo_command_opt_lut), 
            mode
        );

        int opt = XGETOPT_LONG(argc, argv, 
                       sectigo_command_opt_lut[sectigo_opt_index].short_opts,
                       sectigo_command_opt_lut[sectigo_opt_index].long_opts, 
                       &option_index
        );

        if (opt == -1 || error_code != SECTIGO_CLIENT_SUCCESS)
        {
            break;
        }

        switch (opt)
        {
        case 'h':
            XFPRINTF(stdout, get_sectigo_command_opt_helper(mode), argv[0]);
            exit(0);
        case 'C':
            sectigo_parameter->get_cert_param.common_name = optarg;
            certifier_set_property(get_sectigo_certifier_instance(), CERTIFIER_OPT_SECTIGO_COMMON_NAME, optarg);
            break;
        case 'I':
            sectigo_parameter->get_cert_param.id = optarg;
            certifier_set_property(get_sectigo_certifier_instance(), CERTIFIER_OPT_SECTIGO_ID, optarg);
            break;
        case 'b':
            sectigo_parameter->get_cert_param.business_justification = optarg;
            certifier_set_property(get_sectigo_certifier_instance(), CERTIFIER_OPT_SECTIGO_BUSINESS_JUSTIFICATION, optarg);
            break;
        case 'A':
            sectigo_parameter->get_cert_param.subject_alt_names = optarg;
            certifier_set_property(get_sectigo_certifier_instance(), CERTIFIER_OPT_SECTIGO_SUBJECT_ALT_NAMES, optarg);
            break;
        case 'l':
            // config file path, handled in sectigo_perform
            break;
        case 'G':
            sectigo_parameter->get_cert_param.group_name = optarg;
            certifier_set_property(get_sectigo_certifier_instance(), CERTIFIER_OPT_SECTIGO_GROUP_NAME, optarg);
            break;
        case 'E':
            sectigo_parameter->get_cert_param.group_email = optarg;
            certifier_set_property(get_sectigo_certifier_instance(), CERTIFIER_OPT_SECTIGO_GROUP_EMAIL, optarg);
            break;
        case 'O':
            sectigo_parameter->get_cert_param.owner_first_name = optarg;
            certifier_set_property(get_sectigo_certifier_instance(), CERTIFIER_OPT_SECTIGO_OWNER_FIRST_NAME, optarg);
            break;
        case 'J':
            sectigo_parameter->get_cert_param.owner_last_name = optarg;
            certifier_set_property(get_sectigo_certifier_instance(), CERTIFIER_OPT_SECTIGO_OWNER_LAST_NAME, optarg);
            break;
        case 'Z':
            sectigo_parameter->get_cert_param.owner_email = optarg;
            certifier_set_property(get_sectigo_certifier_instance(), CERTIFIER_OPT_SECTIGO_OWNER_EMAIL, optarg);
            break;
        case 'K':
            sectigo_parameter->get_cert_param.auth_token = optarg;
            certifier_set_property(get_sectigo_certifier_instance(), CERTIFIER_OPT_SECTIGO_AUTH_TOKEN, optarg);
            break;
        case 'u':
            sectigo_parameter->get_cert_param.sectigo_url = optarg;
            certifier_set_property(get_sectigo_certifier_instance(), CERTIFIER_OPT_SECTIGO_URL, optarg);
            break;
        case 'D':
            sectigo_parameter->get_cert_param.devhub_id = optarg;
            certifier_set_property(get_sectigo_certifier_instance(), CERTIFIER_OPT_SECTIGO_DEVHUB_ID, optarg);
            break;
        case 'V':
            sectigo_parameter->get_cert_param.validity_days = atol(optarg);
            certifier_set_property(get_sectigo_certifier_instance(), CERTIFIER_OPT_SECTIGO_VALIDITY_DAYS, (void *)(size_t)atol(optarg));
            break;
        case 'W':
            sectigo_parameter->get_cert_param.key_type = optarg;
            certifier_set_property(get_sectigo_certifier_instance(), CERTIFIER_OPT_SECTIGO_KEY_TYPE, optarg);
            break;
        case 'R':
            sectigo_parameter->revoke_cert_param.revocation_request_reason = optarg;
            certifier_set_property(get_sectigo_certifier_instance(), CERTIFIER_OPT_SECTIGO_REVOCATION_REQUEST_REASON, optarg);
            break;
        case 'N':
            sectigo_parameter->revoke_cert_param.serial_number = optarg;
            certifier_set_property(get_sectigo_certifier_instance(), CERTIFIER_OPT_SECTIGO_SERIAL_NUMBER, optarg);
            break;
        case 'i':
            sectigo_parameter->revoke_cert_param.certificate_id = optarg;
            certifier_set_property(get_sectigo_certifier_instance(), CERTIFIER_OPT_SECTIGO_CERTIFICATE_ID, optarg);
            break;
        case 's':
            sectigo_parameter->revoke_cert_param.requestor_email = optarg;
            certifier_set_property(get_sectigo_certifier_instance(), CERTIFIER_OPT_SECTIGO_REQUESTOR_EMAIL, optarg);
            break;
        case 'S':
            certifier_set_property(get_sectigo_certifier_instance(), CERTIFIER_OPT_SECTIGO_STATUS, optarg);
            break;
        case 'o':
            certifier_set_property(get_sectigo_certifier_instance(), CERTIFIER_OPT_SECTIGO_OFFSET, optarg);
            break;
        case 'L':
            certifier_set_property(get_sectigo_certifier_instance(), CERTIFIER_OPT_SECTIGO_LIMIT, (void *)(size_t)atol(optarg));
            break;
        case 'f':
            certifier_set_property(get_sectigo_certifier_instance(), CERTIFIER_OPT_SECTIGO_START_DATE, optarg);
            break;
        case 't':
            certifier_set_property(get_sectigo_certifier_instance(), CERTIFIER_OPT_SECTIGO_END_DATE, optarg);
            break;
        case 'e':
            certifier_set_property(get_sectigo_certifier_instance(), CERTIFIER_OPT_SECTIGO_CERTIFICATE_ID, optarg);
            break;
        case 'p':
            certifier_set_property(get_sectigo_certifier_instance(), CERTIFIER_OPT_SECTIGO_VALIDITY_START_DATE, optarg);
            break;
        case 'q':
            certifier_set_property(get_sectigo_certifier_instance(), CERTIFIER_OPT_SECTIGO_VALIDITY_END_DATE, optarg);
            break;
        case 'c':
            certifier_set_property(get_sectigo_certifier_instance(), CERTIFIER_OPT_SECTIGO_CERTIFICATE_ORDER, optarg);
            break;
        case 'a':
            certifier_set_property(get_sectigo_certifier_instance(), CERTIFIER_OPT_SECTIGO_IS_CN_IN_SAN, optarg);
            break;
        case 'y':
            certifier_set_property(get_sectigo_certifier_instance(), CERTIFIER_OPT_SECTIGO_REQUEST_TYPE, optarg);
            break;
        case 'm':
            certifier_set_property(get_sectigo_certifier_instance(), CERTIFIER_OPT_SECTIGO_TIMESTAMP, optarg);
            break;
        case 'j':
            certifier_set_property(get_sectigo_certifier_instance(), CERTIFIER_OPT_SECTIGO_CERT_PATH, optarg);
            break;
        case '?':
                log_info("Invalid or missing Sectigo option\n");
                error_code = SECTIGO_CLIENT_INVALID_ARGUMENT;
                break;
            default:
                log_info("Unknown Sectigo option: %c\n", opt);
                error_code = SECTIGO_CLIENT_INVALID_ARGUMENT;
                break;
            }
    }

    return error_code;
}

SECTIGO_CLIENT_ERROR_CODE sectigo_perform(int argc, char ** argv)
{
    SECTIGO_MODE mode = sectigo_get_mode(argc, argv);

    if (mode == SECTIGO_MODE_NONE || mode == SECTIGO_MODE_PRINT_HELP)
    {
        return sectigo_print_helper(mode);
    }

    sectigo_parameter_t sectigo_parameter;

    ReturnErrorOnFailure(sectigo_process(mode, &sectigo_parameter, argc - 1, &argv[1]));

    switch (mode)
    {
    case SECTIGO_MODE_GET_CERT:
        return xc_sectigo_get_cert(&sectigo_parameter.get_cert_param);
        break;
    case SECTIGO_MODE_SEARCH_CERT:
        return xc_sectigo_search_cert(&sectigo_parameter.search_cert_param);
        break;
    case SECTIGO_MODE_RENEW_CERT:
        return xc_sectigo_renew_cert(&sectigo_parameter.renew_cert_param);
        break;
    case SECTIGO_MODE_REVOKE_CERT:
        return xc_sectigo_revoke_cert(&sectigo_parameter.revoke_cert_param);
        break;
    case SECTIGO_MODE_OCSP_STATUS:
        return xc_sectigo_ocsp_status(&sectigo_parameter.ocsp_status_param);
        break;
    default:
        break;
    }
    return SECTIGO_CLIENT_SUCCESS;
}

XPKI_CLIENT_ERROR_CODE xpki_perform(int argc, char ** argv)
{
    XPKI_MODE mode = xpki_get_mode(argc, argv);

    if (mode == XPKI_MODE_NONE || mode == XPKI_MODE_PRINT_VERSION || mode == XPKI_MODE_PRINT_HELP)
    {
        return xpki_print_helper(mode);
    }

    xc_parameter_t xc_parameter;

    ReturnErrorOnFailure(process(mode, &xc_parameter, argc - 1, &argv[1]));

    switch (mode)
    {
    case XPKI_MODE_GET_CERT:
        return xc_get_cert(&xc_parameter.get_cert_param);
        break;
    case XPKI_MODE_GET_CERT_STATUS: {
        XPKI_CLIENT_CERT_STATUS status;
        ReturnErrorOnFailure(xc_get_cert_status(&xc_parameter.get_cert_status_param, &status));
        return (XPKI_CLIENT_ERROR_CODE)status;
    }
    break;
    case XPKI_MODE_RENEW_CERT:
        return xc_renew_cert(&xc_parameter.renew_cert_param);
        break;
    case XPKI_MODE_PRINT_CERT:
        // TODO
        return XPKI_CLIENT_NOT_IMPLEMENTED;
        break;
    case XPKI_MODE_REVOKE_CERT:
        // TODO
        return XPKI_CLIENT_NOT_IMPLEMENTED;
        break;
    default:
        break;
    }

    return XPKI_CLIENT_SUCCESS;
}
