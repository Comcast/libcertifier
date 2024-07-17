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

XPKI_CLIENT_ERROR_CODE xpki_perform(int argc, char ** argv);

int main(int argc, char ** argv)
{
    return xpki_perform(argc, argv);
}

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

typedef union
{
    get_cert_param_t get_cert_param;
    get_cert_status_param_t get_cert_status_param;
    renew_cert_param_t renew_cert_param;
} xc_parameter_t;

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
        { "revoke", XPKI_CLIENT_CERT_REVOKED },
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
                 "revoke\n");
    }

    return XPKI_CLIENT_SUCCESS;
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

typedef struct
{
    XPKI_MODE mode;
    const char * short_opts;
    const struct option * long_opts;
} command_opt_lut_t;

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

static const char * get_command_opt_helper(XPKI_MODE mode)
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
            XFPRINTF(stdout, get_command_opt_helper(mode), argv[0]);
            exit(0);
            break;
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
                log_info("Missing mandatory custom property  option");
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
        return status;
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
