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

#ifndef CERTIFIER_H
#define CERTIFIER_H

#include "certifier/property.h"

#define CERTIFIER_APP_REGISTRATION            0x1
#define CERTIFIER_DEVICE_REGISTRATION         0x2

/* CHUNK is the size of the memory chunk used by the zlib routines. */
#define CHUNK 10000

// Digicert CIS
#define DEFAULT_ROOT_CA              "-----BEGIN CERTIFICATE-----\n" \
"MIIDnDCCAoSgAwIBAgIBETANBgkqhkiG9w0BAQUFADBfMQswCQYDVQQGEwJVUzEV\n" \
"MBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29t\n" \
"MR4wHAYDVQQDExVEaWdpQ2VydCBUZXN0IFJvb3QgQ0EwHhcNMDYxMTEwMDAwMDAw\n" \
"WhcNMzExMTEwMDAwMDAwWjBfMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNl\n" \
"cnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMR4wHAYDVQQDExVEaWdp\n" \
"Q2VydCBUZXN0IFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB\n" \
"AQC2mEEv1NiVWb1x7GlRVwmW7tAUQhslTr+5Iz8tHrUq1l1+7rAxjkLzovibesr+\n" \
"orXuL++zlpBAQKxIOQ1T9Kw8m+OKDtAjRiMhP4Mx6O2Qpe4N3Pras2pCPGToXrKf\n" \
"/68lPmt52Fnqd8ISoaBh0+i+SUWM2aNm6e+JFq6IQ/iE2crOXBHaRpv4/IOMCfrT\n" \
"6zAaFnsmWoUjGc6ISqb2nwsYMMOCZtH57ygc54GcIp7t6mmJ3S/Myewtkkk+AGrm\n" \
"hRAgi8/eE6eU++jQoGrZ8UfgYZahTSZkJHZtRj+m9sSUsMX2Lw4Uxk2gUUkdNHvo\n" \
"Odzd+sBLmiw5z6vI9d0YYfwBAgMBAAGjYzBhMA4GA1UdDwEB/wQEAwIBhjAPBgNV\n" \
"HRMBAf8EBTADAQH/MB0GA1UdDgQWBBRGsHII/DXl+vr/nd5REG5ilV3XsDAfBgNV\n" \
"HSMEGDAWgBRGsHII/DXl+vr/nd5REG5ilV3XsDANBgkqhkiG9w0BAQUFAAOCAQEA\n" \
"WcypG3UOkkFw+FEtQmXQDxPBWmS36KwQ64myJXnqcd41ZskYjyCE62iXd2qfQOQ0\n" \
"aoTkbcIo3Ov7RX9M5+m3kpzZmlHHwef0ePd5p1dtVsmnR22TXdmpyxPDOLtYz7wd\n" \
"3DTG2G5fUN2/dgeTK8mITonetrVOkpVx8WtJkMGgVN5Dhy6gVYw0XpNfweyPNacq\n" \
"u0BwrelLn5qTBXCYwg7IWFP2Ca34Xr2tLcQ17zE+PX51TonA7RdB4eOZ2JE6cJp9\n" \
"5D0dyY/RjQvQpn8d7ZjSaHq0HzBMwcXkVMcoKjhOpmwoJz/sJzlt7WFpjd+xyNEr\n" \
"ChW/tdOxL+vy0HBs7NYzkQ==\n" \
"-----END CERTIFICATE-----"

// Digicert CIS
#define DEFAULT_INT_CA              "-----BEGIN CERTIFICATE-----\n" \
"MIIECzCCAvOgAwIBAgIQDz6kXMM9nbbLagSg9vLw2TANBgkqhkiG9w0BAQwFADBf\n" \
"MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\n" \
"d3cuZGlnaWNlcnQuY29tMR4wHAYDVQQDExVEaWdpQ2VydCBUZXN0IFJvb3QgQ0Ew\n" \
"HhcNMTYwNzExMTIwNDE1WhcNMjYwNzExMTIwNDE1WjBVMQwwCgYDVQQGEwNVU0Ex\n" \
"FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMSwwKgYDVQQDEyNEaWdpQ2VydCBUZXN0\n" \
"IEVDQyBJbnRlcm1lZGlhdGUgQ0EtMTB2MBAGByqGSM49AgEGBSuBBAAiA2IABI5j\n" \
"ChFeoXBv6z51jk6bmNEZaNmHt6uLtUIwG+sLux+ROjI2qgbXLywWdeD6JlARaz9z\n" \
"PplVfTJb3s73L7VUCcBMw2tb/VGfD/yZ31bqiuuNJqxEbJtdZ3pwUgYBWKgw5KOC\n" \
"AXkwggF1MB0GA1UdDgQWBBTCVPHjfLke82pOZhLs3w0cKQihOTAfBgNVHSMEGDAW\n" \
"gBRGsHII/DXl+vr/nd5REG5ilV3XsDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1Ud\n" \
"DwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwNAYIKwYB\n" \
"BQUHAQEEKDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20w\n" \
"ewYDVR0fBHQwcjA3oDWgM4YxaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lD\n" \
"ZXJ0VGVzdFJvb3RDQUcyLmNybDA3oDWgM4YxaHR0cDovL2NybDQuZGlnaWNlcnQu\n" \
"Y29tL0RpZ2lDZXJ0VGVzdFJvb3RDQUcyLmNybDA9BgNVHSAENjA0MDIGBFUdIAAw\n" \
"KjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzANBgkq\n" \
"hkiG9w0BAQwFAAOCAQEAO6xbaIjuI+Xwore7bCEvfmWD8UJ+bwJjSK5mwDAEKOXY\n" \
"nK7rNpK3nuLxK1I4gqUspBLXZx4I9WaSQ12o5+H2yDc+2C+klxhAZNtK7GAtTpyX\n" \
"Mjr9VndKuxunEfoil/hpN8JA0KTmWNnlljxkq6UahDyTgMxIOcHUrFEcP7yatXeM\n" \
"IHHCzEgL2sVe2wsMosjjjyutibA82/jZIA/CXyC/VdO/e0prTEgEELtjSzQ68pik\n" \
"GqnNUj6bnL/AGO+UpVqPWC4ZwuNYX9c30umItzvWDDRVNaNX4VCHsRQMj9etXoI1\n" \
"kQdzN/2TPfJCUMk2yysrSCDoe3EbMr62QmzOhQQ6gw==\n" \
"-----END CERTIFICATE-----"


#define ALLOWABLE_CHARACTERS "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnpqrstuvwxyz0123456879"

#define CERTIFIER_ERR_INIT_CERTIFIER 1000
//#define CERTIFIER_ERR_INIT_MINER     2000
#define CERTIFIER_ERR_INIT_SECURITY  3000
#define CERTIFIER_ERR_INIT_CAMERA    4000
#define CERTIFIER_ERR_INIT_MEMORY    4500


#define CERTIFIER_ERR_DESTROY_CERTIFIER 5000
//#define CERTIFIER_ERR_DESTROY_MINER     6000
#define CERTIFIER_ERR_DESTROY_SECURITY  7000
#define CERTIFIER_ERR_DESTROY_CAMERA    7500
#define CERTIFIER_ERR_DESTROY_LOG    7800
#define CERTIFIER_ERR_DESTROY_PROPERTY    7900


#define CERTIFIER_ERR_REGISTER_SECURITY_1                                          9000
#define CERTIFIER_ERR_REGISTER_SECURITY_5                                          9001
#define CERTIFIER_ERR_REGISTER_SECURITY_6                                          9002
#define CERTIFIER_ERR_REGISTER_SECURITY_7                                          9003
#define CERTIFIER_ERR_REGISTER_DELETE_PKCS12_1                                     9004
#define CERTIFIER_ERR_REGISTER_RENAME_PKCS12_1                                     9005
#define CERTIFIER_ERR_REGISTER_DELETE_PKCS12_2                                     9006
#define CERTIFIER_ERR_REGISTER_RENAME_PKCS12_2                                     9007
#define CERTIFIER_ERR_REGISTER_CERT_RENEWAL                                        10000
#define CERTIFIER_ERR_REGISTER_SETUP                                               11000
#define CERTIFIER_ERR_REGISTER_CERTIFIER_1                                         12000
#define CERTIFIER_ERR_REGISTER_MINER_1                                             13000
#define CERTIFIER_ERR_REGISTER_CRT_1                                               14000
#define CERTIFIER_ERR_REGISTER_CRT_2                                               15000
#define CERTIFIER_ERR_REGISTER_UNKNOWN                                             16000

#define CERTIFIER_ERR_PROPERTY_SET                27000
#define CERTIFIER_ERR_PROPERTY_SET_MEMORY         27900

#define CERTIFIER_ERR_CREATE_NODE_ADDRESS_1 100100
#define CERTIFIER_ERR_CREATE_NODE_ADDRESS_2 100200

#define CERTIFIER_ERR_CREATE_CRT_1 100300
#define CERTIFIER_ERR_CREATE_CRT_2 100301
#define CERTIFIER_ERR_CREATE_CRT_3 100302
#define CERTIFIER_ERR_CREATE_CRT_4 100303
#define CERTIFIER_ERR_CREATE_CRT_5 100304
#define CERTIFIER_ERR_CREATE_CRT_6 100305


#define CERTIFIER_ERR_CREATE_X509_CERT_1 100400
#define CERTIFIER_ERR_CREATE_X509_CERT_2 100401
#define CERTIFIER_ERR_CREATE_X509_CERT_3 100402
#define CERTIFIER_ERR_CREATE_X509_CERT_4 100500
#define CERTIFIER_ERR_CREATE_X509_CERT_5 100600
#define CERTIFIER_ERR_CREATE_X509_CERT_6 100680
#define CERTIFIER_ERR_CREATE_X509_CERT_7 100690

#define CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1 100800
#define CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_2 100801
#define CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_3 100802
#define CERTIFIER_ERR_GEN_1 100803
#define CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_5 100804

#define CERTIFIER_ERR_GET_CERT_STATUS_1 130000

#define CERTIFIER_ERR_RENEW_CERT_1 140000

#define CERTIFIER_ERR_PRINT_CERT_1 150000
#define CERTIFIER_ERR_PRINT_CERT_2 160000
#define CERTIFIER_ERR_PRINT_CERT_3 170000
#define CERTIFIER_ERR_PRINT_CERT_4 180000
#define CERTIFIER_ERR_PRINT_CERT_5 190000

#define CERTIFIER_ERR_GENERATE_CRT_NONCE          1

#define CERTIFIER_ERR_SETUP_ECKEY_FAILURE                     1

// NOTUSED - will repurpose
#define CERTIFIER_ERR_SETUP_ECKEY_PUBLIC_WRITE_DER_FAILURE_1  2

#define CERTIFIER_ERR_SETUP_INTERNAL_NODE_ADDRESS_2           3
#define CERTIFIER_ERR_SETUP_EMPTY_FILENAME                    4
#define CERTIFIER_ERR_SETUP_EMPTY_PASSWORD                    5
#define CERTIFIER_ERR_SETUP_EMPTY_ECC_CURVE                   6

#define CERTIFIER_ERR_REGISTRATION_STATUS_X509_NONEXISTENT     1
#define CERTIFIER_ERR_REGISTRATION_STATUS_P12_NONEXISTENT      2
#define CERTIFIER_ERR_REGISTRATION_STATUS_CERTIFIER_ID_NONEXISTENT 3
#define CERTIFIER_ERR_REGISTRATION_STATUS_CERT_TIME_CHECK_1    4
#define CERTIFIER_ERR_REGISTRATION_STATUS_CERT_EXPIRED_1       6
#define CERTIFIER_ERR_REGISTRATION_STATUS_CERT_EXPIRED_2       7
#define CERTIFIER_ERR_REGISTRATION_STATUS_CERT_ABOUT_TO_EXPIRE 8
#define CERTIFIER_ERR_REGISTRATION_STATUS_SIMULATION_1         9
#define CERTIFIER_ERR_REGISTRATION_STATUS_SIMULATION_2         10

typedef enum {
    CERTIFIER_LOG_TRACE = 0,
    CERTIFIER_LOG_DEBUG,
    CERTIFIER_LOG_INFO,
    CERTIFIER_LOG_WARN,
    CERTIFIER_LOG_ERROR,
    CERTIFIER_LOG_FATAL
} CertifierLogPriority;

typedef struct Certifier Certifier;

Certifier *
certifier_new(void);

int
certifier_destroy(Certifier *certifier);

/**
 * Register a device or application
 * @param certifier
 * @param mode
 * @return
 */
int certifier_register(Certifier *certifier, int mode);

int
certifier_set_property(Certifier *certifier, int name, const void *value);


void *
certifier_get_property(Certifier *certifier, int name);

/**
 * Load the configuration file in CERTIFIER_OPT_CFG_FILENAME
 * @param certifier
 * @return 0 on success, or an error code
 */
int
certifier_load_cfg_file(Certifier *certifier);

char *
certifier_get_version(Certifier *certifier);

/**
 * Create a JSON document describing an operation
 * @param certifier
 * @param return_code A return code to include in the 'return_code' key.
 * @param output A string to include in the 'output' key. This value is copied.
 * @return a JSON document (caller must free).
 */
char *
certifier_create_info(Certifier *certifier, const int return_code, const char *output);

int certifier_create_node_address(const unsigned char *input,
                                  int input_len,
                                  char **node_address);

/**
 * Get the node address
 * @param certifier
 * @return
 */
const char *certifier_get_node_address(Certifier *certifier);

/**
 * Get the certifier ID
 * @pre the device is registered
 * @param certifier
 * @return
 */
const char *certifier_get_certifier_id(Certifier *certifier);

int certifier_create_crt(Certifier *certifier, char **out_crt, const char *type);

int certifier_create_x509_crt(Certifier *certifier, char **out_crt);

int certifier_create_json_csr(Certifier *certifier, char *csr, char **out_cert);
int certifier_setup_keys(Certifier *certifier);

int
certifier_get_device_registration_status(Certifier *certifier);

/**
 * Callback that will receive log messages
 * @param prio the log priority
 * @param file the source file that emitted 'msg'
 * @param line the line in 'file'
 * @param msg The original, formatted log message (never NULL)
 */
typedef void (*CERTIFIER_LOG_callback)(const CertifierLogPriority prio,
                                       const char *file,
                                       const uint32_t line,
                                       const char *msg);

/**
 * Register a callback to receive logs. This will disable other logging
 * @param cb
 * @see CERTIFIER_LOG_callback
 */
void certifier_set_log_callback(Certifier *certifier,
                                CERTIFIER_LOG_callback cb);

/**
 * Get the x509 certificate in PEM format (without armor)
 * @param certifier
 * @return A base64 encoded certificate or NULL (caller must free)
 */
char *certifier_get_x509_pem(Certifier *certifier);


#endif
