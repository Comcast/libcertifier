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

#ifndef LIBLEDGER_ERROR_H
#define LIBLEDGER_ERROR_H

#include "certifier/types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CERTIFIER_ERROR_INITIALIZER                                                                                                \
    {                                                                                                                              \
        0, 0, NULL, NULL                                                                                                           \
    }

typedef struct
{
    int application_error_code;
    int library_error_code;
    char * application_error_msg;
    char * library_error_msg;
} CertifierError;

void error_clear(CertifierError * error);

enum
{
    MBEDTLS_SECURITY_INIT_1_E               = -2000,  /* mbedtls_ctr_drbg_seed() failed in security_init() */
    MBEDTLS_BER_TO_DER_ASN_PARSE_E          = -3000,  /* ASN parsing error, invalid input */
    MBEDTLS_BER_TO_DER_MEMORY_E             = -3001,  /* out of memory error */
    MBEDTLS_BER_TO_DER_BUFFER_E             = -3002,  /* output buffer too small or input too large */
    MBEDTLS_BER_TO_DER_BAD_FUNC_ARG_E       = -3003,  /* Bad function argument provided */
    MBEDTLS_BER_TO_DER_LENGTH_ONLY_E        = -3004,  /* Returning output length only */
    MBEDTLS_PERSIST_PKCS12_1_E              = -4000,  /* ```mbedtls_md_setup()``` failed */
    MBEDTLS_PERSIST_PKCS12_2_E              = -4001,  /* could not allocate enough memory for u16_pwd */
    MBEDTLS_PERSIST_PKCS12_3_E              = -4002,  /* could not allocate enough memory for buf */
    MBEDTLS_PERSIST_PKCS12_4_E              = -4003,  /* could not allocate enough memory for cert_bag */
    MBEDTLS_PERSIST_PKCS12_5_E              = -4004,  /* could not allocate enough memory for key bag */
    MBEDTLS_PERSIST_PKCS12_6_E              = -4005,  /* could not allocate enough memory for encrypted cert bag */
    MBEDTLS_PERSIST_PKCS12_7_E              = -4006,  /* could not allocate enough memory for encrypted key bag */
    MBEDTLS_PERSIST_PKCS12_8_E              = -4007,  /* 1st ```security_get_random_bytes()``` call failed. */
    MBEDTLS_PERSIST_PKCS12_9_E              = -4008,  /* 2nd ```security_get_random_bytes()``` call failed. */
    MBEDTLS_PERSIST_PKCS12_10_E             = -4009,  /* 3rd ```security_get_random_bytes()``` call failed. */
    MBEDTLS_PERSIST_PKCS12_11_E             = -4010,  /* 4th ```security_get_random_bytes()``` call failed. */
    MBEDTLS_PERSIST_PKCS12_12_E             = -4011,  /* 5th ```security_get_random_bytes()``` call failed. */
    MBEDTLS_PERSIST_PKCS12_13_E             = -4012,  /* ```serialize_cert_bag()``` len <= 0 */
    MBEDTLS_PERSIST_PKCS12_14_E             = -4013,  /* encrypted_cert_bag_len == 0 */
    MBEDTLS_PERSIST_PKCS12_15_E             = -4014,  /* pkcs8_key_len <= 0 */
    MBEDTLS_PERSIST_PKCS12_16_E             = -4015,  /* ```mbedtls_mpi_add_int()``` failed */
    MBEDTLS_PERSIST_PKCS12_17_E             = -4016,  /* ```mbedtls_md_hmac_starts()``` failed */
    MBEDTLS_PERSIST_PKCS12_18_E             = -4017,  /* ```mbedtls_md_hmac_update()``` failed */
    MBEDTLS_PERSIST_PKCS12_19_E             = -4018,  /* ```mbedtls_md_hmac_finish()``` failed */
    MBEDTLS_PARSE_CERTIFICATE_LIST_1_E      = -5000,  /* ```mbedtls_asn1_get_tag()``` in 1 failure */
    MBEDTLS_PARSE_CERTIFICATE_LIST_2_E      = -5001,  /* ```asn1_confirm_oid()``` in 1 failure */
    MBEDTLS_PARSE_CERTIFICATE_LIST_3_E      = -5002,  /* ```mbedtls_asn1_get_tag()``` in 2 failure */
    MBEDTLS_PARSE_CERTIFICATE_LIST_4_E      = -5003,  /* ```mbedtls_asn1_get_tag()``` in 3 failure */
    MBEDTLS_PARSE_CERTIFICATE_LIST_5_E      = -5004,  /* ```asn1_confirm_oid()``` in 2 failure */
    MBEDTLS_PARSE_CERTIFICATE_LIST_6_E      = -5005,  /* ```mbedtls_asn1_get_tag()``` in 4 failure */
    MBEDTLS_PARSE_CERTIFICATE_LIST_7_E      = -5006,  /* ```mbedtls_asn1_get_tag()``` in 5 failure */
    MBEDTLS_PARSE_PKCS12_1_E                = -6000,  /* null pkcs12 file */
    MBEDTLS_PARSE_PKCS12_2_E                = -6001,  /* file length of pkcs 12 file < 0 */
    MBEDTLS_PARSE_PKCS12_3_E                = -6002,  /* could not allocate enough memory for pkcs12_data */
    MBEDTLS_PARSE_PKCS12_4_E                = -6003,  /* got != file_len during fread of pkcs12 */
    MBEDTLS_PARSE_PKCS12_5_E                = -6004,  /* ```mbedtls_asn1_get_tag()``` failure */
    MBEDTLS_PARSE_PKCS12_6_E                = -6005,  /* ```mbedtls_asn1_get_int()``` failure on pkcs7 version */
    MBEDTLS_PARSE_PKCS12_7_E                = -6006,  /* pkcs7 version was not 3 */
    MBEDTLS_PARSE_PKCS12_8_E                = -6007,  /* ```mbedtls_asn1_get_tag()``` failure */
    MBEDTLS_PARSE_PKCS12_9_E                = -6008,  /* asn1_confirm_oid()``` failure */
    MBEDTLS_PARSE_PKCS12_10_E               = -6009,  /* ```mbedtls_asn1_get_tag()``` failure */
    MBEDTLS_PARSE_PKCS12_11_E               = -6010,  /* ```mbedtls_asn1_get_tag()``` failure */
    MBEDTLS_PARSE_PKCS12_12_E               = -6011,  /* ```mbedtls_asn1_get_tag()``` failure */
    MBEDTLS_PARSE_PKCS12_13_E               = -6012,  /* ```mbedtls_asn1_get_tag()``` failure */
    MBEDTLS_PARSE_PKCS12_14_E               = -6013,  /* ```asn1_confirm_oid()``` failure */
    MBEDTLS_PARSE_PKCS12_15_E               = -6014,  /* ```mbedtls_asn1_get_tag()``` failure */
    MBEDTLS_PARSE_PKCS12_16_E               = -6015,  /* ```mbedtls_asn1_get_tag()``` failure */
    MBEDTLS_PARSE_PKCS12_17_E               = -6016,  /* ```mbedtls_asn1_get_int()``` failure on pkcs7 version */
    MBEDTLS_PARSE_PKCS12_18_E               = -6017,  /* pkcs7 version was not zero */
    MBEDTLS_PARSE_PKCS12_19_E               = -6018,  /* ```mbedtls_asn1_get_tag()``` failure */
    MBEDTLS_PARSE_PKCS12_20_E               = -6019,  /* ```asn1_confirm_oid()``` failure */
    MBEDTLS_PARSE_PKCS12_21_E               = -6020,  /* ```mbedtls_asn1_get_alg()``` failure */
    MBEDTLS_PARSE_PKCS12_22_E               = -6021,  /* ```MBEDTLS_OID_CMP``` failure */
    MBEDTLS_PARSE_PKCS12_23_E               = -6022,  /* ```mbedtls_asn1_get_tag()``` failure */
    MBEDTLS_PARSE_PKCS12_24_E               = -6023,  /* ```test_pkcs5_pbes2()``` failure */
    MBEDTLS_PARSE_PKCS12_25_E               = -6024,  /* ```mbedtls_asn1_get_tag()``` failure */
    MBEDTLS_PARSE_PKCS12_26_E               = -6025,  /* ```asn1_confirm_oid()``` failure */
    MBEDTLS_PARSE_PKCS12_27_E               = -6026,  /* ```mbedtls_asn1_get_tag()``` failure */
    MBEDTLS_PARSE_PKCS12_28_E               = -6027,  /* ```mbedtls_asn1_get_tag()``` failure */
    MBEDTLS_PARSE_PKCS12_29_E               = -6028,  /* ```parse_shrouded_pkcs12_key()``` failure */
    MBEDTLS_LOAD_CERTS_FROM_PKCS7_1_E       = -7000,  /* X509 list passed in was null */
    MBEDTLS_LOAD_CERTS_FROM_PKCS7_2_E       = -7001,  /* ```mbedtls_pem_read_buffer()``` returned non zero */
    MBEDTLS_LOAD_CERTS_FROM_PKCS7_3_E       = -7002,  /* Could not allocate enough memory for der */
    MBEDTLS_LOAD_CERTS_FROM_PKCS7_4_E       = -7003,  /* ```mbedtls_asn1_get_tag()``` failed */
    MBEDTLS_LOAD_CERTS_FROM_PKCS7_5_E       = -7004,  /* ```mbedtls_asn1_get_tag()``` failed */
    MBEDTLS_LOAD_CERTS_FROM_PKCS7_6_E       = -7005,  /* ```mbedtls_asn1_get_tag()``` failed */
    MBEDTLS_LOAD_CERTS_FROM_PKCS7_7_E       = -7006,  /* ```mbedtls_asn1_get_tag()``` failed */
    MBEDTLS_LOAD_CERTS_FROM_PKCS7_8_E       = -7007,  /* ```mbedtls_asn1_get_int()``` failed */
    MBEDTLS_LOAD_CERTS_FROM_PKCS7_9_E       = -7008,  /* ```pkcs7_version``` != 1 */
    MBEDTLS_LOAD_CERTS_FROM_PKCS7_10_E      = -7009,  /* ```mbedtls_asn1_get_tag()``` failed */
    MBEDTLS_LOAD_CERTS_FROM_PKCS7_11_E      = -7010,  /* ```mbedtls_asn1_get_tag()``` failed */
    MBEDTLS_LOAD_CERTS_FROM_PKCS7_12_E      = -7011,  /* ```asn1_confirm_oid()``` failed */
    MBEDTLS_LOAD_CERTS_FROM_PKCS7_13_E      = -7012,  /* Could not allocate enough memory for certs */
    MBEDTLS_LOAD_CERTS_FROM_PKCS7_14_E      = -7013,  /* ```mbedtls_asn1_get_tag()``` failed */
    MBEDTLS_LOAD_CERTS_FROM_PKCS7_15_E      = -7014,  /* ```mbedtls_x509_crt_parse_der()``` failed */
    MBEDTLS_LOAD_CERTS_FROM_CERTIFICATE_1_E = -8000,  /* x509 list passed in was null */
    MBEDTLS_LOAD_CERTS_FROM_CERTIFICATE_2_E = -8001,  /* ```mbedtls_pem_read_buffer()``` returned non zero */
    MBEDTLS_LOAD_CERTS_FROM_CERTIFICATE_3_E = -8002,  /* Could not allocate enough memory for certs */
    MBEDTLS_LOAD_CERTS_FROM_CERTIFICATE_4_E = -8003,  /* ```mbedtls_x509_crt_parse_der()``` returned non zero */
    MBEDTLS_CHECK_X509_VALID_RANGE_1_E      = -9000,  /* ```sim_time_len <= 0 || sim_time_len > 17``` */
    MBEDTLS_CHECK_X509_VALID_RANGE_2_E      = -9001,  /* ```read_sim_time()``` failure */
    MBEDTLS_CHECK_X509_VALID_RANGE_3_E      = -9002,  /* ```x509_time_cmp_timet()``` failure */
    MBEDTLS_CHECK_X509_VALID_RANGE_4_E      = -9003,  /* ```x509_time_cmp_timet()``` failure */
    MBEDTLS_CHECK_X509_VALID_RANGE_5_E      = -9004,  /* ```read_sim_time()``` failure */
    MBEDTLS_CHECK_X509_VALID_RANGE_6_E      = -9005,  /* ```x509_time_cmp_timet()``` failure */
    MBEDTLS_CHECK_X509_VALID_RANGE_7_E      = -9006,  /* ```x509_time_cmp_timet()``` failure */
    MBEDTLS_CHECK_X509_VALID_RANGE_8_E      = -9007,  /* ```diff_day * SECS_IN_DAY + diff_sec) < min_secs_left``` */
    MBEDTLS_CHECK_X509_VALID_RANGE_9_E      = -9008,  /* ```(sim_time_len <= 0 || sim_time_len > 17)``` */
    MBEDTLS_READ_SIM_TIME_1_ERR             = -10000, /* ```tm_len != 13 && tm_len != 15``` */
    MBEDTLS_READ_SIM_TIME_2_ERR             = -10001, /* ```mbedtls_x509_get_time()``` failure */

};

char * error_strerror(int e);

#ifdef __cplusplus
}
#endif

#endif // LIBLEDGER_ERROR_H
