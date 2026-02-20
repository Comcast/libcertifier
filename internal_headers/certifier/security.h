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

#ifndef SECURITY_H
#define SECURITY_H

#include "certifier/error.h"
#include "certifier/property_internal.h"
#include "certifier/types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VALIDATE_CERT 0x1
#define VALIDATE_SIGNATURE 0x2

#define CERTIFIER_ERR_SECURITY_ENCODE_1 1
#define CERTIFIER_ERR_SECURITY_ENCODE_2 2
#define CERTIFIER_ERR_SECURITY_ENCODE_3 3
#define CERTIFIER_ERR_SECURITY_ENCODE_4 5

#define CERTIFIER_SHA1_DIGEST_LENGTH 20

CertifierError security_init(void);

void security_destroy(void);

CertifierError security_post_init(const char * cfg_file);

/*
 * Operations on ECC keys
 */

CertifierError security_find_or_create_keys(CertifierPropMap * properties, const char * keystore, const char * password,
                                            X509_LIST * certs, const char * curve_id, ECC_KEY ** out);

ECC_KEY * security_create_new_ec_key(CertifierPropMap * properties, const char * curve_id);

char * security_sign_hash_b64(const ECC_KEY * key, const unsigned char * digest, const size_t digest_len);

unsigned char * security_sign_hash(const ECC_KEY * key, const unsigned char * digest, const size_t digest_len, size_t * sig_len);

int security_verify_hash(ECC_KEY * key, const unsigned char * sig, size_t sig_len, const unsigned char * digest, size_t digest_len);

CertifierError security_verify_signature(ECC_KEY * key, const char * signature_base64, const unsigned char * message,
                                         int message_len);

ECC_KEY * security_get_key_from_der(unsigned char * der_public_key, int der_public_key_len);

ECC_KEY * security_get_private_key_from_der(unsigned char * der_key, int der_key_len);

/**
 * Serializes ec_key to der_public_key (caller must free when NULL is passed in *der_public_key)
 * Returns length of der_public_key or 0 on error.
 */
int security_serialize_der_public_key(ECC_KEY * ec_key, unsigned char ** der_public_key);

int security_serialize_raw_public_key(ECC_KEY * ec_key, unsigned char * public_key, size_t public_key_capacity);

int security_serialize_raw_private_key(ECC_KEY * ec_key, unsigned char * private_key, size_t private_key_capacity);

void security_free_eckey(ECC_KEY * eckey);

ECC_KEY * security_dup_eckey(const ECC_KEY * eckey);

char * security_encode(const unsigned char * encoded_public_key, int len, int * return_code);

/*
 * Hash Functions
 */

typedef struct sha1_ctx_st sha1_ctx;

sha1_ctx * security_sha1_init();

int security_sha1(unsigned char * output, const unsigned char * input, size_t input_len);

int security_sha1_update(sha1_ctx * ctx, const unsigned char * input, size_t len);

/* writes hash to digest and frees ctx */
int security_sha1_finish(sha1_ctx * ctx, unsigned char * digest);

int security_sha256(unsigned char * output, const unsigned char * input, size_t input_len);

CertifierError security_rmd160(unsigned char * output, const unsigned char * input, size_t input_len);

typedef struct sha256_ctx_st sha256_ctx;

sha256_ctx * security_sha256_init();

int security_sha256_update(sha256_ctx * ctx, const unsigned char * input, size_t len);

int security_sha256_update_cstr(sha256_ctx * ctx, const char * str);

/* writes hash to digest and frees ctx */
int security_sha256_finish(sha256_ctx * ctx, unsigned char * digest);

/*
 * Certificate Handling
 */

/*
 * Return the PEM formatted root CA that we trust
 */
const char * old_digicert_root_ca(void);

/*
 * Return the PEM formatted intermediate CA (issued by the root CA)
 * which is used to sign the node signatures
 */
const char * old_digicert_int_ca(void);

char * security_generate_certificate_signing_request(ECC_KEY * eckey, int * retlen);

unsigned char * security_generate_csr(ECC_KEY * eckey, size_t * retlen);

int security_persist_pkcs_12_file(const char * filename, const char * pwd, ECC_KEY * prikey, X509_CERT * cert, X509_LIST * certs,
                                  CertifierError * CertifierError);

char * security_get_field_from_cert(X509_CERT * cert, const char * field_name);

ECC_KEY * security_get_key_from_cert(X509_CERT * cert);

/**
 * Check an X509 certificate's time validity
 * @param current_time Now (or your idea of now)
 * @param min_secs_left The minimum seconds remaining allowed until expiration.
 * @param cert The X509 certificate to check
 * @param cert_before_time NULL, or a valid simulated ASN.1 time in the format YYYYMMDDHHMMSSZ
 * @param cert_after_time NULL, or a valid simulated ASN.1 time
 * @return 0 if valid, or one of: <br>
 *  - CERTIFIER_ERR_REGISTRATION_STATUS_SIMULATION_1: cert_before_time not parsable <br>
 *  - CERTIFIER_ERR_REGISTRATION_STATUS_SIMULATION_2: cert_after_time not parsable <br>
 *  - CERTIFIER_ERR_REGISTRATION_STATUS_CERT_EXPIRED_1: certificate not yet valid <br>
 *  - CERTIFIER_ERR_REGISTRATION_STATUS_CERT_EXPIRED_2: certificate expired <br>
 *  - CERTIFIER_ERR_REGISTRATION_STATUS_CERT_ABOUT_TO_EXPIRE: &lt;not-after-date&gt; - &lt;current_time&gt < &lt;min_secs_left&gt
 */
CertifierError security_check_x509_valid_range(time_t current_time, long min_secs_left, X509_CERT * cert,
                                               const char * cert_before_time, const char * cert_after_time);

int security_get_before_time_validity(const X509_CERT * cert, char * time, size_t time_len);

int security_get_not_after_time_validity(const X509_CERT * cert, char * time, size_t time_len);

CertifierError security_verify_x509(X509_CERT * cert, const char * signature_b64, const unsigned char * input, int input_len,
                                    const char * security_cert_root_ca, const char * security_cert_int_ca, int security_flags,
                                    time_t * overridden_time_t);

/**
 * Verify certificate status. This assumes the cert was verified
 * by the compiled in trusted CA.
 */
CertifierError security_check_cert_is_valid(X509_CERT * cert, const char * security_cert_root_ca, const char * security_cert_int_ca,
                                            time_t * overridden_time_t);

CertifierError security_get_X509_PKCS12_file(const char * filename, const char * password, X509_LIST * certs, X509_CERT ** out,
                                             ECC_KEY ** out_keypair);

void security_free_cert(X509_CERT * cert);

X509_CERT * security_dup_cert(const X509_CERT * cert);

/*
 * Certificate List Hnadling
 */
X509_LIST * security_new_cert_list(void);

/**
 * Extract a certificate from a list
 * @param certs
 * @param which The nth (0-indexed) certificate to select
 * @return An X509 certificate or NULL on failure
 * @warning The result is freed by security_free_cert_list. Do not free or refer to it beyond the list's lifetime.
 */
X509_CERT * security_cert_list_get(X509_LIST * certs, int which);

/**
 * Extract and delete a certificate from a list
 * @param certs
 * @param which The nth (0-indexed) certificate to select
 * @return An X509 certificate or NULL on failure
 * @warning The result is freed by security_free_cert_list. Caller owns the certficate now, since it was removed from the list.
 */
X509_CERT * security_cert_list_pop(X509_LIST * certs, int which);

CertifierError security_load_certs_from_pem(const char * pem, X509_LIST ** out, bool load_all_certs);

void security_print_certs_in_list(X509_LIST * certs, XFILE output);

void security_free_cert_list(X509_LIST * cert);

/*
 * Misc operations
 */
int security_get_random_bytes(unsigned char * out, int len);

unsigned char * security_X509_to_DER(X509_CERT * cert, size_t * out_len);

X509_CERT * security_X509_from_DER(const unsigned char * der, size_t der_len);

void security_print_subject_issuer(const X509_CERT * cert);

/**
 * Create a Certificate Request Token with a signed X509 certificate
 * @param output_serialized_string A CRT JSON document (caller must free)
 * @param x509_cert The public client certificate
 * @param private_ec_key The client certificate private key
 * @param token An optional Device Association Request (dar) token
 * @return
 */
int security_generate_x509_crt(char ** output_serialized_string, X509_CERT * x509_cert, ECC_KEY * private_ec_key);

char * security_get_version(void);

char * security_aws_sign(char * const str, char * const awskey);

#ifdef __cplusplus
}
#endif

#endif
