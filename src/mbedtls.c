
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

typedef int make_iso_compilers_happy;

#if defined(USE_MBEDTLS)

#include "certifier/base64.h"
#include "certifier/certifier_internal.h"
#include "certifier/error.h"
#include "certifier/log.h"
#include "certifier/security.h"
#include "certifier/types.h"
#include "certifier/util.h"

#include <mbedtls/asn1write.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/oid.h>
#include <mbedtls/pem.h>
#include <mbedtls/pkcs12.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/ripemd160.h>
#include <mbedtls/sha256.h>
#include <mbedtls/version.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>

#define MBEDTLS_ERR_1 100000
#define MBEDTLS_ERR_2 200000
#define MBEDTLS_ERR_3 300000
#define MBEDTLS_ERR_4 400000
#define MBEDTLS_ERR_5 5000
#define MBEDTLS_ERR_6 6000

#ifdef __KLOCWORK__
#define MBEDTLS_ASN1_CHK_ADD(g, f)                                                                                                 \
    do                                                                                                                             \
    {                                                                                                                              \
        if (!(g))                                                                                                                  \
            abort();                                                                                                               \
    } while (0)
#endif

#define SHA256_DIGEST_LENGTH 32
#define RIPEMD160_DIGEST_LENGTH 20

#define _MBEDTLS_OID_BAG_TYPES MBEDTLS_OID_PKCS12 "\x0a\x01"
#define _MBEDTLS_OID_KEY_BAG_TYPE _MBEDTLS_OID_BAG_TYPES "\x01"
#define _MBEDTLS_OID_PKCS8_BAG_TYPE _MBEDTLS_OID_BAG_TYPES "\x02"
#define _MBEDTLS_OID_CERT_BAG_TYPE _MBEDTLS_OID_BAG_TYPES "\x03"

#define _MBEDTLS_OID_PKCS9_CERT_TYPES MBEDTLS_OID_PKCS9 "\x16"
#define _MBEDTLS_OID_PKCS9_X509_CERT _MBEDTLS_OID_PKCS9_CERT_TYPES "\x01"

#define _MBEDTLS_OID_PKCS7 MBEDTLS_OID_PKCS "\x07"
#define _MBEDTLS_OID_PKCS7_DATA _MBEDTLS_OID_PKCS7 "\x01"
#define _MBEDTLS_OID_PKCS7_SIGNED_DATA _MBEDTLS_OID_PKCS7 "\x02"
#define _MBEDTLS_OID_PKCS7_ENC_DATA _MBEDTLS_OID_PKCS7 "\x06"

#define _MBEDTLS_OID_AES_128_CBC MBEDTLS_OID_GOV "\x03\x04\x01\x02"

#define _MBEDTLS_ECC_OID MBEDTLS_OID_ANSI_X9_62 "\x02\x01"
#define _MBEDTLS_ECC_P256_OID MBEDTLS_OID_ANSI_X9_62 "\x03\x01\x07"

#define SECS_IN_DAY 86400

// Global PRNG instance

static mbedtls_entropy_context entropy_ctx;
static mbedtls_ctr_drbg_context rng_ctx;

static void fill_in_library_error_message_as_required(CertifierError * error)
{
    if (!error)
    {
        return;
    }

    int code = error->library_error_code;

    if (code == 0)
    {
        // no error
        return;
    }

    int size = 500;
    char error_buf[200];

    char * result = NULL;
    result        = XMALLOC(size);
    if (result == NULL)
    {
        log_error("Could not allocate enough memory for result.");
        return;
    }

    mbedtls_strerror(code, error_buf, 200);
    XSNPRINTF(result, size, "Last error was: -0x%04x - %s\n\n", (int) -code, error_buf);

    error->library_error_msg = util_format_error(__func__, result, __FILE__, __LINE__);

    XFREE(result);
}

// Functions
CertifierError security_init(void)
{

    CertifierError result = CERTIFIER_ERROR_INITIALIZER;
    error_clear(&result);

    int rc = 0;

    mbedtls_ctr_drbg_init(&rng_ctx);
    mbedtls_entropy_init(&entropy_ctx);

    rc = mbedtls_ctr_drbg_seed(&rng_ctx, mbedtls_entropy_func, &entropy_ctx, NULL, 0);
    if (rc != 0)
    {
        result.application_error_code = MBEDTLS_SECURITY_INIT_1_E;
        result.library_error_code     = rc;
        fill_in_library_error_message_as_required(&result);
    }

    return result;

} /* security_init */

void security_destroy(void)
{

    mbedtls_ctr_drbg_free(&rng_ctx);
    mbedtls_entropy_free(&entropy_ctx);
} /* security_destroy */

unsigned char * security_generate_csr(ECC_KEY * eckey, size_t * retlen)
{
    mbedtls_x509write_csr ctx;
    mbedtls_x509write_csr_init(&ctx);

    mbedtls_x509write_csr_set_key(&ctx, eckey);
    mbedtls_x509write_csr_set_md_alg(&ctx, MBEDTLS_MD_SHA256);

    uint8_t csr_buf[4096];
    int len = mbedtls_x509write_csr_der(&ctx, csr_buf, sizeof(csr_buf), mbedtls_ctr_drbg_random, &rng_ctx);
    mbedtls_x509write_csr_free(&ctx);

    if (len > 0)
    {

        unsigned char * res = XMALLOC(len * 1);

        if (res == NULL)
            return NULL;

        XMEMCPY(res, csr_buf + sizeof(csr_buf) - len, len);
        *retlen = len;
        return res;
    }
    return NULL;
} /* generateCertificateSigningRequest */

static int asn1_confirm_oid(unsigned char ** p, unsigned char * end, const char * exp_oid, const size_t exp_oid_len)
{
    int ret = -1;
    size_t oid_len;

    if (ret = mbedtls_asn1_get_tag(p, end, &oid_len, MBEDTLS_ASN1_OID) != 0)
        goto cleanup;

    if (oid_len != exp_oid_len)
        goto cleanup;

    if (XMEMCMP(*p, exp_oid, exp_oid_len) != 0)
        goto cleanup;

    if (ret == 0)
    {
        *p += oid_len;
    }
cleanup:

    return ret;
}

static size_t pbes2_encrypt(const char * password, int iterations, const uint8_t * salt, size_t salt_len, const uint8_t * iv,
                            size_t iv_len, mbedtls_cipher_type_t cipher_alg, const unsigned char * input, size_t input_len,
                            unsigned char * output)
{
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA1;
    unsigned char key[32];
    size_t output_len = 0;
    size_t keylen     = 0;
    const mbedtls_md_info_t * md_info;
    const mbedtls_cipher_info_t * cipher_info;
    mbedtls_md_context_t md_ctx;
    mbedtls_cipher_context_t cipher_ctx;
    int rc = 0;

    cipher_info = mbedtls_cipher_info_from_type(cipher_alg);
    if (cipher_info == NULL)
        goto cleanup;

    md_info = mbedtls_md_info_from_type(md_type);
    if (md_info == NULL)
        goto cleanup;

    keylen = cipher_info->key_bitlen / 8;

    mbedtls_md_init(&md_ctx);

    rc = mbedtls_md_setup(&md_ctx, md_info, /*hmac*/ 1);
    if (rc != 0)
    {
        log_error("mbedtls_md_setup returned code: [%i]", rc);
        goto cleanup;
    }

    rc = mbedtls_pkcs5_pbkdf2_hmac(&md_ctx, (const uint8_t *) password, XSTRLEN(password), salt, salt_len, iterations, keylen, key);
    if (rc != 0)
    {
        log_error("mbedtls_pkcs5_pbkdf2_hmac returned code: [%i]", rc);
        goto cleanup;
    }

    mbedtls_cipher_init(&cipher_ctx);
    rc = mbedtls_cipher_setup(&cipher_ctx, cipher_info);
    if (rc != 0)
    {
        log_error("mbedtls_cipher_setup returned code: [%i]", rc);
        goto cleanup;
    }

    rc = mbedtls_cipher_setkey(&cipher_ctx, key, cipher_info->key_bitlen, MBEDTLS_ENCRYPT);
    if (rc != 0)
    {
        log_error("mbedtls_cipher_setkey returned code: [%i]", rc);
        goto cleanup;
    }

    rc = mbedtls_cipher_crypt(&cipher_ctx, iv, iv_len, input, input_len, output, &output_len);
    if (rc != 0)
    {
        log_error("mbedtls_cipher_crypt returned code: [%i]", rc);
        goto cleanup;
    }
cleanup:
    mbedtls_md_free(&md_ctx);
    mbedtls_cipher_free(&cipher_ctx);

    return output_len;
}

static size_t serialize_pbes2_params(int iterations, const uint8_t salt[], size_t salt_len, const uint8_t iv[], size_t iv_len,
                                     uint8_t ** c, uint8_t * buf)
{
    mbedtls_mpi iter_mpi;
    size_t len  = 0;
    size_t len2 = 0;
    int ret;

    MBEDTLS_ASN1_CHK_ADD(len2, mbedtls_asn1_write_raw_buffer(c, buf, iv, iv_len));
    MBEDTLS_ASN1_CHK_ADD(len2, mbedtls_asn1_write_len(c, buf, iv_len));
    MBEDTLS_ASN1_CHK_ADD(len2, mbedtls_asn1_write_tag(c, buf, MBEDTLS_ASN1_OCTET_STRING));
    MBEDTLS_ASN1_CHK_ADD(len2,
                         mbedtls_asn1_write_oid(c, buf, _MBEDTLS_OID_AES_128_CBC, MBEDTLS_OID_SIZE(_MBEDTLS_OID_AES_128_CBC)));
    MBEDTLS_ASN1_CHK_ADD(len2, mbedtls_asn1_write_len(c, buf, len2));
    MBEDTLS_ASN1_CHK_ADD(len2, mbedtls_asn1_write_tag(c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    mbedtls_mpi_init(&iter_mpi);
    mbedtls_mpi_add_int(&iter_mpi, &iter_mpi, iterations);
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(c, buf, &iter_mpi));
    mbedtls_mpi_free(&iter_mpi);

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(c, buf, salt, salt_len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(c, buf, salt_len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(c, buf, MBEDTLS_ASN1_OCTET_STRING));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_oid(c, buf, MBEDTLS_OID_PKCS5_PBKDF2, MBEDTLS_OID_SIZE(MBEDTLS_OID_PKCS5_PBKDF2)));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    len += len2;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_oid(c, buf, MBEDTLS_OID_PKCS5_PBES2, MBEDTLS_OID_SIZE(MBEDTLS_OID_PKCS5_PBES2)));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    return len;
}

static int serialize_pkcs8_key(uint8_t * buf, size_t buf_len, const ECC_KEY * key)
{
    uint8_t * c    = buf + buf_len;
    size_t len     = 0;
    size_t alg_len = 0;
    int ret        = 0;

    uint8_t key_der[2048];

    int key_der_len = mbedtls_pk_write_key_der((ECC_KEY *) key, key_der, sizeof(key_der));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(&c, buf, key_der + sizeof(key_der) - key_der_len, key_der_len));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_OCTET_STRING));

    MBEDTLS_ASN1_CHK_ADD(alg_len, mbedtls_asn1_write_oid(&c, buf, _MBEDTLS_ECC_P256_OID, MBEDTLS_OID_SIZE(_MBEDTLS_ECC_P256_OID)));
    MBEDTLS_ASN1_CHK_ADD(alg_len, mbedtls_asn1_write_oid(&c, buf, _MBEDTLS_ECC_OID, MBEDTLS_OID_SIZE(_MBEDTLS_ECC_OID)));

    MBEDTLS_ASN1_CHK_ADD(alg_len, mbedtls_asn1_write_len(&c, buf, alg_len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    len += alg_len;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_int(&c, buf, 0)); // version

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    XASSERT(len < buf_len);
    // Realign to the front of the buffer
    XMEMMOVE(buf, buf + buf_len - len, len);

    return len;
}

static int serialize_cert_to_bag(uint8_t ** c, uint8_t * buf, X509_CERT * cert)
{
    int ret    = 0;
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(c, buf, cert->raw.p, cert->raw.len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(c, buf, cert->raw.len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(c, buf, MBEDTLS_ASN1_OCTET_STRING));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0));
    MBEDTLS_ASN1_CHK_ADD(
        len, mbedtls_asn1_write_oid(c, buf, _MBEDTLS_OID_PKCS9_X509_CERT, MBEDTLS_OID_SIZE(_MBEDTLS_OID_PKCS9_X509_CERT)));

    return len;
}

static int serialize_cert_bag(uint8_t * buf, size_t buf_len, X509_CERT * cert, X509_LIST * certs)
{
    uint8_t * c     = buf + buf_len;
    size_t len      = 0;
    int ret         = 0;
    X509_CERT * crt = certs;

    int cert_len;
    while (crt != NULL)
    {
        cert_len = serialize_cert_to_bag(&c, buf, crt);

        MBEDTLS_ASN1_CHK_ADD(cert_len, mbedtls_asn1_write_len(&c, buf, cert_len));
        MBEDTLS_ASN1_CHK_ADD(cert_len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

        MBEDTLS_ASN1_CHK_ADD(cert_len, mbedtls_asn1_write_len(&c, buf, cert_len));
        MBEDTLS_ASN1_CHK_ADD(cert_len,
                             mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0));

        MBEDTLS_ASN1_CHK_ADD(
            cert_len, mbedtls_asn1_write_oid(&c, buf, _MBEDTLS_OID_CERT_BAG_TYPE, MBEDTLS_OID_SIZE(_MBEDTLS_OID_CERT_BAG_TYPE)));

        MBEDTLS_ASN1_CHK_ADD(cert_len, mbedtls_asn1_write_len(&c, buf, cert_len));
        MBEDTLS_ASN1_CHK_ADD(cert_len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

        len += cert_len;
        crt = crt->next;
    }

    cert_len = serialize_cert_to_bag(&c, buf, cert);

    MBEDTLS_ASN1_CHK_ADD(cert_len, mbedtls_asn1_write_len(&c, buf, cert_len));
    MBEDTLS_ASN1_CHK_ADD(cert_len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    MBEDTLS_ASN1_CHK_ADD(cert_len, mbedtls_asn1_write_len(&c, buf, cert_len));
    MBEDTLS_ASN1_CHK_ADD(cert_len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0));

    MBEDTLS_ASN1_CHK_ADD(cert_len,
                         mbedtls_asn1_write_oid(&c, buf, _MBEDTLS_OID_CERT_BAG_TYPE, MBEDTLS_OID_SIZE(_MBEDTLS_OID_CERT_BAG_TYPE)));

    MBEDTLS_ASN1_CHK_ADD(cert_len, mbedtls_asn1_write_len(&c, buf, cert_len));
    MBEDTLS_ASN1_CHK_ADD(cert_len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    len += cert_len;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    // realign to the front of the buffer...
    XMEMMOVE(buf, buf + buf_len - len, len);

    return len;
}

int security_persist_pkcs_12_file(const char * filename, const char * pwd, ECC_KEY * prikey, X509_CERT * cert, X509_LIST * certs,
                                  CertifierError * result)
{

    const size_t buf_size      = 16 * 1024;
    const size_t cert_bag_size = 8 * 1024;
    const size_t key_bag_size  = 4 * 1024;
    uint8_t * buf              = NULL;

    uint8_t * cert_bag           = NULL;
    uint8_t * encrypted_cert_bag = NULL;
    uint8_t * key_bag            = NULL;
    uint8_t * encrypted_key_bag  = NULL;

    XFILE out_file = NULL;
    uint8_t * c    = NULL;
    size_t len     = 0;
    int ret        = -1;
    mbedtls_mpi iter_mpi;

    uint8_t salt_cert[8] = { 0 };
    uint8_t salt_key[8]  = { 0 };
    uint8_t salt_mac[8]  = { 0 };
    uint8_t iv_cert[16]  = { 0 };
    uint8_t iv_key[16]   = { 0 };
    uint8_t mac[20]      = { 0 };
    uint8_t mac_key[20]  = { 0 };
    uint8_t * mac_ptr    = NULL;
    uint8_t * auth_pdu   = NULL;
    size_t auth_pdu_len  = 0;

    const int iterations           = 50000;
    const int mac_iterations       = 50000;
    uint8_t * encrypted_certs      = NULL;
    size_t sub2_len                = 0;
    size_t sub3_len                = 0;
    size_t mac_len                 = 0;
    size_t inner_mac_len           = 0;
    uint8_t * u16_pwd              = NULL;
    size_t u16_pwd_size            = 2 * XSTRLEN(pwd) + 2;
    int cert_bag_len               = 0;
    size_t encrypted_cert_bag_len  = 0;
    int pkcs8_key_len              = 0;
    size_t encrypted_pkcs8_key_len = 0;

    mbedtls_md_context_t hmac_ctx;

    mbedtls_md_init(&hmac_ctx);

    if (ret = mbedtls_md_setup(&hmac_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 1) != 0)
    {
        result->application_error_code = MBEDTLS_PERSIST_PKCS12_1_E;
        goto cleanup;
    }

    u16_pwd = XCALLOC(u16_pwd_size, 1);
    if (u16_pwd == NULL)
    {
        result->application_error_code = MBEDTLS_PERSIST_PKCS12_2_E;
        goto cleanup;
    }

    for (size_t i = 0; i != u16_pwd_size; i += 2)
        u16_pwd[i + 1] = pwd[i / 2];

    buf = XMALLOC(buf_size * 1);
    if (buf == NULL)
    {
        result->application_error_code = MBEDTLS_PERSIST_PKCS12_3_E;
        goto cleanup;
    }

    cert_bag = XMALLOC(cert_bag_size * 1);
    if (cert_bag == NULL)
    {
        result->application_error_code = MBEDTLS_PERSIST_PKCS12_4_E;
        goto cleanup;
    }

    key_bag = XMALLOC(key_bag_size * 1);
    if (key_bag == NULL)
    {
        result->application_error_code = MBEDTLS_PERSIST_PKCS12_5_E;
        goto cleanup;
    }

    encrypted_cert_bag = XMALLOC(cert_bag_size * 1);
    if (encrypted_cert_bag == NULL)
    {
        result->application_error_code = MBEDTLS_PERSIST_PKCS12_6_E;
        goto cleanup;
    }

    encrypted_key_bag = XMALLOC(key_bag_size * 1);
    if (encrypted_key_bag == NULL)
    {
        result->application_error_code = MBEDTLS_PERSIST_PKCS12_7_E;
        goto cleanup;
    }
    c = buf + buf_size;

    if (ret = security_get_random_bytes(salt_cert, sizeof(salt_cert) != 0))
    {
        result->application_error_code = MBEDTLS_PERSIST_PKCS12_8_E;
        goto cleanup;
    }

    if (ret = security_get_random_bytes(salt_key, sizeof(salt_key)))
    {
        result->application_error_code = MBEDTLS_PERSIST_PKCS12_9_E;
        goto cleanup;
    }

    if (ret = security_get_random_bytes(salt_mac, sizeof(salt_mac)))
    {
        result->application_error_code = MBEDTLS_PERSIST_PKCS12_10_E;
        goto cleanup;
    }

    if (ret = security_get_random_bytes(iv_cert, sizeof(iv_cert)))
    {
        result->application_error_code = MBEDTLS_PERSIST_PKCS12_11_E;
        goto cleanup;
    }

    if (ret = security_get_random_bytes(iv_key, sizeof(iv_key)))
    {
        result->application_error_code = MBEDTLS_PERSIST_PKCS12_12_E;
        goto cleanup;
    }

    cert_bag_len = serialize_cert_bag(cert_bag, cert_bag_size, cert, certs);

    if (cert_bag_len <= 0)
    {
        result->application_error_code = MBEDTLS_PERSIST_PKCS12_13_E;
        goto cleanup;
    }

    encrypted_cert_bag_len = pbes2_encrypt(pwd, iterations, salt_cert, sizeof(salt_cert), iv_cert, sizeof(iv_cert),
                                           MBEDTLS_CIPHER_AES_128_CBC, cert_bag, cert_bag_len, encrypted_cert_bag);

    if (encrypted_cert_bag_len == 0)
    {
        result->application_error_code = MBEDTLS_PERSIST_PKCS12_14_E;
        goto cleanup;
    }
    pkcs8_key_len = serialize_pkcs8_key(key_bag, key_bag_size, prikey);

    if (pkcs8_key_len <= 0)
    {
        result->application_error_code = MBEDTLS_PERSIST_PKCS12_15_E;
        goto cleanup;
    }

    encrypted_pkcs8_key_len = pbes2_encrypt(pwd, iterations, salt_key, sizeof(salt_key), iv_key, sizeof(iv_key),
                                            MBEDTLS_CIPHER_AES_128_CBC, key_bag, pkcs8_key_len, encrypted_key_bag);

    mbedtls_pkcs12_derivation(mac_key, sizeof(mac_key), u16_pwd, u16_pwd_size, salt_mac, sizeof(salt_mac), MBEDTLS_MD_SHA1, 0x3,
                              mac_iterations);

    mbedtls_mpi_init(&iter_mpi);
    ret = mbedtls_mpi_add_int(&iter_mpi, &iter_mpi, mac_iterations);
    if (ret != 0)
    {
        result->application_error_code = MBEDTLS_PERSIST_PKCS12_16_E;
        goto cleanup;
    }

    MBEDTLS_ASN1_CHK_ADD(inner_mac_len, mbedtls_asn1_write_mpi(&c, buf, &iter_mpi));
    mbedtls_mpi_free(&iter_mpi);
    MBEDTLS_ASN1_CHK_ADD(inner_mac_len, mbedtls_asn1_write_raw_buffer(&c, buf, salt_mac, sizeof(salt_mac)));
    MBEDTLS_ASN1_CHK_ADD(inner_mac_len, mbedtls_asn1_write_len(&c, buf, sizeof(salt_mac)));
    MBEDTLS_ASN1_CHK_ADD(inner_mac_len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_OCTET_STRING));

    mac_len = 0;

    MBEDTLS_ASN1_CHK_ADD(mac_len, mbedtls_asn1_write_raw_buffer(&c, buf, mac, sizeof(mac)));
    mac_ptr = c;
    MBEDTLS_ASN1_CHK_ADD(mac_len, mbedtls_asn1_write_len(&c, buf, sizeof(mac)));
    MBEDTLS_ASN1_CHK_ADD(mac_len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_OCTET_STRING));

    MBEDTLS_ASN1_CHK_ADD(mac_len,
                         mbedtls_asn1_write_algorithm_identifier(&c, buf, MBEDTLS_OID_DIGEST_ALG_SHA1,
                                                                 MBEDTLS_OID_SIZE(MBEDTLS_OID_DIGEST_ALG_SHA1), 0));

    MBEDTLS_ASN1_CHK_ADD(mac_len, mbedtls_asn1_write_len(&c, buf, mac_len));
    MBEDTLS_ASN1_CHK_ADD(mac_len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    mac_len += inner_mac_len;
    MBEDTLS_ASN1_CHK_ADD(mac_len, mbedtls_asn1_write_len(&c, buf, mac_len));
    MBEDTLS_ASN1_CHK_ADD(mac_len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    sub3_len = 0;
    MBEDTLS_ASN1_CHK_ADD(sub3_len, mbedtls_asn1_write_raw_buffer(&c, buf, encrypted_key_bag, encrypted_pkcs8_key_len));
    MBEDTLS_ASN1_CHK_ADD(sub3_len, mbedtls_asn1_write_len(&c, buf, encrypted_pkcs8_key_len));
    MBEDTLS_ASN1_CHK_ADD(sub3_len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_OCTET_STRING));
    sub3_len += serialize_pbes2_params(iterations, salt_key, sizeof(salt_key), iv_key, sizeof(iv_key), &c, buf);
    MBEDTLS_ASN1_CHK_ADD(sub3_len, mbedtls_asn1_write_len(&c, buf, sub3_len));
    MBEDTLS_ASN1_CHK_ADD(sub3_len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    MBEDTLS_ASN1_CHK_ADD(sub3_len, mbedtls_asn1_write_len(&c, buf, sub3_len));
    MBEDTLS_ASN1_CHK_ADD(sub3_len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0));
    MBEDTLS_ASN1_CHK_ADD(
        sub3_len, mbedtls_asn1_write_oid(&c, buf, _MBEDTLS_OID_PKCS8_BAG_TYPE, MBEDTLS_OID_SIZE(_MBEDTLS_OID_PKCS8_BAG_TYPE)));
    MBEDTLS_ASN1_CHK_ADD(sub3_len, mbedtls_asn1_write_len(&c, buf, sub3_len));
    MBEDTLS_ASN1_CHK_ADD(sub3_len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    MBEDTLS_ASN1_CHK_ADD(sub3_len, mbedtls_asn1_write_len(&c, buf, sub3_len));
    MBEDTLS_ASN1_CHK_ADD(sub3_len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    MBEDTLS_ASN1_CHK_ADD(sub3_len, mbedtls_asn1_write_len(&c, buf, sub3_len));
    MBEDTLS_ASN1_CHK_ADD(sub3_len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_OCTET_STRING));
    MBEDTLS_ASN1_CHK_ADD(sub3_len, mbedtls_asn1_write_len(&c, buf, sub3_len));
    MBEDTLS_ASN1_CHK_ADD(sub3_len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0));
    MBEDTLS_ASN1_CHK_ADD(sub3_len,
                         mbedtls_asn1_write_oid(&c, buf, _MBEDTLS_OID_PKCS7_DATA, MBEDTLS_OID_SIZE(_MBEDTLS_OID_PKCS7_DATA)));
    MBEDTLS_ASN1_CHK_ADD(sub3_len, mbedtls_asn1_write_len(&c, buf, sub3_len));
    MBEDTLS_ASN1_CHK_ADD(sub3_len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    sub2_len = 0;
    MBEDTLS_ASN1_CHK_ADD(sub2_len, mbedtls_asn1_write_raw_buffer(&c, buf, encrypted_cert_bag, encrypted_cert_bag_len));
    MBEDTLS_ASN1_CHK_ADD(sub2_len, mbedtls_asn1_write_len(&c, buf, encrypted_cert_bag_len));
    MBEDTLS_ASN1_CHK_ADD(sub2_len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0));
    // sub2_len value is used below

    len += serialize_pbes2_params(iterations, salt_cert, sizeof(salt_cert), iv_cert, sizeof(iv_cert), &c, buf);

    len += sub2_len;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_oid(&c, buf, _MBEDTLS_OID_PKCS7_DATA, MBEDTLS_OID_SIZE(_MBEDTLS_OID_PKCS7_DATA)));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_int(&c, buf, 0)); // PKCS 7 version
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0));

    MBEDTLS_ASN1_CHK_ADD(
        len, mbedtls_asn1_write_oid(&c, buf, _MBEDTLS_OID_PKCS7_ENC_DATA, MBEDTLS_OID_SIZE(_MBEDTLS_OID_PKCS7_ENC_DATA)));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    len += sub3_len;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    auth_pdu     = c;
    auth_pdu_len = len;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_OCTET_STRING));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_oid(&c, buf, _MBEDTLS_OID_PKCS7_DATA, MBEDTLS_OID_SIZE(_MBEDTLS_OID_PKCS7_DATA)));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    len += mac_len;
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_int(&c, buf, 3)); // PKCS 12 version
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    ret = mbedtls_md_hmac_starts(&hmac_ctx, mac_key, sizeof(mac_key));
    if (ret != 0)
    {
        result->application_error_code = MBEDTLS_PERSIST_PKCS12_17_E;
        goto cleanup;
    }
    ret = mbedtls_md_hmac_update(&hmac_ctx, auth_pdu, auth_pdu_len);
    if (ret != 0)
    {
        result->application_error_code = MBEDTLS_PERSIST_PKCS12_18_E;
        goto cleanup;
    }
    ret = mbedtls_md_hmac_finish(&hmac_ctx, mac_ptr);
    if (ret != 0)
    {
        result->application_error_code = MBEDTLS_PERSIST_PKCS12_19_E;
        goto cleanup;
    }

    out_file = XFOPEN(filename, "wb");
    if (out_file != NULL)
    {
        XFWRITE(buf + buf_size - len, len, 1, out_file);

        ret = 0;
    }
cleanup:
    if (out_file)
    {
        XFCLOSE(out_file);
    }
    mbedtls_md_free(&hmac_ctx);
    XFREE(u16_pwd);
    XFREE(buf);
    XFREE(cert_bag);
    XFREE(encrypted_certs);
    XFREE(key_bag);
    XFREE(encrypted_key_bag);
    XFREE(encrypted_cert_bag);

    if (ret != 0)
    {
        result->library_error_code = ret;
        fill_in_library_error_message_as_required(result);
    }

    return ret;
} /* persistPkcs12File */

struct sha256_ctx_st
{
    mbedtls_sha256_context h;
};

sha256_ctx * security_sha256_init()
{
    sha256_ctx * ctx = XCALLOC(1, sizeof(struct sha256_ctx_st));
    mbedtls_sha256_starts(&ctx->h, 0);
    return ctx;
}

int security_sha256_update(sha256_ctx * ctx, const unsigned char input[], size_t len)
{
    mbedtls_sha256_update(&ctx->h, input, len);
    return 0;
}

int security_sha256_finish(sha256_ctx * ctx, unsigned char * digest)
{
    mbedtls_sha256_finish(&ctx->h, digest);
    XFREE(ctx);
    return 0;
}

CertifierError security_rmd160(uint8_t * digest, const uint8_t * message, size_t len)
{
    CertifierError result = CERTIFIER_ERROR_INITIALIZER;
    mbedtls_ripemd160_context ctx;
    mbedtls_ripemd160_starts(&ctx);
    mbedtls_ripemd160_update(&ctx, message, len);
    mbedtls_ripemd160_finish(&ctx, digest);
    return result;
}

unsigned char * security_sign_hash(const ECC_KEY * ecc_key, const unsigned char * digest, const size_t digest_len, size_t * sig_len)
{

    unsigned char * der = NULL;
    size_t der_len      = 0;
    int err             = 0;

    der_len = MBEDTLS_ECDSA_MAX_LEN;
    der     = (unsigned char *) XMALLOC(der_len * sizeof(unsigned char));

    err = mbedtls_ecdsa_write_signature(mbedtls_pk_ec(*ecc_key), MBEDTLS_MD_SHA256, digest, digest_len, der, &der_len,
                                        mbedtls_ctr_drbg_random, &rng_ctx);

    if (err != 0)
    {
        XFREE(der);
        return NULL;
    }

    *sig_len = der_len;

    return der;
}

ECC_KEY * security_create_new_ec_key(CertifierPropMap * properties, const char * curve_id)
{
    ECC_KEY * keypair = XMALLOC(sizeof(ECC_KEY));

    if (keypair == NULL)
    {
        return NULL;
    }

    if (curve_id == NULL)
    {
        security_free_eckey(keypair);
        return NULL;
    }

    // TODO:  map the curve_id string value to the corresponding value below.
    // hack for now...
    if (XSTRCMP(curve_id, "prime256v1") != 0)
    {
        security_free_eckey(keypair);
        return NULL;
    }

    mbedtls_pk_init(keypair);
    mbedtls_pk_setup(keypair, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));

    int err = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(*keypair), mbedtls_ctr_drbg_random, &rng_ctx);

    if (err)
    {
        security_free_eckey(keypair);
        return NULL;
    }

    return keypair;
}

static int pkcs5_parse_pbkdf2_params(const mbedtls_asn1_buf * params, mbedtls_asn1_buf * salt, int * iterations, int * keylen,
                                     mbedtls_md_type_t * md_type)
{
    int ret;
    mbedtls_asn1_buf prf_alg_oid;
    unsigned char * p         = params->p;
    const unsigned char * end = params->p + params->len;

    if (params->tag != (MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE))
        return (MBEDTLS_ERR_PKCS5_INVALID_FORMAT + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG);
    /*
     *  PBKDF2-params ::= SEQUENCE {
     *    salt              OCTET STRING,
     *    iterationCount    INTEGER,
     *    keyLength         INTEGER OPTIONAL
     *    prf               AlgorithmIdentifier DEFAULT algid-hmacWithSHA1
     *  }
     *
     */
    if ((ret = mbedtls_asn1_get_tag(&p, end, &salt->len, MBEDTLS_ASN1_OCTET_STRING)) != 0)
        return (MBEDTLS_ERR_PKCS5_INVALID_FORMAT + ret);

    salt->p = p;
    p += salt->len;

    if ((ret = mbedtls_asn1_get_int(&p, end, iterations)) != 0)
        return (MBEDTLS_ERR_PKCS5_INVALID_FORMAT + ret);

    if (p == end)
        return (0);

    if ((ret = mbedtls_asn1_get_int(&p, end, keylen)) != 0)
    {
        if (ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG)
            return (MBEDTLS_ERR_PKCS5_INVALID_FORMAT + ret);
    }

    if (p == end)
        return (0);

    if ((ret = mbedtls_asn1_get_alg_null(&p, end, &prf_alg_oid)) != 0)
        return (MBEDTLS_ERR_PKCS5_INVALID_FORMAT + ret);

    if (MBEDTLS_OID_CMP(MBEDTLS_OID_HMAC_SHA1, &prf_alg_oid) == 0)
    {
        *md_type = MBEDTLS_MD_SHA1;
    }
    else if (MBEDTLS_OID_CMP(MBEDTLS_OID_HMAC_SHA256, &prf_alg_oid) == 0)
    {
        *md_type = MBEDTLS_MD_SHA256;
    }
    else
    {
        return (MBEDTLS_ERR_PKCS5_FEATURE_UNAVAILABLE);
    }

    if (p != end)
        return (MBEDTLS_ERR_PKCS5_INVALID_FORMAT + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);

    return (0);
}

static int test_pkcs5_pbes2(const mbedtls_asn1_buf * pbe_params, int mode, const unsigned char * pwd, size_t pwdlen,
                            const unsigned char * data, size_t datalen, unsigned char * output)
{
    int ret, iterations = 0, keylen = 0;
    unsigned char *p, *end;
    mbedtls_asn1_buf kdf_alg_oid, enc_scheme_oid, kdf_alg_params, enc_scheme_params;
    mbedtls_asn1_buf salt;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA1;
    unsigned char key[32], iv[32];
    size_t olen = 0;
    const mbedtls_md_info_t * md_info;
    const mbedtls_cipher_info_t * cipher_info;
    mbedtls_md_context_t md_ctx;
    mbedtls_cipher_type_t cipher_alg;
    mbedtls_cipher_context_t cipher_ctx;

    p   = pbe_params->p;
    end = p + pbe_params->len;

    /*
     *  PBES2-params ::= SEQUENCE {
     *    keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
     *    encryptionScheme AlgorithmIdentifier {{PBES2-Encs}}
     *  }
     */
    if (pbe_params->tag != (MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE))
        return (MBEDTLS_ERR_PKCS5_INVALID_FORMAT + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG);

    if ((ret = mbedtls_asn1_get_alg(&p, end, &kdf_alg_oid, &kdf_alg_params)) != 0)
        return (MBEDTLS_ERR_PKCS5_INVALID_FORMAT + ret);

    // Only PBKDF2 supported at the moment
    //
    if (MBEDTLS_OID_CMP(MBEDTLS_OID_PKCS5_PBKDF2, &kdf_alg_oid) != 0)
        return (MBEDTLS_ERR_PKCS5_FEATURE_UNAVAILABLE);

    if ((ret = pkcs5_parse_pbkdf2_params(&kdf_alg_params, &salt, &iterations, &keylen, &md_type)) != 0)
    {
        return (ret);
    }

    md_info = mbedtls_md_info_from_type(md_type);
    if (md_info == NULL)
        return (MBEDTLS_ERR_PKCS5_FEATURE_UNAVAILABLE);

    if ((ret = mbedtls_asn1_get_alg(&p, end, &enc_scheme_oid, &enc_scheme_params)) != 0)
    {
        return (MBEDTLS_ERR_PKCS5_INVALID_FORMAT + ret);
    }

    /*
    if( mbedtls_oid_get_cipher_alg( &enc_scheme_oid, &cipher_alg ) != 0 )
        return( MBEDTLS_ERR_PKCS5_FEATURE_UNAVAILABLE );
    */
    cipher_alg = MBEDTLS_CIPHER_AES_128_CBC;

    cipher_info = mbedtls_cipher_info_from_type(cipher_alg);
    if (cipher_info == NULL)
        return (MBEDTLS_ERR_PKCS5_FEATURE_UNAVAILABLE);

    /*
     * The value of keylen from pkcs5_parse_pbkdf2_params() is ignored
     * since it is optional and we don't know if it was set or not
     */
    keylen = cipher_info->key_bitlen / 8;

    if (enc_scheme_params.tag != MBEDTLS_ASN1_OCTET_STRING || enc_scheme_params.len != cipher_info->iv_size)
    {
        return (MBEDTLS_ERR_PKCS5_INVALID_FORMAT);
    }

    mbedtls_md_init(&md_ctx);
    mbedtls_cipher_init(&cipher_ctx);

    XMEMCPY(iv, enc_scheme_params.p, enc_scheme_params.len);

    if ((ret = mbedtls_md_setup(&md_ctx, md_info, 1)) != 0)
        goto exit;

    if ((ret = mbedtls_pkcs5_pbkdf2_hmac(&md_ctx, pwd, pwdlen, salt.p, salt.len, iterations, keylen, key)) != 0)
    {
        goto exit;
    }

    if ((ret = mbedtls_cipher_setup(&cipher_ctx, cipher_info)) != 0)
        goto exit;

    if ((ret = mbedtls_cipher_setkey(&cipher_ctx, key, 8 * keylen, (mbedtls_operation_t) mode)) != 0)
        goto exit;

    if ((ret = mbedtls_cipher_crypt(&cipher_ctx, iv, enc_scheme_params.len, data, datalen, output, &olen)) != 0)
    {
        ret = MBEDTLS_ERR_PKCS5_PASSWORD_MISMATCH;
    }

exit:
    mbedtls_md_free(&md_ctx);
    mbedtls_cipher_free(&cipher_ctx);

    return (ret);
}

static int parse_certificate_list(uint8_t * cert_buf, size_t len, X509_CERT * main_cert, X509_LIST * certs, CertifierError * error)
{

    /*
     * Parse the "certificate bag" structure from PKCS 12
     */

    int rc          = 0;
    uint8_t * p     = cert_buf;
    uint8_t * end   = p + len;
    size_t body_len = 0;
    bool first_cert = true;

    if (rc = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
    {
        error->application_error_code = MBEDTLS_PARSE_CERTIFICATE_LIST_1_E;
        goto cleanup;
    }

    while (p < end)
    {
        size_t seq_len     = 0;
        uint8_t * next_val = NULL;
        int cert_result    = 0;

        if (mbedtls_asn1_get_tag(&p, end, &seq_len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
        {
            break;
        }

        next_val = p + seq_len;

        if (rc = asn1_confirm_oid(&p, end, _MBEDTLS_OID_CERT_BAG_TYPE, MBEDTLS_OID_SIZE(_MBEDTLS_OID_CERT_BAG_TYPE)) != 0)
        {
            error->application_error_code = MBEDTLS_PARSE_CERTIFICATE_LIST_2_E;
            goto cleanup;
        }

        if (rc = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0) != 0)
        {
            error->application_error_code = MBEDTLS_PARSE_CERTIFICATE_LIST_3_E;
            goto cleanup;
        }

        if (rc = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
        {
            error->application_error_code = MBEDTLS_PARSE_CERTIFICATE_LIST_4_E;
            goto cleanup;
        }

        if (rc = asn1_confirm_oid(&p, end, _MBEDTLS_OID_PKCS9_X509_CERT, MBEDTLS_OID_SIZE(_MBEDTLS_OID_PKCS9_X509_CERT)) != 0)
        {
            error->application_error_code = MBEDTLS_PARSE_CERTIFICATE_LIST_5_E;
            goto cleanup;
        }

        if (rc = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0) != 0)
        {
            error->application_error_code = MBEDTLS_PARSE_CERTIFICATE_LIST_6_E;
            goto cleanup;
        }

        if (rc = mbedtls_asn1_get_tag(&p, end, &body_len, MBEDTLS_ASN1_OCTET_STRING) != 0)
        {
            error->application_error_code = MBEDTLS_PARSE_CERTIFICATE_LIST_7_E;
            goto cleanup;
        }

        if (first_cert)
        {
            if (main_cert == NULL)
            {
                cert_result = mbedtls_x509_crt_parse_der(certs, p, body_len);
            }
            else
            {
                cert_result = mbedtls_x509_crt_parse_der(main_cert, p, body_len);
            }
            first_cert = false;
        }
        else
        {
            if (certs != NULL)
            {
                cert_result = mbedtls_x509_crt_parse_der(certs, p, body_len);
            }
        }

        if (cert_result != 0)
        {
            goto cleanup;
        }

        p = next_val;
    }
    rc = 0;
cleanup:
    error->library_error_code = rc;
    fill_in_library_error_message_as_required(error);

    return rc;
}

static ECC_KEY * parse_shrouded_pkcs12_key(uint8_t * p, size_t body_len, const char * password)
{
    ECC_KEY * result = 0;

    uint8_t * key_buf = NULL;
    uint8_t * end     = p + body_len;
    size_t len        = 0;
    mbedtls_asn1_buf pbe_alg;
    mbedtls_asn1_buf pbe_params;
    int parse = 0;

    if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
        goto cleanup;
    if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
        goto cleanup;

    if (asn1_confirm_oid(&p, end, _MBEDTLS_OID_PKCS8_BAG_TYPE, MBEDTLS_OID_SIZE(_MBEDTLS_OID_PKCS8_BAG_TYPE)) != 0)
        goto cleanup;

    if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0) != 0)
        goto cleanup;

    if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
        goto cleanup;

    if (mbedtls_asn1_get_alg(&p, end, &pbe_alg, &pbe_params) != 0)
        goto cleanup;

    if (MBEDTLS_OID_CMP(MBEDTLS_OID_PKCS5_PBES2, &pbe_alg) != 0)
        goto cleanup;

    if (mbedtls_asn1_get_tag(&p, end, &body_len, MBEDTLS_ASN1_OCTET_STRING) != 0)
        goto cleanup;

    key_buf = XCALLOC(body_len, 1);

    if (test_pkcs5_pbes2(&pbe_params, MBEDTLS_PKCS5_DECRYPT, (uint8_t *) password, XSTRLEN(password), p, body_len, key_buf) != 0)
    {
        goto cleanup;
    }

    result = XCALLOC(1, sizeof(ECC_KEY));
    mbedtls_pk_init(result);
    parse = mbedtls_pk_parse_key(result, key_buf, body_len, NULL, 0);

    if (parse != 0)
    {
        mbedtls_pk_free(result);
        result = NULL;
        goto cleanup;
    }

cleanup:
    XFREE(key_buf);
    return result;
}

static ECC_KEY * mbedtls_parse_pkcs12(const char * pkcs12_fsname, const char * password, X509_CERT * main_cert, X509_LIST * certs,
                                      CertifierError * error)
{
    uint8_t * pkcs12_data = NULL;
    XFILE pkcs12_file     = NULL;
    long file_len         = 0;
    uint8_t * p           = NULL;
    size_t len            = file_len;
    uint8_t * end         = NULL;
    int pkcs12_version    = 0;
    int ret               = 0;

    int pkcs7_version = 0;
    size_t body_len   = 0;
    mbedtls_asn1_buf pbe_alg;
    mbedtls_asn1_buf pbe_params;
    ECC_KEY * eckey    = NULL;
    uint8_t * cert_buf = NULL;
    ssize_t got        = 0;

    pkcs12_file = XFOPEN(pkcs12_fsname, "rb");

    if (!pkcs12_file)
    {
        error->application_error_code = MBEDTLS_PARSE_PKCS12_1_E;
        return NULL;
    }

    XFSEEK(pkcs12_file, 0, XSEEK_END);
    file_len = XFTELL(pkcs12_file);

    if (file_len < 0)
    {
        error->application_error_code = MBEDTLS_PARSE_PKCS12_2_E;
        goto cleanup;
    }

    XFSEEK(pkcs12_file, 0, SEEK_SET);

    pkcs12_data = XCALLOC(1, file_len);

    if (!pkcs12_data)
    {
        error->application_error_code = MBEDTLS_PARSE_PKCS12_3_E;
        goto cleanup;
    }

    got = XFREAD(pkcs12_data, 1, file_len, pkcs12_file);

    if (got != file_len)
    {
        error->application_error_code = MBEDTLS_PARSE_PKCS12_4_E;
        goto cleanup;
    }

    p   = pkcs12_data;
    end = p + file_len;

    if (ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
    {
        error->application_error_code = MBEDTLS_PARSE_PKCS12_5_E;
        goto cleanup;
    }

    if (ret = mbedtls_asn1_get_int(&p, end, &pkcs12_version) != 0)
    {
        error->application_error_code = MBEDTLS_PARSE_PKCS12_6_E;
        goto cleanup;
    }

    if (pkcs12_version != 3)
    {
        error->application_error_code = MBEDTLS_PARSE_PKCS12_7_E;
        goto cleanup;
    }

    if (ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
    {
        error->application_error_code = MBEDTLS_PARSE_PKCS12_8_E;
        goto cleanup;
    }
    if (ret = asn1_confirm_oid(&p, end, _MBEDTLS_OID_PKCS7_DATA, MBEDTLS_OID_SIZE(_MBEDTLS_OID_PKCS7_DATA)) != 0)
    {
        error->application_error_code = MBEDTLS_PARSE_PKCS12_9_E;
        goto cleanup;
    }
    if (ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0) != 0)
    {
        error->application_error_code = MBEDTLS_PARSE_PKCS12_10_E;
        goto cleanup;
    }
    if (ret = mbedtls_asn1_get_tag(&p, end, &body_len, MBEDTLS_ASN1_OCTET_STRING) != 0)
    {
        error->application_error_code = MBEDTLS_PARSE_PKCS12_11_E;
        goto cleanup;
    }
    end = p + body_len;
    if (ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
    {
        error->application_error_code = MBEDTLS_PARSE_PKCS12_12_E;
        goto cleanup;
    }

    if (ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
    {
        error->application_error_code = MBEDTLS_PARSE_PKCS12_13_E;
        goto cleanup;
    }

    if (ret = asn1_confirm_oid(&p, end, _MBEDTLS_OID_PKCS7_ENC_DATA, MBEDTLS_OID_SIZE(_MBEDTLS_OID_PKCS7_ENC_DATA)) != 0)
    {
        error->application_error_code = MBEDTLS_PARSE_PKCS12_14_E;
        goto cleanup;
    }

    if (ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0) != 0)
    {
        error->application_error_code = MBEDTLS_PARSE_PKCS12_15_E;
        goto cleanup;
    }

    if (ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
    {
        error->application_error_code = MBEDTLS_PARSE_PKCS12_16_E;
        goto cleanup;
    }

    if (ret = mbedtls_asn1_get_int(&p, end, &pkcs7_version) != 0)
    {
        error->application_error_code = MBEDTLS_PARSE_PKCS12_17_E;
        goto cleanup;
    }

    if (pkcs7_version != 0)
    {
        error->application_error_code = MBEDTLS_PARSE_PKCS12_18_E;
        goto cleanup;
    }

    if (ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
    {
        error->application_error_code = MBEDTLS_PARSE_PKCS12_19_E;
        goto cleanup;
    }

    if (ret = asn1_confirm_oid(&p, end, _MBEDTLS_OID_PKCS7_DATA, MBEDTLS_OID_SIZE(_MBEDTLS_OID_PKCS7_DATA)) != 0)
    {
        error->application_error_code = MBEDTLS_PARSE_PKCS12_20_E;
        goto cleanup;
    }

    if (ret = mbedtls_asn1_get_alg(&p, end, &pbe_alg, &pbe_params) != 0)
    {
        error->application_error_code = MBEDTLS_PARSE_PKCS12_21_E;
        goto cleanup;
    }

    if (ret = MBEDTLS_OID_CMP(MBEDTLS_OID_PKCS5_PBES2, &pbe_alg) != 0)
    {
        error->application_error_code = MBEDTLS_PARSE_PKCS12_22_E;
        goto cleanup;
    }

    if (ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0) != 0)
    {
        error->application_error_code = MBEDTLS_PARSE_PKCS12_23_E;
        goto cleanup;
    }

    cert_buf = XCALLOC(len, 1);

    if (ret = test_pkcs5_pbes2(&pbe_params, MBEDTLS_PKCS5_DECRYPT, (uint8_t *) password, XSTRLEN(password), p, len, cert_buf) != 0)
    {
        error->application_error_code = MBEDTLS_PARSE_PKCS12_24_E;
        goto cleanup;
    }

    if (ret = parse_certificate_list(cert_buf, len, main_cert, certs, error) != 0)
    {
        goto cleanup;
    }

    p += len;

    if (ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
    {
        error->application_error_code = MBEDTLS_PARSE_PKCS12_25_E;
        goto cleanup;
    }

    if (ret = asn1_confirm_oid(&p, end, _MBEDTLS_OID_PKCS7_DATA, MBEDTLS_OID_SIZE(_MBEDTLS_OID_PKCS7_DATA)) != 0)
    {
        error->application_error_code = MBEDTLS_PARSE_PKCS12_26_E;
        goto cleanup;
    }

    if (ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0) != 0)
    {
        error->application_error_code = MBEDTLS_PARSE_PKCS12_27_E;
        goto cleanup;
    }

    if (ret = mbedtls_asn1_get_tag(&p, end, &body_len, MBEDTLS_ASN1_OCTET_STRING) != 0)
    {
        error->application_error_code = MBEDTLS_PARSE_PKCS12_28_E;
        goto cleanup;
    }

    eckey = parse_shrouded_pkcs12_key(p, body_len, password);
    if (eckey == NULL)
    {
        error->application_error_code = MBEDTLS_PARSE_PKCS12_29_E;
        goto cleanup;
    }

cleanup:
    if (pkcs12_file)
        XFCLOSE(pkcs12_file);

    if (cert_buf)
        XFREE(cert_buf);

    if (pkcs12_data)
        XFREE(pkcs12_data);

    error->library_error_code = ret;

    fill_in_library_error_message_as_required(error);

    return eckey;
}

/**
 * Creates an elliptical curve key pair.
 * @param keystore Filename of pkcs12 key store. If it exists, reads keys from it, else creates them
 * @param password Used to access keystore.
 */
CertifierError security_find_or_create_keys(CertifierPropMap * properties, const char * keystore, const char * password,
                                            X509_LIST * certs, const char * curve_id, ECC_KEY ** out)
{
    ECC_KEY * eckey = NULL;
    XFILE p12_file  = NULL;

    CertifierError result = CERTIFIER_ERROR_INITIALIZER;
    error_clear(&result);

    if (out == NULL)
    {
        result.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        result.application_error_msg  = util_format_error_here("out cannot be NULL");
        return result;
    }

    // Check if keys already exist in PKCS12 keystore file
    if (util_file_exists(keystore))
    {
        // Read and store the keys in memory
        p12_file = XFOPEN(keystore, "rb");
        if (p12_file)
        {
            log_info("Found existing Key Store File.");
            eckey = mbedtls_parse_pkcs12(keystore, password, NULL, certs, &result);
            XFCLOSE(p12_file);
            goto cleanup;
        }
    }
    else
    {
        eckey = security_create_new_ec_key(properties, curve_id);
    }

cleanup:
    *out = eckey;

    return result;
} /* security_find_or_create_keys */

char * security_get_field_from_cert(X509_CERT * cert, const char * field_name)
{
    mbedtls_asn1_named_data * name = &cert->subject;

    if (field_name == NULL)
    {
        return NULL;
    }

    while (name)
    {
        if ((MBEDTLS_OID_CMP(MBEDTLS_OID_AT_ORG_UNIT, &name->oid) == 0) && (strcmp("organizationalUnitName", field_name) == 0))
        {
            char * ret = XCALLOC(name->val.len + 1, 1);
            if (ret == NULL)
            {
                log_error("Could not allocate enough memory for ret (#1)");
                return NULL;
            }
            XMEMCPY(ret, name->val.p, name->val.len);
            return ret;
        }
        else if ((MBEDTLS_OID_CMP(MBEDTLS_OID_AT_CN, &name->oid) == 0) && (strcmp("commonName", field_name) == 0))
        {
            char * ret = XCALLOC(name->val.len + 1, 1);
            if (ret == NULL)
            {
                log_error("Could not allocate enough memory for ret (#2)");
                return NULL;
            }
            XMEMCPY(ret, name->val.p, name->val.len);
            return ret;
        }
        name = name->next;
    }

    return NULL; // not found?
}

CertifierError security_get_X509_PKCS12_file(const char * filename, const char * password, X509_LIST * certs, X509_CERT ** out)
{

    CertifierError result = CERTIFIER_ERROR_INITIALIZER;
    error_clear(&result);

    result.application_error_code = 0;

    X509_CERT * cert = XCALLOC(1, sizeof(X509_CERT));
    if (cert == NULL)
    {
        result.application_error_code = 100;
        return result;
    }
    ECC_KEY * eckey = mbedtls_parse_pkcs12(filename, password, cert, certs, &result);
    if (eckey == NULL)
    {
        result.application_error_code = 200;
        security_free_cert(cert);
        return result;
    }
    security_free_eckey(eckey);
    *out = cert;

    return result;

} /* security_get_X509_PKCS12_file */

void security_free_eckey(ECC_KEY * eckey)
{
    mbedtls_pk_free(eckey);
    XFREE(eckey);
}

int security_get_random_bytes(unsigned char * out, int len)
{
    return mbedtls_ctr_drbg_random(&rng_ctx, out, len);
}

static int x509_time_cmp(const mbedtls_x509_time * t1, const mbedtls_x509_time * t2)
{
    if (t1->year != t2->year)
        return (t1->year < t2->year) ? -1 : 1;

    if (t1->mon != t2->mon)
        return (t1->mon < t2->mon) ? -1 : 1;

    if (t1->day != t2->day)
        return (t1->day < t2->day) ? -1 : 1;

    if (t1->hour != t2->hour)
        return (t1->hour < t2->hour) ? -1 : 1;

    if (t1->min != t2->min)
        return (t1->min < t2->min) ? -1 : 1;

    if (t1->sec != t2->sec)
        return (t1->sec < t2->sec) ? -1 : 1;

    return 0; // equal
}

static int x509_time_cmp_timet(const mbedtls_x509_time * t1, time_t ref_time)
{
    struct tm ref_cal;
    gmtime_r(&ref_time, &ref_cal);

    mbedtls_x509_time t2;
    t2.year = ref_cal.tm_year + 1900;
    t2.mon  = ref_cal.tm_mon + 1;
    t2.day  = ref_cal.tm_mday;
    t2.hour = ref_cal.tm_hour;
    t2.min  = ref_cal.tm_min;
    t2.sec  = ref_cal.tm_sec;
    return x509_time_cmp(t1, &t2);
}

int security_check_x509_expires_before(X509_CERT * cert, time_t time)
{
    if (x509_time_cmp_timet(&cert->valid_to, time) != 1)
    {
        return 1;
    }
    return 0; // is not expired at specified time
}

void security_free_cert(X509_CERT * cert)
{
    if (cert)
    {
        mbedtls_x509_crt_free(cert);
        XFREE(cert);
    }
}

X509_CERT * security_dup_cert(const X509_CERT * cert)
{
    if (cert == NULL)
    {
        log_error("cert was NULL!");
        return NULL;
    }

    return security_X509_from_DER(cert->raw.p, cert->raw.len);
}

ECC_KEY * security_dup_eckey(const ECC_KEY * eckey)
{
    ECC_KEY * key = NULL;

    if (eckey != NULL)
    {
        // More than sufficient; even P-521 is only ~241 bytes
        uint8_t buf[8192] = { 0 };
        int rc            = mbedtls_pk_write_key_der((ECC_KEY *) eckey, buf, sizeof(buf));

        if (rc <= 0 || rc >= sizeof(buf))
        {
            log_error("error 1 in security_dup_eckey.  buf %X\n", rc);
            return NULL;
        }

        key = XCALLOC(1, sizeof(ECC_KEY));
        if (key == NULL)
        {
            return key;
        }
        mbedtls_pk_init(key);

        rc = mbedtls_pk_parse_key(key, buf + sizeof(buf) - rc, rc, NULL, 0);
        if (rc != 0)
        {
            log_error("error 2 in security_dup_eckey.  bad parse\n");
            mbedtls_pk_free(key);
            XFREE(key);
            return NULL;
        }
    }

    return key;
}

char * security_get_version(void)
{
    char * version       = XMALLOC(18);
    char * formatted_str = NULL;
    if (version == NULL)
    {
        log_error("Could not allocate enough memory for version string.");
        return "unknown-1";
    }

    mbedtls_version_get_string_full(version);

    formatted_str = util_format_str("mbedTLS (Library: %s)", version);
    XFREE(version);
    return formatted_str;
}

CertifierError security_post_init(const char * cfg_file)
{
    CertifierError rc = CERTIFIER_ERROR_INITIALIZER;
    error_clear(&rc);
    return rc;
}

X509_CERT * security_cert_list_get(X509_LIST * certs, int which)
{
    if (certs == NULL)
    {
        return NULL;
    }

    for (int i = 0; i != which; ++i)
    {
        if (certs != NULL)
            certs = certs->next;
    }

    if (certs && certs->version == 0)
        return NULL;
    return certs;
}

void security_free_cert_list(X509_LIST * certs)
{
    if (certs)
    {
        mbedtls_x509_crt_free(certs);
        XFREE(certs);
    }
}

X509_LIST * security_new_cert_list(void)
{
    return XCALLOC(1, sizeof(X509_LIST));
}

void security_print_certs_in_list(X509_LIST * certs, XFILE output)
{
    char buf[4096];
    while (certs)
    {
        mbedtls_x509_crt_info(buf, sizeof(buf), "", certs);
        XFPRINTF(output, "%s", buf);
        certs = certs->next;
    }
}

/*
 * Begin Code - Ber to Der - used for PKCS7 parsing
 */
#define INDEF_ITEMS_MAX 20

/* Indef length item data */
typedef struct Indef
{
    size_t start;
    int depth;
    int headerLen;
    size_t len;
} Indef;

/* Indef length items */
typedef struct IndefiniteItems
{
    Indef len[INDEF_ITEMS_MAX];
    int cnt;
    int idx;
    int depth;
} IndefiniteItems;

/* ASN Tags   */
enum ASN_Tags
{
    ASN_EOC              = 0x00,
    ASN_BOOLEAN          = 0x01,
    ASN_INTEGER          = 0x02,
    ASN_BIT_STRING       = 0x03,
    ASN_OCTET_STRING     = 0x04,
    ASN_TAG_NULL         = 0x05,
    ASN_OBJECT_ID        = 0x06,
    ASN_ENUMERATED       = 0x0a,
    ASN_UTF8STRING       = 0x0c,
    ASN_SEQUENCE         = 0x10,
    ASN_SET              = 0x11,
    ASN_PRINTABLE_STRING = 0x13,
    ASN_UTC_TIME         = 0x17,
    ASN_OTHER_TYPE       = 0x00,
    ASN_RFC822_TYPE      = 0x01,
    ASN_DNS_TYPE         = 0x02,
    ASN_DIR_TYPE         = 0x04,
    ASN_URI_TYPE         = 0x06, /* the value 6 is from GeneralName OID */
    ASN_GENERALIZED_TIME = 0x18,
    CRL_EXTENSIONS       = 0xa0,
    ASN_EXTENSIONS       = 0xa3,
    ASN_LONG_LENGTH      = 0x80,
    ASN_INDEF_LENGTH     = 0x80,

    /* ASN_Flags - Bitmask */
    ASN_CONSTRUCTED      = 0x20,
    ASN_APPLICATION      = 0x40,
    ASN_CONTEXT_SPECIFIC = 0x80,
};

enum
{
    BIT_SIZE = 8,
};

enum
{
    DYNAMIC_TYPE_TMP_BUFFER = 38,
};

/* give option to check length value found against index. 1 to check 0 to not */
static int get_length_ex(const unsigned char * input, size_t * inOutIdx, int * len, size_t maxIdx, int check)
{
    int length = 0;
    size_t idx = *inOutIdx;
    unsigned char b;

    *len = 0; /* default length */

    if ((idx + 1) > maxIdx)
    { /* for first read */
        log_error("GetLength bad index on input");
        return MBEDTLS_BER_TO_DER_BUFFER_E;
    }

    b = input[idx++];
    if (b >= ASN_LONG_LENGTH)
    {
        size_t bytes = b & 0x7F;

        if ((idx + bytes) > maxIdx)
        { /* for reading bytes */
            log_error("GetLength bad long length");
            return MBEDTLS_BER_TO_DER_BUFFER_E;
        }

        if (bytes > sizeof(length))
        {
            return MBEDTLS_BER_TO_DER_ASN_PARSE_E;
        }
        while (bytes--)
        {
            b      = input[idx++];
            length = (length << 8) | b;
        }
        if (length < 0)
        {
            return MBEDTLS_BER_TO_DER_ASN_PARSE_E;
        }
    }
    else
        length = b;

    if (check && (idx + length) > maxIdx)
    { /* for user of length */
        log_error("GetLength value exceeds buffer length");
        return MBEDTLS_BER_TO_DER_BUFFER_E;
    }

    *inOutIdx = idx;
    if (length > 0)
        *len = length;

    return length;
}

static int get_length(const unsigned char * input, size_t * inOutIdx, int * len, size_t maxIdx)
{
    return get_length_ex(input, inOutIdx, len, maxIdx, 1);
}

/* Pull information from the ASN.1 BER encoded item header */
static int get_ber_header(const unsigned char * data, size_t * idx, size_t maxIdx, unsigned char * pTag, size_t * pLen, int * indef)
{
    int len = 0;
    unsigned char tag;
    size_t i = *idx;

    *indef = 0;

    /* Check there is enough data for a minimal header */
    if (i + 2 > maxIdx)
    {
        return MBEDTLS_BER_TO_DER_ASN_PARSE_E;
    }

    /* Retrieve tag */
    tag = data[i++];

    /* Indefinite length handled specially */
    if (data[i] == 0x80)
    {
        /* Check valid tag for indefinite */
        if (((tag & 0xc0) == 0) && ((tag & ASN_CONSTRUCTED) == 0x00))
        {
            return MBEDTLS_BER_TO_DER_ASN_PARSE_E;
        }
        i++;
        *indef = 1;
    }
    else if (get_length(data, &i, &len, maxIdx) < 0)
    {
        return MBEDTLS_BER_TO_DER_ASN_PARSE_E;
    }

    /* Return tag, length and index after BER item header */
    *pTag = tag;
    *pLen = len;
    *idx  = i;
    return 0;
}

/* Add a indefinite length item */
static int add_item(IndefiniteItems * items, size_t start)
{
    int ret = 0;
    int i;

    if (items->cnt == INDEF_ITEMS_MAX)
    {
        ret = MBEDTLS_BER_TO_DER_MEMORY_E;
    }
    else
    {
        i                       = items->cnt++;
        items->len[i].start     = start;
        items->len[i].depth     = items->depth++;
        items->len[i].headerLen = 1;
        items->len[i].len       = 0;
        items->idx              = i;
    }

    return ret;
}

/* Increase data length of current item */
static void add_data(IndefiniteItems * items, size_t length)
{
    items->len[items->idx].len += length;
}

static size_t byte_precision(size_t value)
{
    size_t i;
    for (i = sizeof(value); i; --i)
        if (value >> ((i - 1) * BIT_SIZE))
            break;

    return i;
}

size_t set_length(size_t length, unsigned char * output)
{
    size_t i = 0, j;

    if (length < ASN_LONG_LENGTH)
    {
        if (output)
            output[i] = (unsigned char) length;
        i++;
    }
    else
    {
        if (output)
            output[i] = (unsigned char) (byte_precision(length) | ASN_LONG_LENGTH);
        i++;

        for (j = byte_precision(length); j; --j)
        {
            if (output)
                output[i] = (unsigned char) (length >> ((j - 1) * BIT_SIZE));
            i++;
        }
    }

    return i;
}

/* Update header length of current item to reflect data length */
static void update_header_len(IndefiniteItems * items)
{
    items->len[items->idx].headerLen += set_length(items->len[items->idx].len, NULL);
}

/* Calcuate final length by adding length of indefinite child items */
static void calc_length(IndefiniteItems * items)
{
    int i;
    int idx = items->idx;

    for (i = idx + 1; i < items->cnt; i++)
    {
        if (items->len[i].depth == items->depth)
        {
            items->len[idx].len += items->len[i].headerLen;
            items->len[idx].len += items->len[i].len;
        }
    }
    items->len[idx].headerLen += set_length(items->len[idx].len, NULL);
}

/* Go to indefinite parent of current item */
static void items_up(IndefiniteItems * items)
{
    int i;
    int depth = items->len[items->idx].depth - 1;

    for (i = items->cnt - 1; i >= 0; i--)
    {
        if (items->len[i].depth == depth)
        {
            break;
        }
    }
    items->idx   = i;
    items->depth = depth + 1;
}

/* Add more data to indefinite length item */
static void more_data(IndefiniteItems * items, size_t length)
{
    if (items->cnt > 0 && items->idx >= 0)
    {
        items->len[items->idx].len += length;
    }
}

/* Get header length of current item */
static int header_len(IndefiniteItems * items)
{
    return items->len[items->idx].headerLen;
}

/* Get data length of current item */
static size_t items_len(IndefiniteItems * items)
{
    return items->len[items->idx].len;
}

/* Convert a BER encoding with indefinite length items to DER.
 *
 * ber    BER encoded data.
 * ber_size  Length of BER encoded data.
 * der    Buffer to hold DER encoded version of data.
 *        NULL indicates only the length is required.
 * der_size  The size of the buffer to hold the DER encoded data.
 *        Will be set if der is NULL, otherwise the value is checked as der is
 *        filled.
 * returns MBEDTLS_BER_TO_DER_ASN_PARSE_E if the BER data is invalid and MBEDTLS_BER_TO_DER_BAD_FUNC_ARG_E if ber or
 * der_size are NULL.
 */
static int ber2der(const unsigned char * ber, size_t ber_size, unsigned char * der, size_t * der_size)
{
    int ret = 0;
    size_t i, j;
    IndefiniteItems * indefinite_items = NULL;
    unsigned char tag, basic;
    size_t length;
    int indef;

    if (ber == NULL || der_size == NULL)
        return MBEDTLS_BER_TO_DER_BAD_FUNC_ARG_E;

    indefinite_items = XCALLOC(1, sizeof(IndefiniteItems));
    if (indefinite_items == NULL)
    {
        ret = MBEDTLS_BER_TO_DER_MEMORY_E;
        goto end;
    }

    XMEMSET(indefinite_items, 0, sizeof(*indefinite_items));

    /* Calculate indefinite item lengths */
    for (i = 0; i < ber_size;)
    {
        size_t start = i;

        /* Get next BER item */
        ret = get_ber_header(ber, &i, ber_size, &tag, &length, &indef);
        if (ret != 0)
        {
            goto end;
        }

        if (indef)
        {
            /* Indefinite item - add to list */
            ret = add_item(indefinite_items, i);
            if (ret != 0)
            {
                goto end;
            }

            if ((tag & 0xC0) == 0 && tag != (ASN_SEQUENCE | ASN_CONSTRUCTED) && tag != (ASN_SET | ASN_CONSTRUCTED))
            {
                /* Constructed basic type - get repeating tag */
                basic = tag & (~ASN_CONSTRUCTED);

                /* Add up lengths of each item below */
                for (; i < ber_size;)
                {
                    /* Get next BER_item */
                    ret = get_ber_header(ber, &i, ber_size, &tag, &length, &indef);
                    if (ret != 0)
                    {
                        goto end;
                    }

                    /* End of content closes item */
                    if (tag == ASN_EOC)
                    {
                        /* Must be zero length */
                        if (length != 0)
                        {
                            ret = MBEDTLS_BER_TO_DER_ASN_PARSE_E;
                            goto end;
                        }
                        break;
                    }

                    /* Must not be indefinite and tag must match parent */
                    if (indef || tag != basic)
                    {
                        ret = MBEDTLS_BER_TO_DER_ASN_PARSE_E;
                        goto end;
                    }

                    /* Add to length */
                    add_data(indefinite_items, length);
                    /* Skip data */
                    i += length;
                }

                /* Ensure we got an EOC and not end of data */
                if (tag != ASN_EOC)
                {
                    ret = MBEDTLS_BER_TO_DER_ASN_PARSE_E;
                    goto end;
                }

                /* Set the header length to include the length field */
                update_header_len(indefinite_items);
                /* Go to indefinte parent item */
                items_up(indefinite_items);
            }
        }
        else if (tag == ASN_EOC)
        {
            /* End-of-content must be 0 length */
            if (length != 0)
            {
                ret = MBEDTLS_BER_TO_DER_ASN_PARSE_E;
                goto end;
            }
            /* Check there is an item to close - missing EOC */
            if (indefinite_items->depth == 0)
            {
                ret = MBEDTLS_BER_TO_DER_ASN_PARSE_E;
                goto end;
            }

            /* Finish calculation of data length for indefinite item */
            calc_length(indefinite_items);
            /* Go to indefinte parent item */
            items_up(indefinite_items);
        }
        else
        {
            /* Known length item to add in - make sure enough data for it */
            if (i + length > ber_size)
            {
                ret = MBEDTLS_BER_TO_DER_ASN_PARSE_E;
                goto end;
            }

            /* Include all data - can't have indefinite inside definite */
            i += length;
            /* Add entire item to current indefinite item */
            more_data(indefinite_items, i - start);
        }
    }
    /* Check we had a EOC for each indefinite item */
    if (indefinite_items->depth != 0)
    {
        ret = MBEDTLS_BER_TO_DER_ASN_PARSE_E;
        goto end;
    }

    /* Write out DER */

    j = 0;
    /* Reset index */
    indefinite_items->idx = 0;
    for (i = 0; i < ber_size;)
    {
        size_t start = i;

        /* Get item - checked above */
        (void) get_ber_header(ber, &i, ber_size, &tag, &length, &indef);
        if (indef)
        {
            if (der != NULL)
            {
                /* Check enough space for header */
                if (j + header_len(indefinite_items) > *der_size)
                {
                    ret = MBEDTLS_BER_TO_DER_BUFFER_E;
                    goto end;
                }

                if ((tag & 0xC0) == 0 && tag != (ASN_SEQUENCE | ASN_CONSTRUCTED) && tag != (ASN_SET | ASN_CONSTRUCTED))
                {
                    /* Remove constructed tag for basic types */
                    tag &= ~ASN_CONSTRUCTED;
                }
                /* Add tag and length */
                der[j] = tag;
                (void) set_length(items_len(indefinite_items), der + j + 1);
            }
            /* Add header length of indefinite item */
            j += header_len(indefinite_items);

            if ((tag & 0xC0) == 0 && tag != (ASN_SEQUENCE | ASN_CONSTRUCTED) && tag != (ASN_SET | ASN_CONSTRUCTED))
            {
                /* For basic type - get each child item and add data */
                for (; i < ber_size;)
                {
                    (void) get_ber_header(ber, &i, ber_size, &tag, &length, &indef);
                    if (tag == ASN_EOC)
                    {
                        break;
                    }
                    if (der != NULL)
                    {
                        if (j + length > *der_size)
                        {
                            ret = MBEDTLS_BER_TO_DER_BUFFER_E;
                            goto end;
                        }
                        XMEMCPY(der + j, ber + i, length);
                    }
                    j += length;
                    i += length;
                }
            }

            /* Move to next indef item in list */
            indefinite_items->idx++;
        }
        else if (tag == ASN_EOC)
        {
            /* End-Of-Content is not written out in DER */
        }
        else
        {
            /* Write out definite length item as is. */
            i += length;
            if (der != NULL)
            {
                /* Ensure space for item */
                if (j + i - start > *der_size)
                {
                    ret = MBEDTLS_BER_TO_DER_BUFFER_E;
                    goto end;
                }
                /* Copy item as is */
                XMEMCPY(der + j, ber + start, i - start);
            }
            j += i - start;
        }
    }

    /* Return the length of the DER encoded ASN.1 */
    *der_size = j;
    if (der == NULL)
    {
        ret = MBEDTLS_BER_TO_DER_LENGTH_ONLY_E;
    }
end:
    if (indefinite_items != NULL)
    {
        XFREE(indefinite_items);
    }

    return ret;
}

/*
 * End Code - Ber to Der - used for PKCS7 parsing
 */

static CertifierError load_certs_from_pkcs7(const char * pkcs7, X509_LIST ** out)
{
    CertifierError result = CERTIFIER_ERROR_INITIALIZER;
    error_clear(&result);

    if (out == NULL)
    {
        result.application_error_code = MBEDTLS_LOAD_CERTS_FROM_PKCS7_1_E;
        goto cleanup;
    }

    X509_LIST * certs = NULL;

    mbedtls_pem_context pem_ctx;
    size_t pem_len;
    int ret;
    uint8_t * p   = NULL;
    uint8_t * der = NULL;

    size_t len     = 0;
    size_t der_len = 0;

    uint8_t * end     = p + len;
    int pkcs7_version = 0;

    mbedtls_pem_init(&pem_ctx);

    ret = mbedtls_pem_read_buffer(&pem_ctx, "-----BEGIN PKCS7-----", "-----END PKCS7-----", (const uint8_t *) pkcs7, NULL, 0,
                                  &pem_len);

    if (ret != 0)
    {
        result.application_error_code = MBEDTLS_LOAD_CERTS_FROM_PKCS7_2_E;
        goto cleanup;
    }

    p   = pem_ctx.buf;
    len = pem_ctx.buflen;
    end = p + len;

    der_len = len * 2;

    der = XCALLOC(der_len, 1);
    if (der == NULL)
    {
        result.application_error_code = MBEDTLS_LOAD_CERTS_FROM_PKCS7_3_E;
        goto cleanup;
    }

    ber2der(p, len, der, &der_len);

    p   = der;
    len = der_len;
    end = p + len;

    log_debug("der is: %s", der);
    log_debug("len= %hhu", der_len, end);

    log_debug("PKCS #7 from security_load_certs_from_pkcs7 is: %s ok?", pkcs7);

    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0)
    {
        result.application_error_code = MBEDTLS_LOAD_CERTS_FROM_PKCS7_4_E;
        goto cleanup;
    }

    if (ret = asn1_confirm_oid(&p, end, _MBEDTLS_OID_PKCS7_SIGNED_DATA, MBEDTLS_OID_SIZE(_MBEDTLS_OID_PKCS7_SIGNED_DATA)) != 0)
    {
        result.application_error_code = MBEDTLS_LOAD_CERTS_FROM_PKCS7_5_E;
        goto cleanup;
    }

    if (ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0) != 0)
    {
        result.application_error_code = MBEDTLS_LOAD_CERTS_FROM_PKCS7_6_E;
        goto cleanup;
    }

    if (ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
    {
        result.application_error_code = MBEDTLS_LOAD_CERTS_FROM_PKCS7_7_E;
        goto cleanup;
    }

    if (ret = mbedtls_asn1_get_int(&p, end, &pkcs7_version) != 0)
    {
        result.application_error_code = MBEDTLS_LOAD_CERTS_FROM_PKCS7_8_E;
        goto cleanup;
    }

    if (pkcs7_version != 1)
    {
        result.application_error_code = MBEDTLS_LOAD_CERTS_FROM_PKCS7_9_E;
        goto cleanup;
    }

    if (ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET) != 0)
    {
        result.application_error_code = MBEDTLS_LOAD_CERTS_FROM_PKCS7_10_E;
        goto cleanup;
    }

    if (ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
    {
        result.application_error_code = MBEDTLS_LOAD_CERTS_FROM_PKCS7_11_E;
        goto cleanup;
    }

    if (ret = asn1_confirm_oid(&p, end, _MBEDTLS_OID_PKCS7_DATA, MBEDTLS_OID_SIZE(_MBEDTLS_OID_PKCS7_DATA)) != 0)
    {
        result.application_error_code = MBEDTLS_LOAD_CERTS_FROM_PKCS7_12_E;
        goto cleanup;
    }

    if (ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0) != 0)
    {
        // this could be an EJBCA certificate, run through offset.
        p = p + 32;
    }

    // util_hex_dump(stderr, p, end);

    certs = XCALLOC(1, sizeof(mbedtls_x509_crt));
    if (certs == NULL)
    {
        result.application_error_code = MBEDTLS_LOAD_CERTS_FROM_PKCS7_13_E;
        goto cleanup;
    }

    int cert_number = 0;

    for (;;)
    {
        uint8_t * cert_hdr  = p;
        size_t cert_hdr_len = 0;

        if (cert_number == 3)
        {
            goto cleanup;
        }

        if (ret = mbedtls_asn1_get_tag(&cert_hdr, end, &cert_hdr_len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
        {
            result.application_error_code = MBEDTLS_LOAD_CERTS_FROM_PKCS7_14_E;
            goto cleanup;
        }

        cert_hdr_len += (cert_hdr - p); // add also the length of the tags decoded above
        // XFPRINTF(stderr, "HDR LENGTH IS: %i\n", cert_hdr_len);
        // util_hex_dump(stderr, cert_hdr, end);

        ret = mbedtls_x509_crt_parse_der(certs, p, cert_hdr_len);

        if (ret != 0)
        {
            result.application_error_code = MBEDTLS_LOAD_CERTS_FROM_PKCS7_15_E;
            mbedtls_x509_crt_free(certs);
            certs = NULL;
            goto cleanup;
        }
        else
        {
            log_info("*** SUCCESSFUL ADD!!! - %i\n", ++cert_number);
        }

        mbedtls_x509_crt * certp = certs;
        while (certp->next != NULL)
        {
            certp = certp->next;
        }

        p += cert_hdr_len;

        if (end - p < 16)
        {
            break;
        }
    }

cleanup:
    mbedtls_pem_free(&pem_ctx);

    if (der)
    {
        XFREE(der);
    }

    *out = certs;

    if (ret != 0)
    {
        result.library_error_code = ret;
        fill_in_library_error_message_as_required(&result);
    }

    return result;
}

CertifierError load_certs_from_certificate(const char * pem, X509_LIST ** out, bool load_all_certs)
{
    CertifierError result = CERTIFIER_ERROR_INITIALIZER;
    error_clear(&result);

    if (out == NULL)
    {
        result.application_error_code = MBEDTLS_LOAD_CERTS_FROM_CERTIFICATE_1_E;
        return result;
    }

    // Note: mbedtls implementation currently only supports single certificate loading
    // The load_all_certs parameter is accepted for API compatibility but not yet implemented
    (void)load_all_certs;

    X509_LIST * certs = NULL;

    mbedtls_pem_context pem_ctx;
    size_t pem_len;
    int ret;
    uint8_t * p = NULL;
    size_t len  = 0;

    mbedtls_pem_init(&pem_ctx);

    ret = mbedtls_pem_read_buffer(&pem_ctx, "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----", (const uint8_t *) pem, NULL,
                                  0, &pem_len);

    if (ret != 0)
    {
        result.application_error_code = MBEDTLS_LOAD_CERTS_FROM_CERTIFICATE_2_E;
        goto cleanup;
    }

    p   = pem_ctx.buf;
    len = pem_ctx.buflen;

    log_debug("pem_ctx.buf is: %s", p);
    log_debug("len= %hhu", len);

    log_debug("PEM from security_load_certs_from_pem is: %s ok?", pem);

    certs = XCALLOC(1, sizeof(mbedtls_x509_crt));
    if (certs == NULL)
    {
        result.application_error_code = MBEDTLS_LOAD_CERTS_FROM_CERTIFICATE_3_E;
        goto cleanup;
    }

    ret = mbedtls_x509_crt_parse_der(certs, p, len);
    if (ret != 0)
    {
        result.application_error_code = MBEDTLS_LOAD_CERTS_FROM_CERTIFICATE_4_E;
        goto cleanup;
    }

cleanup:
    mbedtls_pem_free(&pem_ctx);

    *out = certs;

    if (ret != 0)
    {
        result.library_error_code = ret;
        fill_in_library_error_message_as_required(&result);
    }

    return result;
}

CertifierError security_load_certs_from_pem(const char * pem, X509_LIST ** out, bool load_all_certs)
{
    CertifierError result = CERTIFIER_ERROR_INITIALIZER;
    if (XSTRSTR(pem, "-----BEGIN PKCS7-----"))
    {
        result = load_certs_from_pkcs7(pem, out);
    }
    else if (XSTRSTR(pem, "-----BEGIN CERTIFICATE-----"))
    {
        result = load_certs_from_certificate(pem, out, load_all_certs);
    }
    else
    {
        log_error("Unknown PEM file!");
    }

    return result;
}

int security_serialize_der_public_key(ECC_KEY * ec_key, unsigned char ** der_public_key)
{
    uint8_t buf[4096];
    int len = mbedtls_pk_write_pubkey_der(ec_key, buf, sizeof(buf));

    if (len <= 0)
    {
        return 0; // error
    }

    unsigned char * my_der_public_key = XMALLOC(4096);
    if (my_der_public_key == NULL)
    {
        log_error("Could not allocate enough memory for the der_public_key");
        return 0;
    }

    XMEMCPY(my_der_public_key, buf + sizeof(buf) - len, len);
    *der_public_key = my_der_public_key;

    return len;
}

static int read_sim_time(mbedtls_x509_time * sim_time, const char * time_str)
{
    const size_t tm_len     = XSTRLEN(time_str);
    uint8_t asn1buf[15 + 5] = { 0 };
    uint8_t * p             = &asn1buf[0];

    if (tm_len != 13 && tm_len != 15)
        return MBEDTLS_READ_SIM_TIME_1_ERR;

    asn1buf[0] = (tm_len == 15) ? MBEDTLS_ASN1_GENERALIZED_TIME : MBEDTLS_ASN1_UTC_TIME;
    asn1buf[1] = tm_len;
    XMEMCPY(asn1buf + 2, time_str, tm_len);

    if (mbedtls_x509_get_time(&p, asn1buf + tm_len + 2, sim_time) != 0)
        return MBEDTLS_READ_SIM_TIME_2_ERR;

    return 0;
}

static time_t mbedtls_time_to_unix(mbedtls_x509_time * xtime)
{
    struct tm t;

    if (!xtime || !xtime->year || xtime->year < 0)
        return (time_t) (long long) -1;

    XMEMSET(&t, 0, sizeof(t));

    t.tm_year  = xtime->year - 1900;
    t.tm_mon   = xtime->mon - 1; /* mbedtls months are 1+, tm are 0+ */
    t.tm_mday  = xtime->day - 1; /* mbedtls days are 1+, tm are 0+ */
    t.tm_hour  = xtime->hour;
    t.tm_min   = xtime->min;
    t.tm_sec   = xtime->sec;
    t.tm_isdst = -1;

    return mktime(&t);
}

CertifierError security_check_x509_valid_range(time_t current_time, long min_secs_left, X509_CERT * cert,
                                               const char * sim_cert_before_time, const char * sim_cert_after_time)
{

    int ret               = 0;
    CertifierError result = CERTIFIER_ERROR_INITIALIZER;
    error_clear(&result);

    time_t unix_after_time;

    if (sim_cert_before_time)
    {
        mbedtls_x509_time sim_time;

        const size_t sim_time_len = XSTRLEN(sim_cert_before_time);

        if (sim_time_len <= 0 || sim_time_len > 17)
        {
            result.application_error_code = MBEDTLS_CHECK_X509_VALID_RANGE_1_E;
            goto cleanup;
        }

        if (ret = read_sim_time(&sim_time, sim_cert_before_time) != 0)
        {
            XFREE(util_format_error(__func__, "read_sim_time failure [1].", __FILE__, __LINE__));
            log_error("read_sim_time failure [1].");
            result.application_error_code = MBEDTLS_CHECK_X509_VALID_RANGE_2_E;
            goto cleanup;
        }

        if (ret = x509_time_cmp_timet(&sim_time, current_time) != -1)
        {
            util_format_error(__func__, "x509_time_cmp_timet failure [1].", __FILE__, __LINE__);
            log_error("x509_time_cmp_timet failure [1].");
            result.application_error_code = MBEDTLS_CHECK_X509_VALID_RANGE_3_E;
            goto cleanup;
        }
    }
    else
    {
        if (ret = x509_time_cmp_timet(&cert->valid_from, current_time) != -1)
        {
            XFREE(util_format_error(__func__, "x509_time_cmp_timet failure [1].", __FILE__, __LINE__));
            log_error("x509_time_cmp_timet failure [1].");
            result.application_error_code = MBEDTLS_CHECK_X509_VALID_RANGE_4_E;
            goto cleanup;
        }
    }

    if (sim_cert_after_time)
    {
        mbedtls_x509_time sim_time;

        const size_t sim_time_len = XSTRLEN(sim_cert_after_time);

        if (sim_time_len <= 0 || sim_time_len > 17)
        {
            result.application_error_code = MBEDTLS_CHECK_X509_VALID_RANGE_9_E;
            goto cleanup;
        }

        if (ret = read_sim_time(&sim_time, sim_cert_after_time) != 0)
        {
            XFREE(util_format_error(__func__, "read_sim_time failure [2].", __FILE__, __LINE__));
            log_error("read_sim_time failure [2].");
            result.application_error_code = MBEDTLS_CHECK_X509_VALID_RANGE_5_E;
            goto cleanup;
        }

        if (ret = x509_time_cmp_timet(&sim_time, current_time) != 1)
        {
            util_format_error(__func__, "x509_time_cmp_timet failure [3].", __FILE__, __LINE__);
            log_error("x509_time_cmp_timet failure [3].");
            result.application_error_code = MBEDTLS_CHECK_X509_VALID_RANGE_6_E;
            goto cleanup;
        }

        unix_after_time = mbedtls_time_to_unix(&sim_time);
    }
    else
    {

        if (ret = x509_time_cmp_timet(&cert->valid_to, current_time) != 1)
        {
            XFREE(util_format_error(__func__, "x509_time_cmp_timet failure [4].", __FILE__, __LINE__));
            log_error("x509_time_cmp_timet failure [4].");
            result.application_error_code = MBEDTLS_CHECK_X509_VALID_RANGE_7_E;
            goto cleanup;
        }

        struct tm texp = { .tm_sec   = cert->valid_to.sec,
                           .tm_min   = cert->valid_to.min,
                           .tm_hour  = cert->valid_to.hour,
                           .tm_mday  = cert->valid_to.day,
                           .tm_mon   = cert->valid_to.mon - 1,
                           .tm_year  = cert->valid_to.year - 1900,
                           .tm_isdst = -1 };

        unix_after_time = mktime(&texp);
    }

    if (min_secs_left != 0)
    {
        int diff_day = (unix_after_time - time(NULL)) / (24 * 3600);
        int diff_sec = 0;

        if ((diff_day * SECS_IN_DAY + diff_sec) < min_secs_left)
        {
            result.application_error_code = MBEDTLS_CHECK_X509_VALID_RANGE_8_E;
            result.application_error_msg  = util_format_error_here("Certificate is about to expire!");
            goto cleanup;
        }
    }

cleanup:

    if (ret != 0)
    {
        result.library_error_code = ret;
        fill_in_library_error_message_as_required(&result);
    }

    return result;
}

CertifierError security_check_cert_is_valid(X509_CERT * cert, const char * security_cert_root_ca, const char * security_cert_int_ca,
                                            time_t * overridden_time_t)
{
    CertifierError ret = CERTIFIER_ERROR_INITIALIZER;
    error_clear(&ret);

    const char * ca_cert_pem  = security_cert_root_ca;
    const char * int_cert_pem = security_cert_int_ca;
    mbedtls_x509_crt trusted_ca;
    mbedtls_x509_crt int_ca;
    mbedtls_x509_crt cert_chain;
    uint32_t flags;
    int rc = 0;

    mbedtls_x509_crt_init(&trusted_ca);
    mbedtls_x509_crt_init(&int_ca);

    rc = mbedtls_x509_crt_parse(&trusted_ca, (const unsigned char *) ca_cert_pem, XSTRLEN(ca_cert_pem) + 1);
    if (rc != 0)
    {
        log_error("Received error code: %i from mbedtls_x509_crt_parse[1].", rc);
        rc = MBEDTLS_ERR_1;
        util_format_error(__func__, "Received error code: %i from mbedtls_x509_crt_parse[1].", __FILE__, __LINE__);
        goto cleanup;
    }

    rc = mbedtls_x509_crt_parse(&int_ca, (const unsigned char *) int_cert_pem, XSTRLEN(int_cert_pem) + 1);
    if (rc != 0)
    {
        log_error("Received error code: %i from mbedtls_x509_crt_parse[2].", rc);
        rc = MBEDTLS_ERR_2;
        util_format_error(__func__, "Received error code: %i from mbedtls_x509_crt_parse[2].", __FILE__, __LINE__);
        goto cleanup;
    }

    cert_chain      = *cert;
    cert_chain.next = &int_ca;

    rc = mbedtls_x509_crt_verify(&cert_chain, &trusted_ca,
                                 NULL, // CRL
                                 NULL, // CN
                                 &flags,
                                 NULL, // verify func
                                 NULL  // param to verify func
    );

    if (rc != 0)
    {
        log_error("Received error code: %i from mbedtls_x509_crt_verify.", rc);
        rc = MBEDTLS_ERR_3;
        util_format_error(__func__, "Received error code: %i from mbedtls_x509_crt_verify.", __FILE__, __LINE__);

        goto cleanup;
    }

cleanup:
    mbedtls_x509_crt_free(&int_ca);
    mbedtls_x509_crt_free(&trusted_ca);

    ret.application_error_code = rc;
    return ret;
}

ECC_KEY * security_get_key_from_der(unsigned char * der_public_key, int der_public_key_len)
{

    int ret                  = 0;
    mbedtls_pk_context * ctx = XCALLOC(1, sizeof(mbedtls_pk_context));
    if (ctx == NULL)
    {
        log_error("Could not allocate enough memory for creating a mbedtls_pk_context");
        goto cleanup;
    }

    mbedtls_pk_init(ctx);
    if ((ret = mbedtls_pk_parse_public_key(ctx, der_public_key, der_public_key_len)) != 0)
    {
        log_error("Received error code: %i from mbedtls_pk_parse_public_key.", ret);
        util_format_error(__func__, "Received error code: %i from mbedtls_pk_parse_public_key.", __FILE__, __LINE__);

        goto cleanup;
    }

cleanup:
    return ctx;
}

ECC_KEY * security_get_key_from_cert(X509_CERT * cert)
{
    unsigned char buf[4096]  = { 0 };
    mbedtls_pk_context * ctx = XCALLOC(1, sizeof(mbedtls_pk_context));
    if (ctx == NULL)
    {
        log_error("Could not allocate enough memory for creating a mbedtls_pk_context");
        return NULL;
    }
    int len = mbedtls_pk_write_pubkey_der(&cert->pk, buf, sizeof(buf));

    mbedtls_pk_init(ctx);

    mbedtls_pk_parse_public_key(ctx, buf + sizeof(buf) - len, len);

    return ctx;
}

X509_CERT * security_X509_from_DER(const unsigned char * der, size_t der_len)
{
    int rc           = 0;
    X509_CERT * cert = XCALLOC(1, sizeof(mbedtls_x509_crt));
    if (cert == NULL)
    {
        log_error("Could not allocate enough memory for the cert.");
        return NULL;
    }
    rc = mbedtls_x509_crt_parse_der(cert, der, der_len);
    if (rc != 0)
    {
        log_error("mbedtls_x509_crt_parse_der returned: [%i]", rc);
        XFREE(cert);
        return NULL;
    }
    return cert;
}

unsigned char * security_X509_to_DER(X509_CERT * cert, size_t * out_len)
{
    unsigned char * result = XMALLOC(cert->raw.len + 1);
    if (result == NULL)
    {
        log_error("Could not allocate enough memory for result.");
        return NULL;
    }
    XMEMCPY(result, cert->raw.p, cert->raw.len);
    result[cert->raw.len] = '\0'; /* add a null termination char */
    *out_len              = cert->raw.len;
    return result;
}

void security_print_subject_issuer(const X509_CERT * cert)
{
    char subject[1024];
    char issuer[1024];

    mbedtls_x509_dn_gets(subject, sizeof(subject), &cert->subject);
    mbedtls_x509_dn_gets(issuer, sizeof(issuer), &cert->issuer);

    printf("subject=%s\n\n", subject);
    printf("issuer=%s\n\n", issuer);
}

CertifierError security_verify_signature(ECC_KEY * key, const char * signature_b64, const unsigned char * input, int input_len)
{
    CertifierError ret = CERTIFIER_ERROR_INITIALIZER;
    error_clear(&ret);

    int rc                 = 0;
    unsigned char * buffer = NULL;
    unsigned char digest[32];
    mbedtls_ecdsa_context ctx;

    int dec_len = base64_decode_len(signature_b64);

    buffer = (unsigned char *) XMALLOC(dec_len);
    if (buffer == NULL)
    {
        rc = MBEDTLS_ERR_1;
        util_format_error(__func__, "Buffer was null.", __FILE__, __LINE__);
        goto cleanup;
    }

    dec_len = base64_decode(buffer, signature_b64);

    if (security_sha256(digest, input, input_len) != 0)
    {
        rc = MBEDTLS_ERR_3;
        util_format_error(__func__, "security_sha256 failure.", __FILE__, __LINE__);
        goto cleanup;
    }

    mbedtls_ecdsa_init(&ctx);
    mbedtls_ecdsa_from_keypair(&ctx, mbedtls_pk_ec(*key));

    rc = mbedtls_ecdsa_read_signature(&ctx, digest, sizeof(digest), buffer, dec_len);

    if (rc != 0)
    {
        rc = MBEDTLS_ERR_4;
        XFREE(util_format_error(__func__, "mbedtls_ecdsa_read_signature failure.", __FILE__, __LINE__));
    }
    mbedtls_ecdsa_free(&ctx);

cleanup:

    XFREE(buffer);

    ret.application_error_code = rc;
    return ret;
}

#endif
