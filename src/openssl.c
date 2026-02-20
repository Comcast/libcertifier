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

#ifndef USE_MBEDTLS

#include "certifier/base58.h"
#include "certifier/base64.h"
#include "certifier/certifier_internal.h"
#include "certifier/error.h"
#include "certifier/log.h"
#include "certifier/property.h"
#include "certifier/security.h"
#include "certifier/system.h"
#include "certifier/timer.h"
#include "certifier/types.h"
#include "certifier/util.h"

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/ripemd.h>

#include <openssl/buffer.h>
#include <openssl/hmac.h>
#include <openssl/opensslv.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define OPENSSL_ERR_1 1000
#define OPENSSL_ERR_2 2000
#define OPENSSL_ERR_3 3000
#define OPENSSL_ERR_4 4000
#define OPENSSL_ERR_5 5000
#define OPENSSL_ERR_6 6000
#define OPENSSL_ERR_7 7000
#define OPENSSL_ERR_8 8000
#define OPENSSL_ERR_9 9000

#define SSL_ERR_BUF_LEN 320

#define DEFAULT_P12_ENC_ALGORITHM "AES-128-CBC"
#define SECS_IN_DAY 86400

#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER < 0x10100000L
#define SECURITY_NEED_CRYPTO_INIT
#endif
// Declaring custom function not included in x509.h, but makes use of x509 features
int add_ext(STACK_OF(X509_EXTENSION) * sk, int nid, char * value);

ECC_KEY * security_get_key_from_cert(X509_CERT * cert)
{
    EVP_PKEY * public_key;
    ECC_KEY * ecc_key;

    if (cert == NULL)
    {
        return NULL;
    }

    public_key = X509_get_pubkey(cert);
    ecc_key    = EVP_PKEY_get1_EC_KEY(public_key);
    EVP_PKEY_free(public_key);

    return ecc_key;
}

// Functions

CertifierError security_init(void)
{

    CertifierError result = CERTIFIER_ERROR_INITIALIZER;

    ERR_clear_error();

#ifdef SECURITY_NEED_CRYPTO_INIT
    // Initialize openssl
    char * error_message = NULL;
    ERR_load_crypto_strings();
    result.application_error_code = ERR_get_error();
    if (result.application_error_code)
    {
        goto exit;
    }

    OpenSSL_add_all_algorithms();
    result.application_error_code = ERR_get_error();
    if (result.application_error_code)
    {
        goto exit;
    }

    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

exit:

    if (result.application_error_code != 0)
    {
        error_message = ERR_error_string(result.application_error_code, NULL);
        if (error_message != NULL)
        {
            result.application_error_msg = util_format_error(__func__, error_message, __FILE__, __LINE__);
            ERR_print_errors_fp(stderr);
        }
    }
#endif

    return result;

} /* security_init */

void security_destroy(void)
{
#ifdef SECURITY_NEED_CRYPTO_INIT
    EVP_cleanup();
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();
#endif
} /* security_destroy */

CertifierError security_post_init(const char * cfg_file)
{
    CertifierError rc = CERTIFIER_ERROR_INITIALIZER;
    return rc;
}

unsigned char * security_generate_csr(ECC_KEY * eckey, size_t * retlen)
{

    unsigned char * result          = NULL;
    X509_REQ * x                    = NULL;
    EVP_PKEY * pk                   = NULL;
    int der_len                     = 0;
    STACK_OF(X509_EXTENSION) * exts = NULL;
    CertifierPropMap * properties   = NULL;
    char * usage_values             = NULL;

    if ((pk = EVP_PKEY_new()) == NULL)
    {
        log_error("EVP_PKEY_new failed.");
        goto cleanup;
    }

    // Create the request
    if ((x = X509_REQ_new()) == NULL)
    {
        log_error("X509_REQ_new failed.");
        goto cleanup;
    }

    if (!EVP_PKEY_set1_EC_KEY(pk, eckey))
    {
        log_error("EVP_PKEY_set1_EC_KEY failed.");
        goto cleanup;
    }

    X509_REQ_set_pubkey(x, pk);

    // Set extended key usage values from cfg
    exts         = sk_X509_EXTENSION_new_null();
    properties   = property_ext();
    usage_values = property_get(properties, CERTIFIER_OPT_EXT_KEY_USAGE);
    log_debug("Ext Key Usage is: %s", usage_values);
    add_ext(exts, NID_ext_key_usage, usage_values);
    X509_REQ_add_extensions(x, exts);
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

    // Cleanup temp propmap
    XFREE(properties);
    XFREE(usage_values);

    // Set the signature algorithm
    if (!X509_REQ_sign(x, pk, EVP_sha256()))
    {
        log_error("X509_REQ_sign failed.");
        goto cleanup;
    }

    der_len = i2d_X509_REQ(x, &result);

    if (der_len <= 0)
    {
        XFREE(result);
        result = NULL;
        log_error("der_len < 0.");
        goto cleanup;
    }

    *retlen = der_len;

cleanup:
    X509_REQ_free(x);
    EVP_PKEY_free(pk);

    return result;
}

int add_ext(STACK_OF(X509_EXTENSION) * sk, int nid, char * value)
{
    X509_EXTENSION * ex;
    ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
    if (!ex)
        log_error("Failed to load X509 Extensions!");
    sk_X509_EXTENSION_push(sk, ex);
    return 0;
}

int security_persist_pkcs_12_file(const char * filename, const char * pwd, ECC_KEY * prikey, X509_CERT * cert, X509_LIST * certs,
                                  CertifierError * result)
{
    int ppbe                         = 0;
    unsigned long openssl_error_code = 0;
    PKCS12 * pkcs12bundle            = NULL;
    XFILE pkcs12file                 = NULL;
    EVP_PKEY * pkey                  = NULL;
    int bytes                        = 0;
    char * tmpfilename               = util_format_str("%s.tmp", filename);
    char * error_message             = NULL;

    // Get the private key and convert from ECC to EVP_PKEY format
    pkey = EVP_PKEY_new();
    if (EVP_PKEY_set1_EC_KEY(pkey, prikey) == 0)
    {
        result->application_error_code = OPENSSL_ERR_1;
        result->application_error_msg  = util_format_error(__func__, "EVP_PKEY_set1_EC_KEY failed.", __FILE__, __LINE__);

        error_message = ERR_error_string(ERR_get_error(), NULL);
        if (error_message != NULL)
        {
            log_error("%s", error_message);
            ERR_print_errors_fp(stderr);
        }
        goto cleanup;
    }

    // commented this code out, not sure if it is even necessary
    /*
    if (!X509_check_private_key(cert, pkey)) {
        result->application_error_code = OPENSSL_ERR_2;
        result->application_error_msg = util_format_error(__func__, "X509_check_private_key failed.",
                                             __FILE__, __LINE__);
        error_message = ERR_error_string(ERR_get_error(), NULL);
        if (error_message != NULL) {
            log_error(error_message);
            ERR_print_errors_fp(stderr);
        }
        goto cleanup;
    }
    */

    ppbe = OBJ_txt2nid(DEFAULT_P12_ENC_ALGORITHM);
    if (ppbe == NID_undef)
    {
        log_error("\n<<< Unknown PBE algorithm. >>>\n");
        result->application_error_code = OPENSSL_ERR_3;
        result->application_error_msg  = util_format_error(__func__, "Unknown PBE algorithm.", __FILE__, __LINE__);
        error_message                  = ERR_error_string(ERR_get_error(), NULL);
        if (error_message != NULL)
        {
            log_error("%s", error_message);
            ERR_print_errors_fp(stderr);
        }
        goto cleanup;
    }

    // Values of zero use the openssl default values
    pkcs12bundle = PKCS12_create((char *) pwd, // certbundle access password
                                 "key",        // friendly certname
                                 pkey,         // the certificate private key
                                 cert,         // the main certificate
                                 certs,        // stack of CA cert chain
                                 ppbe,         // int nid_key (default 3DES)
                                 ppbe,         // int nid_cert (40bitRC2)
                                 50000,        // int iter (default 2048)
                                 50000,        // int mac_iter (default 1)
                                 0);           // int keytype (default no flag)
    if (pkcs12bundle == NULL)
    {
        log_error("\n<<< Error generating a valid PKCS12 certificate. >>>\n");
        result->application_error_code = OPENSSL_ERR_4;
        result->application_error_msg =
            util_format_error(__func__, "Error generating a valid PKCS12 certificate.", __FILE__, __LINE__);

        error_message = ERR_error_string(ERR_get_error(), NULL);
        if (error_message != NULL)
        {
            log_error("%s", error_message);
            ERR_print_errors_fp(stderr);
        }

        goto cleanup;
    }

    if (tmpfilename == NULL)
    {
        result->application_error_code = OPENSSL_ERR_8;
        result->application_error_msg  = util_format_error(__func__, "tmpfilename==NULL", __FILE__, __LINE__);
        goto cleanup;
    }

    // Write the PKCS12 structure out to a tmpfile and atomically commission it later with a rename
    if (!(pkcs12file = XFOPEN(tmpfilename, "w")))
    {
        log_error("\n<<< Error can't open pkcs12 certificate file for writing. >>>\n");
        result->application_error_code = OPENSSL_ERR_5;
        result->application_error_msg =
            util_format_error(__func__, "Error can't open pkcs12 certificate file for writing.", __FILE__, __LINE__);

        error_message = ERR_error_string(ERR_get_error(), NULL);
        if (error_message != NULL)
        {
            log_error("%s", error_message);
            ERR_print_errors_fp(stderr);
        }

        goto cleanup;
    }

    bytes = i2d_PKCS12_fp(pkcs12file, pkcs12bundle);
    if (bytes <= 0)
    {
        log_error("\n<<< Error writing PKCS12 certificate. >>>\n");
        result->application_error_code = OPENSSL_ERR_5;
        result->application_error_msg  = util_format_error(__func__, "Error writing PKCS12 certificate.", __FILE__, __LINE__);

        error_message = ERR_error_string(ERR_get_error(), NULL);
        if (error_message != NULL)
        {
            log_error("%s", error_message);
            ERR_print_errors_fp(stderr);
        }

        goto cleanup;
    }

    if (util_rename_file(tmpfilename, filename) != 0)
    {
        result->application_error_msg  = util_format_error_here("Unable to commission keystore '%s' as '%s'");
        result->application_error_code = OPENSSL_ERR_6;
    }

// Clean up
cleanup:

    openssl_error_code = ERR_get_error();

    if (result->application_error_code == 0)
    {
        if (openssl_error_code <= INT_MAX)
        {
            result->application_error_code = (int) openssl_error_code;
        }
        else
        {
            log_error("SSL error [%ld]", openssl_error_code);
        }
    }

    if (openssl_error_code != 0)
    {

        error_message = ERR_error_string(openssl_error_code, NULL);
        if (error_message != NULL)
        {
            result->application_error_msg = util_format_error_here(error_message);
            ERR_print_errors_fp(stderr);
        }
    }

    if (pkcs12file)
    {
        XFCLOSE(pkcs12file);
    }

    XFREE(tmpfilename);
    PKCS12_free(pkcs12bundle);
    EVP_PKEY_free(pkey);

    if (result->application_error_code != 0)
    {
        char errBuf[SSL_ERR_BUF_LEN];
        error_message = ERR_error_string(ERR_get_error(), errBuf);
        if (error_message != NULL)
        {
            result->application_error_msg = util_format_error_here(error_message);
        }
        ERR_print_errors_fp(stderr);
    }

    return result->application_error_code;
} /* persistPkcs12File */

struct sha1_ctx_st
{
    SHA_CTX h;
};

sha1_ctx * security_sha1_init()
{
    sha1_ctx * ctx = XMALLOC(sizeof(struct sha1_ctx_st)); /* */
    if (SHA1_Init(&ctx->h) != 1)
    {
        XFREE(ctx);
        return NULL;
    }
    return ctx;
}

int security_sha1_update(sha1_ctx * ctx, const unsigned char input[], size_t len)
{
    return SHA1_Update(&ctx->h, input, len) == 1 ? 0 : -1;
}

int security_sha1_finish(sha1_ctx * ctx, unsigned char * digest)
{
    int rc = 0;
    rc     = SHA1_Final(digest, &ctx->h) == 1 ? 0 : -1;
    XFREE(ctx);
    return rc;
}

struct sha256_ctx_st
{
    SHA256_CTX h;
};

sha256_ctx * security_sha256_init()
{
    sha256_ctx * ctx = XMALLOC(sizeof(struct sha256_ctx_st)); /* */
    if (SHA256_Init(&ctx->h) != 1)
    {
        XFREE(ctx);
        return NULL;
    }
    return ctx;
}

int security_sha256_update(sha256_ctx * ctx, const unsigned char input[], size_t len)
{
    return SHA256_Update(&ctx->h, input, len) == 1 ? 0 : -1;
}

int security_sha256_finish(sha256_ctx * ctx, unsigned char * digest)
{
    int rc = 0;
    rc     = SHA256_Final(digest, &ctx->h) == 1 ? 0 : -1;
    XFREE(ctx);
    return rc;
}

CertifierError security_rmd160(uint8_t * digest, const uint8_t * message, size_t len)
{
    RIPEMD160_CTX ctx;
    CertifierError result = CERTIFIER_ERROR_INITIALIZER;

    if (RIPEMD160_Init(&ctx) != 1)
    {
        result.application_error_msg  = util_format_error(__func__, "RIPEMD160_Init failed.", __FILE__, __LINE__);
        result.application_error_code = OPENSSL_ERR_1;
    }
    if (RIPEMD160_Update(&ctx, message, len) != 1)
    {
        result.application_error_msg  = util_format_error(__func__, "RIPEMD160_Update failed.", __FILE__, __LINE__);
        result.application_error_code = OPENSSL_ERR_2;
    }
    if (RIPEMD160_Final(digest, &ctx) != 1)
    {
        result.application_error_msg  = util_format_error(__func__, "RIPEMD160_Final failed.", __FILE__, __LINE__);
        result.application_error_code = OPENSSL_ERR_3;
    }

    return result;
}

CertifierError security_verify_signature(ECC_KEY * key, const char * signature_b64, const unsigned char * input, int input_len)
{
    CertifierError rc   = CERTIFIER_ERROR_INITIALIZER;
    unsigned char * sig = NULL;
    int sig_len         = 0;
    unsigned char digest[32];

    if (key == NULL || signature_b64 == NULL || input == NULL)
    {
        rc.application_error_code = OPENSSL_ERR_1;
        rc.application_error_msg  = util_format_error_here("Invalid arguments.");
        goto cleanup;
    }

    sig_len = base64_decode_len(signature_b64);

    sig = (unsigned char *) XMALLOC(sig_len);
    if (sig == NULL)
    {
        rc.application_error_code = OPENSSL_ERR_1;
        rc.application_error_msg  = util_format_error(__func__, "Sig was null.", __FILE__, __LINE__);
        goto cleanup;
    }

    sig_len = base64_decode(sig, signature_b64);

    if (sig_len <= 0)
    {
        rc.application_error_code = OPENSSL_ERR_5;
        rc.application_error_msg  = util_format_error(__func__, "base64_decode failure.", __FILE__, __LINE__);
        goto cleanup;
    }

    if (security_sha256(digest, input, input_len) != 0)
    {
        rc.application_error_code = OPENSSL_ERR_3;
        rc.application_error_msg  = util_format_error(__func__, "security_sha256 failure.", __FILE__, __LINE__);
        goto cleanup;
    }

    rc.application_error_code = security_verify_hash(key, sig, sig_len, digest, sizeof(digest));

cleanup:

    XFREE(sig);
    return rc;
}

int security_verify_hash(ECC_KEY * key, const unsigned char * sig, size_t sig_len, const unsigned char * digest, size_t digest_len)
{
    EVP_PKEY_CTX * ctx    = NULL;
    EVP_PKEY * pkey       = NULL;
    ECC_KEY * ec_pub_only = NULL;
    int rc                = 4000; /* expected error for invalid sig */
    int r;

    pkey = EVP_PKEY_new();
    if (pkey == NULL)
        goto done;

    if (ec_pub_only == NULL)
    {
        if (!EVP_PKEY_set1_EC_KEY(pkey, key))
            goto done;
    }

    ctx = EVP_PKEY_CTX_new(pkey, NULL);

    if (!ctx)
        goto done;

    if (EVP_PKEY_verify_init(ctx) <= 0)
        goto done;

    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
        goto done;

    r = EVP_PKEY_verify(ctx, sig, sig_len, digest, digest_len);

    if (r <= 0)
        goto done;

    // valid
    rc = 0;

done:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    EC_KEY_free(ec_pub_only);
    return rc;
}

unsigned char * security_sign_hash(const ECC_KEY * ecc_key, const unsigned char * digest, const size_t digest_len, size_t * sig_len)
{

    EVP_PKEY_CTX * ctx  = NULL;
    EVP_PKEY * pkey     = NULL;
    unsigned char * der = NULL;
    size_t der_len      = 0;

    der_len = ECDSA_size(ecc_key);

    pkey = EVP_PKEY_new();
    if (pkey == NULL)
        goto done;

    if (!EVP_PKEY_set1_EC_KEY(pkey, (ECC_KEY *) ecc_key))
        goto done;

    ctx = EVP_PKEY_CTX_new(pkey, NULL);

    if (!ctx)
        goto done;

    if (EVP_PKEY_sign_init(ctx) <= 0)
        goto done;

    der = (unsigned char *) XMALLOC(der_len * sizeof(unsigned char));

    if (!der)
        goto done;

    if (EVP_PKEY_sign(ctx, der, &der_len, digest, digest_len) <= 0)
    {
        XFREE(der);
        der = NULL;
        goto done;
    }

    *sig_len = der_len;
done:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return der;
}

ECC_KEY * security_create_new_ec_key(CertifierPropMap * properties, const char * curve_id)
{
    ECC_KEY * eckey = NULL;

    log_debug("\nGenerating Elliptic Curve Key Pair...\n");

    // Create a EC key structure, setting the group type from NID
    eckey = EC_KEY_new_by_curve_name(OBJ_txt2nid(curve_id));

    if (eckey == NULL)
    {
        log_error("\nCould not instantiate an EC Key with name: %s\n", curve_id);
        return eckey;
    }

    // For cert signing, we use  the OPENSSL_EC_NAMED_CURVE flag
    EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

    // Create the public/private EC key pair here
    if (!(EC_KEY_generate_key(eckey)))
    {
        log_error("\nError generating the Elliptic Curve key.\n");
        EC_KEY_free(eckey);
    }

    return eckey;
}

char * ossl_err_as_string(void)
{
    BIO * bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char * buf = NULL;
    char * ret = NULL;
    size_t len = BIO_get_mem_data(bio, &buf);
    if (BIO_eof(bio))
    {
        goto cleanup;
    }

    ret = (char *) calloc(1, 1 + len); // TODO:  need to use macro for this, don't use libc version
    if (ret)
        XMEMCPY(ret, buf, len);

cleanup:
    BIO_free(bio);
    return ret;
}

/**
 * Creates an elliptical curve key pair.
 * @param keystore Filename of pkcs12 key store. If it exists, reads keys from it, else creates them
 * @param password Used to access keystore.
 * @param curve id
 */
CertifierError security_find_or_create_keys(CertifierPropMap * properties, const char * keystore, const char * password,
                                            X509_LIST * certs, const char * curve_id, ECC_KEY ** out)
{
    ECC_KEY * eckey     = NULL;
    XFILE p12_file      = NULL;
    char * error_string = NULL;
    PKCS12 * p12_cert   = NULL;
    EVP_PKEY * pri      = NULL;

    CertifierError result = CERTIFIER_ERROR_INITIALIZER;
    ERR_clear_error();

    if (out == NULL)
    {
        result.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        result.application_error_msg  = util_format_error_here("out cannot be NULL");
        return result;
    }

    double start_user_cpu_time, end_user_cpu_time;
    double start_system_cpu_time, end_system_cpu_time;

    long int start_memory_used, end_memory_used;
    const bool measure_performance = property_get(properties, CERTIFIER_OPT_MEASURE_PERFORMANCE);

    if (measure_performance)
    {
        start_user_cpu_time   = system_user_cpu_time();
        start_system_cpu_time = system_system_cpu_time();

        start_memory_used = system_get_memory_used();

        timer_reset();
        timer_start_time();
        timer_start_CPU_time();
    }

    // Check if keys already exist in PKCS12 keystore file
    if (util_file_exists(keystore))
    {
        // Read and store the keys in memory
        p12_file = XFOPEN(keystore, "rb");
        if (p12_file)
        {
            log_info("\nFound existing Key Store File.\n");
            int err = 0;
            d2i_PKCS12_fp(p12_file, &p12_cert);

            err = PKCS12_parse(p12_cert, password, &pri, NULL, certs == NULL ? NULL : &certs);

            error_string = ossl_err_as_string();

            if (error_string && XSTRLEN(error_string) > 0)
            {
                result.application_error_code = 1;
                result.library_error_code     = ERR_get_error();
                result.library_error_msg      = util_format_error(__func__, error_string, __FILE__, __LINE__);
                eckey                         = NULL;
                goto cleanup;
            }

            if (err == 1)
            {
                eckey = EVP_PKEY_get1_EC_KEY(pri);
            }
            else
            {
                log_error("\nFailure in PKCS12_parse.  Returning NULL\n");
                result.application_error_code = 2;
            }
            goto cleanup;
        }
    }
    else
    {
        eckey = security_create_new_ec_key(properties, curve_id);
    }

cleanup:

    if (error_string)
    {
        XFREE(error_string);
    }

    if (p12_cert)
    {
        PKCS12_free(p12_cert);
    }

    if (pri)
    {
        EVP_PKEY_free(pri);
    }

    if (p12_file)
    {
        XFCLOSE(p12_file);
    }

    if (measure_performance)
    {
        timer_end_time();
        timer_end_CPU_time();
        timer_calculate_cpu_utilization();
        end_memory_used     = system_get_memory_used();
        end_user_cpu_time   = system_user_cpu_time();
        end_system_cpu_time = system_system_cpu_time();

        log_debug("security_find_or_create_keys[performance] - Answer %10.1f, Elapsed Time %7.4f, CPU Time %7.4f, CPU Ut %3.0f",
                  timer_get_answer(), timer_get_secs_value(), timer_get_cpu_secs(), timer_get_cpu_utilization());

        if ((start_memory_used > 0) && (end_memory_used > 0))
        {
            log_debug("security_find_or_create_keys[performance] start_memory_used: %ld", start_memory_used);
            log_debug("security_find_or_create_keys[performance] end_memory_used: %ld", end_memory_used);
        }

        if ((start_user_cpu_time > 0) && (end_user_cpu_time > 0))
        {
            log_debug("security_find_or_create_keys[performance] start_user_cpu_time: %7.4f", start_user_cpu_time);
            log_debug("security_find_or_create_keys[performance] end_user_cpu_time: %7.4f", end_user_cpu_time);
        }

        if ((start_system_cpu_time > 0) && (end_system_cpu_time > 0))
        {
            log_debug("security_find_or_create_keys[performance] start_system_cpu_time: %7.4f", start_system_cpu_time);
            log_debug("security_find_or_create_keys[performance] end_system_cpu_time: %7.4f", end_system_cpu_time);
        }
    }

    ERR_clear_error();

    *out = eckey;
    return result;
} /* security_find_or_create_keys */

char * security_get_field_from_cert(X509_CERT * cert, const char * field_name)
{
    int i;

    if (field_name == NULL)
    {
        return NULL;
    }

    X509_NAME * subj = X509_get_subject_name(cert);
    if (subj)
    {
        for (i = 0; i < X509_NAME_entry_count(subj); i++)
        {
            X509_NAME_ENTRY * e = X509_NAME_get_entry(subj, i);
            ASN1_OBJECT * o     = X509_NAME_ENTRY_get_object(e);

            char object_name[1024];
            OBJ_obj2txt(object_name, 1024, o, 0);

            ASN1_STRING * d = X509_NAME_ENTRY_get_data(e);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
            const unsigned char * str = ASN1_STRING_get0_data(d);
#else
            unsigned char * str = ASN1_STRING_data(d);
#endif

            if (XSTRCMP(object_name, field_name) == 0)
            {
                if (str == NULL)
                {
                    log_error("str was null.");
                    return NULL;
                }
                else
                {
                    return XSTRDUP((char *) str);
                }
            }
        }
    }

    /* ---------------------------------------------------------- *
     * Now, try the certificate's extensions                      *
     * ---------------------------------------------------------- */

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    const STACK_OF(X509_EXTENSION) * ext_list = X509_get0_extensions(cert);
#else
    X509_CINF * cert_inf                      = cert->cert_info;
    const STACK_OF(X509_EXTENSION) * ext_list = cert_inf->extensions;
#endif

    if ((sk_X509_EXTENSION_num(ext_list) > 0))
    {
        for (i = 0; i < sk_X509_EXTENSION_num(ext_list); i++)
        {
            BIO * outbio = BIO_new(BIO_s_mem());
            ASN1_OBJECT * obj;
            X509_EXTENSION * ext;
            BUF_MEM * bptr = NULL;
            char * buf     = NULL;

            ext = sk_X509_EXTENSION_value(ext_list, i);

            obj = X509_EXTENSION_get_object(ext);

            char object_name[1024];
            OBJ_obj2txt(object_name, 1024, obj, 0);

            i2a_ASN1_OBJECT(outbio, obj);
            X509V3_EXT_print(outbio, ext, 0, 0);
            BIO_flush(outbio);
            BIO_get_mem_ptr(outbio, &bptr);

            // remove newlines
            int lastchar = bptr->length;
            if (lastchar > 1 && (bptr->data[lastchar - 1] == '\n' || bptr->data[lastchar - 1] == '\r'))
            {
                bptr->data[lastchar - 1] = (char) 0;
            }
            if (lastchar > 0 && (bptr->data[lastchar] == '\n' || bptr->data[lastchar] == '\r'))
            {
                bptr->data[lastchar] = (char) 0;
            }

            // now bptr contains the strings of the key_usage, take
            // care that bptr->data is NOT NULL terminated, so
            // to print it well, let's do something..
            buf = (char *) XMALLOC((bptr->length + 1) * sizeof(char));
            if (buf == NULL)
            {
                log_error("Error calling malloc!");
                goto cleanup;
            }

            XMEMCPY(buf, bptr->data, bptr->length);
            buf[bptr->length] = '\0';

            if ((strcmp(object_name, "X509v3 Subject Alternative Name") == 0) &&
                (strcmp(field_name, "X509v3 Subject Alternative Name") == 0))
            {
                // X509v3 Subject Alternative NameDNS:16yXMATU8HdXouq8Vk1WWnVYgerKf2Xa9A
                //  pos 34 is where the first colon is.
                int pos = 34;
                int len = XSTRLEN(buf);
                if (len > pos)
                {
                    char substr[MEDIUM_STRING_SIZE];
                    XSNPRINTF(substr, MEDIUM_STRING_SIZE - 1, "%s", buf + (pos + 1));

                    BIO_free_all(outbio);
                    if (buf)
                        XFREE(buf);

                    return XSTRDUP(substr);
                }
            }

        cleanup:
            BIO_free_all(outbio);
            if (buf)
                XFREE(buf);
        }
    }

    return NULL;
}

CertifierError security_get_X509_PKCS12_file(const char * filename, const char * password, X509_LIST * certs, X509_CERT ** out,
                                             ECC_KEY ** out_keypair)
{
    XFILE fp                         = NULL;
    EVP_PKEY * pkey                  = NULL;
    PKCS12 * p12                     = NULL;
    X509_CERT * cert                 = NULL;
    unsigned long openssl_error_code = 0;
    bool free_cert_list              = false;
    bool free_keypair                = false;
    CertifierError result            = CERTIFIER_ERROR_INITIALIZER;

    if (filename == NULL || password == NULL)
    {
        result.application_error_code = OPENSSL_ERR_1;
        result.application_error_msg  = util_format_error_here("invalid arguments");
        goto cleanup;
    }

    if (certs == NULL)
    {
        certs          = sk_X509_new_null();
        free_cert_list = true;
    }

    if (out_keypair == NULL)
    {
        free_keypair = true;
    }

    if (!(fp = XFOPEN(filename, "rb")))
    {
        log_error("Error opening file %s\n", filename);
        goto cleanup;
    }
    p12 = d2i_PKCS12_fp(fp, NULL);
    if (!p12)
    {
        log_error("Error reading PKCS#12 file\n");
        goto cleanup;
    }

    if (!PKCS12_parse(p12, password, &pkey, &cert, &certs))
    {
        log_error("Error parsing PKCS#12 file\n");
        goto cleanup;
    }

// Cleanup - free cert after use in calling routine
cleanup:
    openssl_error_code            = ERR_get_error();
    result.application_error_code = (int) openssl_error_code;

    result.application_error_code = (int) openssl_error_code;
    if (openssl_error_code != 0)
    {
        log_error("Open SSL Error Code: %lu %s\n", openssl_error_code, ERR_error_string(openssl_error_code, NULL));
        result.application_error_msg = util_format_error(__func__, ERR_error_string(openssl_error_code, NULL), __FILE__, __LINE__);
        ERR_print_errors_fp(stderr);
    }

    if (free_cert_list)
    {
        security_free_cert_list(certs);
    }

    PKCS12_free(p12);

    if (free_keypair)
    {
        EVP_PKEY_free(pkey);
    }
    else
    {
        *out_keypair = EVP_PKEY_get1_EC_KEY(pkey);
    }

    if (fp)
    {
        XFCLOSE(fp);
    }

    if (out)
    {
        *out = cert;
    }

    ERR_clear_error();

    return result;
} /* security_get_X509_PKCS12_file */

void security_free_eckey(ECC_KEY * eckey)
{
    EC_KEY_free(eckey);
}

ECC_KEY * security_dup_eckey(const ECC_KEY * eckey)
{
    ECC_KEY * key = NULL;
    if (eckey != NULL)
    {
        key = EC_KEY_dup(eckey);
    }

    return key;
}

int security_get_random_bytes(unsigned char * out, int len)
{
    return RAND_bytes(out, len);
}

void security_free_cert(X509_CERT * cert)
{
    if (cert)
    {
        X509_free(cert);
    }
}

X509_CERT * security_dup_cert(const X509_CERT * cert)
{
    X509_CERT * newcert = NULL;
    if (cert != NULL)
    {
        newcert = X509_dup((X509_CERT *) cert);
    }
    return newcert;
}

X509_CERT * security_cert_list_get(X509_LIST * certs, int which)
{
    if (certs == NULL)
    {
        return NULL;
    }

    return sk_X509_value(certs, which);
}

X509_CERT * security_cert_list_pop(X509_LIST * certs, int which)
{
    if (certs == NULL)
    {
        return NULL;
    }

    return sk_X509_delete(certs, which);
}

void security_free_cert_list(X509_LIST * certs)
{
    if (certs)
    {
        sk_X509_pop_free(certs, X509_free);
    }
}

X509_LIST * security_new_cert_list(void)
{
    return sk_X509_new_null();
}

void security_print_certs_in_list(X509_LIST * certs, XFILE output)
{
    int i;
    BIO * outbio = BIO_new_fp(output, BIO_NOCLOSE);
    for (i = 0; certs && i < sk_X509_num(certs); i++)
    {
        PEM_write_bio_X509(outbio, sk_X509_value(certs, i));
    }
    BIO_free_all(outbio);
}

X509_CERT * security_X509_from_DER(const unsigned char * der, size_t der_len)
{
    X509 * cert;
    const unsigned char ** derp = &der;
    cert                        = d2i_X509(NULL, derp, der_len);
    return cert;
}

unsigned char * security_X509_to_DER(X509_CERT * cert, size_t * out_len)
{
    unsigned char * out = NULL;
    int ret;
    ret = i2d_X509(cert, &out);

    if (ret <= 0)
        return NULL;

    *out_len = ret;
    return out;
}

void security_print_subject_issuer(const X509_CERT * cert)
{
    X509_NAME * subject = NULL;
    X509_NAME * issuer  = NULL;

    subject = X509_get_subject_name(cert);
    if (subject == NULL)
    {
        return;
    }

    issuer = X509_get_issuer_name(cert);
    if (issuer == NULL)
    {
        return;
    }

    char * ssubject = X509_NAME_oneline(subject, NULL, 0);
    char * sissuer  = X509_NAME_oneline(issuer, NULL, 0);

    printf("subject=%s\n\n", ssubject);
    printf("issuer=%s\n\n", sissuer);

    XFREE(ssubject);
    XFREE(sissuer);
}

CertifierError load_certs_from_pkcs7(const char * pkcs7, X509_LIST ** out)
{
    CertifierError result = CERTIFIER_ERROR_INITIALIZER;

    if (out == NULL)
    {
        result.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        result.application_error_msg  = util_format_error_here("out must not be NULL");
        return result;
    }

    X509_LIST * certs = NULL;

    BIO * bio_cert = NULL;
    PKCS7 * p7     = NULL;
    int p7_type    = 0;

    bio_cert = BIO_new_mem_buf(pkcs7, -1);

    p7 = PEM_read_bio_PKCS7(bio_cert, NULL, NULL, NULL);
    if (!p7)
    {
        result.application_error_msg = util_format_error_here(ERR_error_string(ERR_get_error(), NULL));
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    p7_type = OBJ_obj2nid(p7->type);
    if (p7_type == NID_pkcs7_signed)
    {
        certs = p7->d.sign->cert;
    }
    else if (p7_type == NID_pkcs7_signedAndEnveloped)
    {
        certs = p7->d.signed_and_enveloped->cert;
    }

    if (!certs)
    {
        result.application_error_msg = util_format_error(__func__, "Internal error.  certs are empty/null!", __FILE__, __LINE__);
        goto cleanup;
    }

    log_debug("Certs Length is: %i", sk_X509_num(certs));

    if (sk_X509_num(certs) != 3)
    {
        result.application_error_msg =
            util_format_error(__func__, "Internal error.  Expected there to be 3 certs.", __FILE__, __LINE__);
        security_free_cert_list(certs);
        certs = NULL;
        goto cleanup;
    }

    certs = X509_chain_up_ref(certs);

cleanup:
    BIO_free_all(bio_cert);
    PKCS7_free(p7);
    if (result.application_error_msg != NULL)
    {
        result.application_error_code = CERTIFIER_ERR_GET_CERT_STATUS_1;
    }

    *out = certs;
    return result;
}

CertifierError load_certs_from_certificate(const char * pem, X509_LIST ** out, bool load_all_certs)
{
    CertifierError result = CERTIFIER_ERROR_INITIALIZER;

    if (out == NULL)
    {
        result.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        result.application_error_msg  = util_format_error_here("out must not be NULL");
        return result;
    }

    X509_LIST * certs = NULL;
    X509_CERT * cert  = NULL;

    size_t cert_len = XSTRLEN(pem);

    BIO * cert_bio = BIO_new(BIO_s_mem());
    BIO_write(cert_bio, pem, cert_len);
    
    certs = sk_X509_new_null();
    if (certs == NULL)
    {
        result.application_error_msg = util_format_error(__func__, "Unable to call sk_X509_new_null!", __FILE__, __LINE__);
        goto cleanup;
    }
    
    if (load_all_certs)
    {
        // Read all certificates (i.e. for OCSP) 
        while ((cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL)) != NULL)
        {
            sk_X509_push(certs, cert);
        }
    }
    else
    {
        // Legacy behavior loading only the first certificate from the chain
        cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
        if (cert != NULL)
        {
            sk_X509_push(certs, cert);
        }
    }
    
    // Check if we read at least one certificate
    if (sk_X509_num(certs) == 0)
    {
        result.application_error_msg = util_format_error(__func__, "Unable to parse any certificates!", __FILE__, __LINE__);
        goto cleanup;
    }

cleanup:
    BIO_free(cert_bio);

    if (result.application_error_msg != NULL)
    {
        result.application_error_code = CERTIFIER_ERR_GET_CERT_STATUS_1;
    }

    *out = certs;
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

ECC_KEY * security_get_key_from_der(unsigned char * der_public_key, int der_public_key_len)
{
    BIO * bio = BIO_new_mem_buf(der_public_key, der_public_key_len);

    ECC_KEY * key = d2i_EC_PUBKEY_bio(bio, NULL);

    BIO_free_all(bio);

    return key;
}

ECC_KEY * security_get_private_key_from_der(unsigned char * der_key, int der_key_len)
{
    BIO * bio = BIO_new_mem_buf(der_key, der_key_len);

    ECC_KEY * key = d2i_ECPrivateKey_bio(bio, NULL);

    BIO_free_all(bio);

    return key;
}

int security_serialize_der_public_key(ECC_KEY * ec_key, unsigned char ** der_public_key)
{
    int der_len = 0;

    der_len = i2d_EC_PUBKEY(ec_key, der_public_key);

    if (der_len < 0)
        return 0;
    else
        return der_len;
}

int security_serialize_raw_public_key(ECC_KEY * ec_key, unsigned char * public_key, size_t public_key_capacity)
{
    int len            = 0;
    EC_GROUP * group   = NULL;
    size_t pubkey_size = 0;

    const EC_POINT * pubkey_ecp = EC_KEY_get0_public_key(ec_key);
    if (pubkey_ecp == NULL)
    {
        goto exit;
    }

    group = EC_GROUP_new_by_curve_name(EC_curve_nist2nid("P-256"));
    if (group == NULL)
    {
        goto exit;
    }

    pubkey_size = EC_POINT_point2oct(group, pubkey_ecp, POINT_CONVERSION_UNCOMPRESSED, public_key, public_key_capacity, NULL);
    pubkey_ecp  = NULL;

    if (pubkey_size != 65)
    {
        goto exit;
    }

    len = pubkey_size;

exit:
    if (group != NULL)
    {
        EC_GROUP_free(group);
        group = NULL;
    }

    return len;
}

int security_serialize_raw_private_key(ECC_KEY * ec_key, unsigned char * private_key, size_t private_key_capacity)
{
    if (private_key_capacity != 32)
    {
        return 0;
    }

    int privkey_size          = 0;
    const BIGNUM * privkey_bn = EC_KEY_get0_private_key(ec_key);
    if (privkey_bn == NULL)
    {
        return 0;
    }

    privkey_size = BN_bn2binpad(privkey_bn, private_key, private_key_capacity);
    privkey_bn   = NULL;
    if (privkey_size != private_key_capacity)
    {
        return 0;
    }

    return privkey_size;
}

CertifierError security_check_x509_valid_range(time_t current_time, long min_secs_left, X509_CERT * cert,
                                               const char * sim_cert_before_time, const char * sim_cert_after_time)
{
    CertifierError result                 = CERTIFIER_ERROR_INITIALIZER;
    ASN1_TIME * before_time               = NULL;
    ASN1_TIME * after_time                = NULL;
    bool is_before_cert_simulation_active = false;
    bool is_after_cert_simulation_active  = false;
    int time_cmp                          = 0;

    if (sim_cert_before_time && XSTRLEN(sim_cert_before_time) > 0)
    {
        before_time                      = ASN1_TIME_new();
        is_before_cert_simulation_active = true;
        if (!ASN1_TIME_set_string(before_time, sim_cert_before_time))
        {
            result.application_error_code = CERTIFIER_ERR_REGISTRATION_STATUS_SIMULATION_1;
            result.application_error_msg =
                util_format_error(__func__, "Could not obtain the before expiration date.", __FILE__, __LINE__);
            goto cleanup;
        }
    }
    else
    {
        before_time = X509_get_notBefore(cert);
    }

    if (sim_cert_after_time && XSTRLEN(sim_cert_after_time) > 0)
    {
        after_time                      = ASN1_TIME_new();
        is_after_cert_simulation_active = true;
        if (!ASN1_TIME_set_string(after_time, sim_cert_after_time))
        {
            result.application_error_code = CERTIFIER_ERR_REGISTRATION_STATUS_SIMULATION_2;
            result.application_error_msg =
                util_format_error(__func__, "Could not set the after expiration time.", __FILE__, __LINE__);
            goto cleanup;
        }
    }
    else
    {
        after_time = X509_get_notAfter(cert);
    }

    /*
     * Some versions of openSSL (up to 1.1.0i) did not define the X509_cmp_time contract well and MAY return:
     * <= -1: ASN.1 time is before or on current_time
     * 0: error
     * >= 1: ASN.1 time is after current_time.
     */
    time_cmp = X509_cmp_time(before_time, &current_time);
    if (time_cmp > -1)
    {
        result.application_error_code = CERTIFIER_ERR_REGISTRATION_STATUS_CERT_EXPIRED_1;
        result.application_error_msg  = util_format_error_here("certificate not yet valid!");
        goto cleanup;
    }

    time_cmp = X509_cmp_time(after_time, &current_time);
    if (time_cmp < 1)
    {
        result.application_error_code = CERTIFIER_ERR_REGISTRATION_STATUS_CERT_EXPIRED_2;
        result.application_error_msg  = util_format_error(__func__, "Certificate has expired.", __FILE__, __LINE__);
        goto cleanup;
    }

    if (min_secs_left != 0)
    {
        int diff_day;
        int diff_sec;

        if (ASN1_TIME_diff(&diff_day, &diff_sec, NULL, after_time))
        {
            //            if ((diff_day * SECS_IN_DAY + diff_sec) < min_secs_left) {
            if ((((long) diff_day) * SECS_IN_DAY + diff_sec) < min_secs_left)
            {
                result.application_error_code = CERTIFIER_ERR_REGISTRATION_STATUS_CERT_ABOUT_TO_EXPIRE;
                result.application_error_msg  = util_format_error_here("Certificate is about to expire!");
            }
        }
        else
        {
            result.application_error_code = CERTIFIER_ERR_REGISTRATION_STATUS_CERT_ABOUT_TO_EXPIRE;
            result.application_error_msg  = util_format_error_here("Unable to determine certificate expiration status;"
                                                                    "assuming it is about to expire!");
        }
    }

cleanup:

    if (before_time && is_before_cert_simulation_active)
    {
        ASN1_TIME_free(before_time);
    }

    if (after_time && is_after_cert_simulation_active)
    {
        ASN1_TIME_free(after_time);
    }

    return result;
}

int security_get_before_time_validity(const X509_CERT * cert, char * time, size_t time_len)
{
    BIO * bio;

    bio = BIO_new(BIO_s_mem());
    if (bio)
    {
        if (ASN1_TIME_print(bio, X509_get_notBefore(cert)))
        {
            int bytes_read   = BIO_read(bio, time, time_len - 1);
            time[bytes_read] = '\0';
        }
        BIO_free(bio);
    }
    else
    {
        return 1;
    }

    return 0;
}

int security_get_not_after_time_validity(const X509_CERT * cert, char * time, size_t time_len)
{
    BIO * bio;

    bio = BIO_new(BIO_s_mem());
    if (bio)
    {
        if (ASN1_TIME_print(bio, X509_get_notAfter(cert)))
        {
            int bytes_read   = BIO_read(bio, time, time_len - 1);
            time[bytes_read] = '\0';
        }
        BIO_free(bio);
    }
    else
    {
        return 1;
    }

    return 0;
}

static X509 * openssl_load_cert(const char * cert_str)
{
    BIO * bio = BIO_new(BIO_s_mem());
    BIO_puts(bio, cert_str);
    X509 * certificate = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free_all(bio);
    return certificate;
}

/*

static char *X509_to_PEM(X509 *cert) {

 BIO *bio = NULL;
 char *pem = NULL;

 if (NULL == cert) {
     return NULL;
 }

 bio = BIO_new(BIO_s_mem());
 if (NULL == bio) {
     return NULL;
 }

 if (0 == PEM_write_bio_X509(bio, cert)) {
     BIO_free(bio);
     return NULL;
 }

 pem = (char *) XMALLOC(bio->num_write + 1);
if (NULL == pem) {
     BIO_free(bio);
     return NULL;
 }

 XMEMSET(pem, 0, bio->num_write + 1);
 BIO_read(bio, pem, bio->num_write);
 BIO_free(bio);
 return pem;
}

static void cert_info(const char* cert_pem)
{
 BIO *b = BIO_new(BIO_s_mem());
 BIO_puts(b, cert_pem);
 X509 * x509 = PEM_read_bio_X509(b, NULL, NULL, NULL);

 BIO *bio_out = BIO_new_fp(stderr, BIO_NOCLOSE);

 //Subject
 BIO_printf(bio_out,"Subject: ");
 X509_NAME_print(bio_out,X509_get_subject_name(x509),0);
 BIO_printf(bio_out,"\n");

 //Issuer
 BIO_printf(bio_out,"Issuer: ");
 X509_NAME_print(bio_out,X509_get_issuer_name(x509),0);
 BIO_printf(bio_out,"\n");

 //Public Key
 EVP_PKEY *pkey=X509_get_pubkey(x509);
 EVP_PKEY_print_public(bio_out, pkey, 0, NULL);
 EVP_PKEY_free(pkey);

 //Signature
 X509_signature_print(bio_out, x509->sig_alg, x509->signature);
 BIO_printf(bio_out,"\n");

 BIO_free(bio_out);
 BIO_free(b);
 X509_free(x509);
}
*/

CertifierError security_check_cert_is_valid(X509_CERT * cert, const char * security_cert_root_ca, const char * security_cert_int_ca,
                                            time_t * overridden_time_t)
{
    CertifierError result = CERTIFIER_ERROR_INITIALIZER;

    // char *cert_pem = NULL;

    X509_STORE * store   = NULL;
    X509_STORE_CTX * ctx = NULL;

    time_t check_time;

    X509 * ca_cert = openssl_load_cert(security_cert_root_ca);

    X509 * int_cert = openssl_load_cert(security_cert_int_ca);

    if (ca_cert == NULL || int_cert == NULL)
    {
        result.application_error_code = OPENSSL_ERR_1;
        result.application_error_msg  = util_format_error(__func__, "ca_cert and/or int_cert was null.", __FILE__, __LINE__);
        goto cleanup;
    }

    store = X509_STORE_new();
    if (store == NULL)
    {
        result.application_error_code = OPENSSL_ERR_2;
        result.application_error_msg  = util_format_error(__func__, "x509_store was null.", __FILE__, __LINE__);
        goto cleanup;
    }

    ctx = X509_STORE_CTX_new();
    if (ctx == NULL)
    {
        result.application_error_code = OPENSSL_ERR_3;
        result.application_error_msg  = util_format_error(__func__, "x509 context was null.", __FILE__, __LINE__);
        goto cleanup;
    }

    X509_STORE_add_cert(store, ca_cert);
    X509_STORE_add_cert(store, int_cert);

    if (overridden_time_t == NULL)
    {
        check_time = time(NULL);
    }
    else
    {
        check_time = *overridden_time_t;
    }

    X509_STORE_CTX_init(ctx, store, cert, NULL);

    X509_STORE_CTX_set_time(ctx, 0, check_time);
    X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_USE_CHECK_TIME);

    result.application_error_code = X509_verify_cert(ctx);

    if (result.application_error_code == 1)
    {
        // result.error_codeurn value of 1 indicates certificate chain was valid
        result.application_error_code = 0;
    }
    else
    {
        int err = X509_STORE_CTX_get_error(ctx);
        log_error("certificate validation failed %s", X509_verify_cert_error_string(err));
        result.application_error_msg  = util_format_error(__func__, "certificate validation failed.", __FILE__, __LINE__);
        result.application_error_code = OPENSSL_ERR_4 + err;
    }

cleanup:
    X509_free(ca_cert);
    X509_free(int_cert);
    X509_STORE_free(store);
    X509_STORE_CTX_free(ctx);

    return result;
}

char * security_get_version(void)
{
    return util_format_str("OpenSSL (Library: %s)", SSLeay_version(SSLEAY_VERSION));
}

#endif
