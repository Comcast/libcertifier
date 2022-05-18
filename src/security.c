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

#include "certifier/security.h"
#include "certifier/base64.h"
#include "certifier/base58.h"
#include "certifier/certifier.h"
#include "certifier/log.h"
#include "certifier/parson.h"
#include "certifier/types.h"
#include "certifier/util.h"

const char X509_TOKEN_TYPE[] = "X509";

unsigned char *
security_generate_csr(ECC_KEY *eckey, size_t *retlen);

char *
security_generate_certificate_signing_request(ECC_KEY *eckey, int *retlen) {

    unsigned char *der_csr = NULL;
    char *base64_csr = NULL;
    size_t der_csr_len = 0;
    size_t b64_csr_len = 0;

    der_csr = security_generate_csr(eckey, &der_csr_len);

    if (der_csr == NULL || der_csr_len == 0)
        goto cleanup;

    b64_csr_len = base64_encode_len(der_csr_len);

    base64_csr = XMALLOC(b64_csr_len + 4);

    if (base64_csr == NULL)
        goto cleanup;

    base64_encode(base64_csr, der_csr, der_csr_len);
    *retlen = (int) XSTRLEN(base64_csr);

    cleanup:
    XFREE(der_csr);

    return base64_csr;
}

char *
security_encode(const unsigned char *value, int len, int *return_code) {
    const unsigned char version = 0x00;
    char *out = NULL;
    int i = 0;
    int err_code = 1;
    unsigned char checksum[4];

#define SHA256_DIGEST_LENGTH 32
#define RIPEMD160_DIGEST_LENGTH 20

    unsigned char sharesults[SHA256_DIGEST_LENGTH] = {0};
    unsigned char riperesults[RIPEMD160_DIGEST_LENGTH] = {0};
    unsigned char hash[SHA256_DIGEST_LENGTH * 2] = {0};

    const int out_len = 1 + RIPEMD160_DIGEST_LENGTH + 4;

    // ALGO -
    // Version = 1 byte of 0's; on the test network, this is 1 byte of 1's
    // Key hash = Version concatenated with RIPEMD-160(SHA-256(input value))
    // Checksum = 1st 4 bytes of SHA-256(SHA-256(Key hash))
    // Ledger Address = Base58Encode(Key hash concatenated with Checksum)

    // Make sure input is at least 128 long, else pad with pkcs7pad

    sha256_ctx *sha256 = security_sha256_init();

    security_sha256_update(sha256, value, len);

    if (len < 128) {
        unsigned char pad_byte = 128 - len;
        for (int i = 0; i != pad_byte; ++i)
            security_sha256_update(sha256, &pad_byte, 1);
    }

    security_sha256_finish(sha256, sharesults);

    CertifierError result = security_rmd160(riperesults, sharesults, SHA256_DIGEST_LENGTH);
    if (result.application_error_code != 0) {
        err_code = CERTIFIER_ERR_SECURITY_ENCODE_1;
        goto cleanup;
    }

    // Calculate Checksum
    hash[0] = version;
    XMEMCPY(hash + 1, riperesults, RIPEMD160_DIGEST_LENGTH);

    if (security_sha256(sharesults, hash, RIPEMD160_DIGEST_LENGTH + 1) != 0) {
        err_code = CERTIFIER_ERR_SECURITY_ENCODE_2;
        goto cleanup;
    }
    if (security_sha256(sharesults, sharesults, SHA256_DIGEST_LENGTH) != 0) {
        err_code = CERTIFIER_ERR_SECURITY_ENCODE_3;
        goto cleanup;
    }

    for (i = 0; i < 4; i++) {
        checksum[i] = sharesults[i];
    }

    // Base64encode(value, results, SHA256_DIGEST_LENGTH);
    out = (char *) XMALLOC(out_len * 3);
    if (out == NULL) {
        err_code = CERTIFIER_ERR_SECURITY_ENCODE_4;
        goto cleanup;
    }

    out[0] = version;
    XMEMCPY(out + 1, riperesults, RIPEMD160_DIGEST_LENGTH);
    XMEMCPY(out + 1 + RIPEMD160_DIGEST_LENGTH, checksum, 4);

    // Base58 Encode
    base58_b58enc(out, out, out_len);

    err_code = 0; // success

    cleanup:

    error_clear(&result);
    if (return_code) {
        *return_code = err_code;
    }

    return (out);
} /* securityhelper_encode */

int security_sha256_update_cstr(sha256_ctx *ctx, const char *str) {
    return security_sha256_update(ctx, (const unsigned char *) str, XSTRLEN(str));
}

int
security_sha1(unsigned char *output, const unsigned char *input, size_t input_len) {
    sha1_ctx *h = security_sha1_init();

    security_sha1_update(h, input, input_len);
    security_sha1_finish(h, output);
    return 0;
}

int
security_sha256(uint8_t *digest, const uint8_t *message, size_t len) {
    sha256_ctx *h = security_sha256_init();

    security_sha256_update(h, message, len);
    security_sha256_finish(h, digest);
    return 0;
}

char *
security_sign_hash_b64(const ECC_KEY *key, const unsigned char *digest, const size_t digest_len) {
    size_t sig_len = 0;
    unsigned char *sig = NULL;
    size_t b64_len = 0;
    char *b64_sig = NULL;

    sig = security_sign_hash(key, digest, digest_len, &sig_len);

    if (sig == NULL || sig_len == 0) {
        log_error("[security_sign_hash_b64] signature was null and/or length was zero.");
        goto cleanup;
    }

    b64_len = base64_encode_len(sig_len);
    b64_sig = XMALLOC(b64_len + 6);

    if (b64_sig == NULL) {
        log_error("[security_sign_hash_b64] b64_sig was null and could not allocate memory.");
        goto cleanup;
    }

    base64_encode(b64_sig, sig, sig_len);

    cleanup:
    if (sig != NULL) {
        XFREE(sig);
    }

    return b64_sig;
}

int security_generate_x509_crt(char **output_serialized_string, X509_CERT *x509_cert, ECC_KEY *key) {
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    sha256_ctx *sha256 = NULL;
    struct timeval ptm;
    unsigned char digest[32] = {0};
    unsigned char *der_cert = NULL;
    char *der_base64 = NULL;
    size_t der_cert_len = 0;
    char *signature = NULL;
    char *nonce = NULL;
    long long ms = 0;
    int return_code = 0;

    json_object_set_string(root_object, "tokenType", X509_TOKEN_TYPE);

    der_cert = security_X509_to_DER(x509_cert, &der_cert_len);
    if (der_cert == NULL || der_cert_len == 0)
        goto cleanup;


    der_base64 = XMALLOC(base64_encode_len(der_cert_len + 2));

    if (der_base64 == NULL)
        goto cleanup;

    base64_encode(der_base64, der_cert, der_cert_len);
    json_object_set_string(root_object, "certificate", der_base64);

    gettimeofday(&ptm, NULL);
    char timestamp[21];
    ms = ptm.tv_sec * 1000LL + ptm.tv_usec / 1000; // calculate milliseconds
    sprintf(timestamp, "%lld", ms);

    json_object_set_string(root_object, "timestamp", timestamp);

    nonce = util_generate_random_value(16, ALLOWABLE_CHARACTERS);

    if (nonce == NULL) {
        log_error("Error Generating Nonce returned NULL.");
        return_code = CERTIFIER_ERR_GENERATE_CRT_NONCE;
        goto cleanup;
    }

    json_object_set_string(root_object, "nonce", nonce);

    // Create the transaction
    sha256 = security_sha256_init();
    security_sha256_update(sha256, der_cert, der_cert_len);
    security_sha256_update_cstr(sha256, timestamp);
    security_sha256_update_cstr(sha256, nonce);
    security_sha256_update_cstr(sha256, X509_TOKEN_TYPE);
    security_sha256_finish(sha256, digest);

    // Sign the transaction
    signature = security_sign_hash_b64(key, digest, sizeof(digest));

    json_object_set_string(root_object, "signature", signature);

    *output_serialized_string = json_serialize_to_string_pretty(root_value);

    cleanup:

    json_value_free(root_value);

    XFREE(signature);
    XFREE(nonce);
    XFREE(der_cert);
    XFREE(der_base64);

    return return_code;
}

CertifierError
security_verify_x509(X509_CERT *cert, const char *signature_b64, const unsigned char *input, int input_len,
                     const char *security_cert_root_ca, const char *security_cert_int_ca,
                     int security_flags,
                     time_t *overridden_time_t) {
    ECC_KEY *pk = NULL;
    CertifierError rc = CERTIFIER_ERROR_INITIALIZER;

    if (cert == NULL) {
        rc.application_error_code = 1;
        goto cleanup;
    }


    if (security_flags & VALIDATE_CERT) {
        rc = security_check_cert_is_valid(cert, security_cert_root_ca, security_cert_int_ca, overridden_time_t);
        if (rc.application_error_code != 0)
            goto cleanup;
    }


    if (security_flags & VALIDATE_SIGNATURE) {
        pk = security_get_key_from_cert(cert);
        if (pk == NULL) {
            //FIXME: magic number
            rc.application_error_code = 3;
            goto cleanup;
        }

        rc = security_verify_signature(pk, signature_b64, input, input_len);
        if (rc.application_error_code != 0) {
            log_error("**** security_verify_signature is: %i", rc.application_error_code);
            //FIXME: magic number
            rc.application_error_code = 4;
            goto cleanup;
        }
    }

    cleanup:
    if (pk != NULL) {
        security_free_eckey(pk);
    }

    return rc;
}
