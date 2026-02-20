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

#include "certifier/types.h"

#ifdef CMOCKA_ENABLED

#include <cmocka.h>

#else
#include <unity.h>
#endif

#include <stdbool.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "certifier/base58.h"
#include "certifier/base64.h"
#include "certifier/certifier.h"
#include "certifier/certifierclient.h"
#include "certifier/security.h"

#include "certifier/certifier_internal.h"
#include "certifier/http.h"
#include "certifier/log.h"
#include "certifier/parson.h"
#include "certifier/types.h"
#include "certifier/util.h"
#include "tests.h"

extern inline void delete_file(const char * path);

static Certifier * certifier                 = NULL;
static const char * g_mock_http_expected_url = NULL;
static char * g_mock_http_expected_body      = NULL;
static http_response g_mock_http_response;

// FIXME: use cmocka object mocking for this instead of assert
static http_response * do_http(const char * url, const char * http_headers[], const char * body, const char * http_method)
{
    if (g_mock_http_expected_url != NULL)
        assert_string_equal(g_mock_http_expected_url, url);
    if ((g_mock_http_expected_body != NULL) && (body != NULL))
        assert_string_equal(g_mock_http_expected_body, body);

    // reset for next test
    g_mock_http_expected_url = NULL;

    XFREE(g_mock_http_expected_body);
    g_mock_http_expected_body = NULL;

    return &g_mock_http_response;
}

http_response * http_get(const CertifierPropMap * props, const char * url, const char * http_headers[])
{
    return do_http(url, http_headers, NULL, "GET");
}

http_response * http_post(const CertifierPropMap * props, const char * url, const char * http_headers[], const char * body)
{

    return do_http(url, http_headers, body, "POST");
}

http_response * http_put(const CertifierPropMap * props, const char * url, const char * http_headers[], const char * body)
{
    return do_http(url, http_headers, body, "PUT");
}

void http_free_response(http_response * resp)
{
    if (resp)
    {
        assert_ptr_equal(resp, &g_mock_http_response);
    }
}

int http_init(void)
{
    return 0;
}

int http_destroy(void)
{
    return 0;
}

static void mock_http_set_response_success(const char * body, int status)
{
    g_mock_http_response.payload   = body;
    g_mock_http_response.http_code = status;
    g_mock_http_response.error_msg = NULL;
    g_mock_http_response.error     = 0;
}

// Add unused attribute marker to suppress warning
__attribute__((unused)) static void mock_http_set_response_failure(const char * err, int status)
{
    g_mock_http_response.payload   = NULL;
    g_mock_http_response.http_code = status;
    g_mock_http_response.error_msg = err;
    g_mock_http_response.error     = status;
}

static void test_certifier_client_requests(void)
{

    const char * csr           = "CSr";
    const char * node_address  = "802802802";
    const char * node_id       = "AABBCCDDEEFFEEDD";
    const char * profile_name  = "profile";
    const char * product_id    = "product";
    const char * certifier_id  = "12345";
    const char * fabric_id     = "fabric";
    const char * certifier_url = "https://some.host";
    const char * bearer_token  = "polar";
    const char * tracking_id   = "12345678";
    const char * source        = "test_libcertifier";
    size_t validity_days       = 365;
    char * ret                 = NULL;

    JSON_Value * root_value   = json_value_init_object();
    JSON_Object * root_object = json_value_get_object(root_value);

    g_mock_http_expected_url = "https://some.host/certificate";

    json_object_set_string(root_object, "csr", (const char *) csr);
    json_object_set_string(root_object, "nodeAddress", node_address);
    json_object_set_string(root_object, "nodeId", node_id);
    json_object_set_string(root_object, "profileName", profile_name);
    json_object_set_string(root_object, "productId", product_id);
    if (XSTRLEN(fabric_id) > 0)
    {
        json_object_set_string(root_object, "fabricId", fabric_id);
    }
    json_object_set_string(root_object, "ledgerId", certifier_id);
    json_object_set_number(root_object, "validityDays", validity_days);
    json_object_set_string(root_object, "certificateLite", "true");

    g_mock_http_expected_body = json_serialize_to_string_pretty(root_value);

    mock_http_set_response_success("{\"certificateChain\":\"hereitis\"}", 200);

    certifier_set_property(certifier, CERTIFIER_OPT_SOURCE, source);
    certifier_set_property(certifier, CERTIFIER_OPT_TRACKING_ID, tracking_id);
    certifier_set_property(certifier, CERTIFIER_OPT_CRT, bearer_token);
    certifier_set_property(certifier, CERTIFIER_OPT_FABRIC_ID, fabric_id);
    certifier_set_property(certifier, CERTIFIER_OPT_CERTIFIER_URL, certifier_url);
    certifier_set_property(certifier, CERTIFIER_OPT_NODE_ID, node_id);
    certifier_set_property(certifier, CERTIFIER_OPT_PROFILE_NAME, profile_name);
    certifier_set_property(certifier, CERTIFIER_OPT_PRODUCT_ID, product_id);

    int options = (int)(size_t)certifier_get_property(certifier, CERTIFIER_OPT_OPTIONS);
    options |= CERTIFIER_OPTION_CERTIFICATE_LITE;
    certifier_set_property(certifier, CERTIFIER_OPT_OPTIONS, (void *)(size_t)options);

    CertifierError rc = certifierclient_request_x509_certificate(_certifier_get_properties(certifier), (unsigned char *) csr,
                                                                 node_address, certifier_id, &ret);
    assert_int_equal(0, rc.application_error_code);
    error_clear(&rc);
    assert_string_equal(ret, "hereitis");

    XFREE(ret);

    if (root_value)
    {
        json_value_free(root_value);
    }
}

static void test_certifier_client_requests1(void)
{

    const char * csr           = "CSr";
    const char * ledger_id     = "12345";
    const char * node_id       = "AABBCCDDEEFFEEDD";
    const char * profile_name  = "profile";
    const char * product_id    = "product";
    const char * fabric_id     = "system";
    const char * certifier_url = "https://some.host";
    const char * bearer_token  = "polar";
    const char * tracking_id   = "12345678";
    const char * source        = "test_libledger";
    char * ret                 = NULL;
    char * cn_prefix           = NULL;
    int return_code = 0;
    unsigned int num_days = 0;

    JSON_Value * root_value   = json_value_init_object();
    JSON_Object * root_object = json_value_get_object(root_value);

    g_mock_http_expected_url = "https://some.host/certificate";

    return_code = certifier_set_property(certifier, CERTIFIER_OPT_CN_PREFIX, "xcal.tv");
    assert_int_equal(0, return_code);

    return_code = certifier_set_property(certifier, CERTIFIER_OPT_VALIDITY_DAYS, (void *)(size_t)730);
    assert_int_equal(0, return_code);

    cn_prefix = certifier_get_property(certifier, CERTIFIER_OPT_CN_PREFIX);
    num_days  = (unsigned int)(size_t)certifier_get_property(certifier, CERTIFIER_OPT_VALIDITY_DAYS);
    assert_int_equal(730, num_days);
    if (cn_prefix)
    {
        return_code = strncmp(cn_prefix, "xcal.tv", 8);
        assert_int_equal(0, return_code);
    }

    json_object_set_string(root_object, "csr", (const char *) csr);
    json_object_set_string(root_object, "nodeAddress", cn_prefix);

    json_object_set_string(root_object, "nodeId", node_id);
    json_object_set_string(root_object, "profileName", profile_name);
    json_object_set_string(root_object, "productId", product_id);

    if (strlen(fabric_id) > 0)
    {
        json_object_set_string(root_object, "fabricId", fabric_id);
    }

    json_object_set_string(root_object, "ledgerId", ledger_id);

    if (num_days > 0)
    {
        json_object_set_number(root_object, "validityDays", num_days);
    }

    json_object_set_string(root_object, "certificateLite", "true");

    g_mock_http_expected_body = json_serialize_to_string_pretty(root_value);

    mock_http_set_response_success("{\"certificateChain\":\"hereitis\"}", 200);

    certifier_set_property(certifier, CERTIFIER_OPT_SOURCE, source);
    certifier_set_property(certifier, CERTIFIER_OPT_TRACKING_ID, tracking_id);
    certifier_set_property(certifier, CERTIFIER_OPT_CRT, bearer_token);
    certifier_set_property(certifier, CERTIFIER_OPT_FABRIC_ID, fabric_id);
    certifier_set_property(certifier, CERTIFIER_OPT_CERTIFIER_URL, certifier_url);
    certifier_set_property(certifier, CERTIFIER_OPT_NODE_ID, node_id);
    certifier_set_property(certifier, CERTIFIER_OPT_PROFILE_NAME, profile_name);
    certifier_set_property(certifier, CERTIFIER_OPT_PRODUCT_ID, product_id);

    int options = (int)(size_t)certifier_get_property(certifier, CERTIFIER_OPT_OPTIONS);
    options |= CERTIFIER_OPTION_CERTIFICATE_LITE;
    certifier_set_property(certifier, CERTIFIER_OPT_OPTIONS, (void *)(size_t)options);

    CertifierError rc = certifierclient_request_x509_certificate(_certifier_get_properties(certifier), (unsigned char *) csr,
                                                                 cn_prefix, ledger_id, &ret);
    assert_int_equal(0, rc.application_error_code);
    error_clear(&rc);
    assert_string_equal(ret, "hereitis");

    free(ret);

    // if (cn_prefix) {
    //   free(cn_prefix);
    // }

    if (root_value)
    {
        json_value_free(root_value);
    }
}

static void test_certifier_create_crt1(void)
{
    int rc         = 0;
    char * out_crt = NULL;

    certifier_set_property(certifier, CERTIFIER_OPT_AUTH_TOKEN, "test token");
    rc = certifier_create_crt(certifier, &out_crt, "CRT_TYPE_2");
    assert_int_equal(0, rc);
    assert_non_null(out_crt);
    XFREE(out_crt);
    out_crt = NULL;

    certifier_set_property(certifier, CERTIFIER_OPT_AUTH_TOKEN, "");
    rc = certifier_create_crt(certifier, &out_crt, "CRT_TYPE_2");
    assert_int_equal(100300, rc);
    assert_null(out_crt);
    XFREE(out_crt);
}

static void test_certifier_create_node_address(void)
{
    int rc                      = 0;
    char * node_address         = NULL;
    const unsigned char input[] = { 't', 's', 't' };

    rc = certifier_create_node_address(input, 3, &node_address);
    assert_int_equal(0, rc);
    XFREE(node_address);
    node_address = NULL;

    rc = certifier_create_node_address(NULL, 3, &node_address);
    assert_int_equal(100100, rc);
    XFREE(node_address);
}

static void test_certifier_get_version(void)
{
    char * out_version = certifier_get_version(certifier);

    assert_non_null(out_version);
    XFREE(out_version);

    char * security_ver = security_get_version();
    assert_non_null(security_ver);
    XFREE(security_ver);
}

#ifndef CMOCKA_ENABLED

void setUp(void)
{
    // TEST_ASSERT_EQUAL_INT_MESSAGE(0, certifier_init(), "Initialization worked");
    certifier = certifier_new();

    if (certifier != NULL)
    {

        certifier_set_property(certifier, CERTIFIER_OPT_MEASURE_PERFORMANCE, (void *) true);
    }
}

void tearDown(void)
{
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, certifier_destroy(certifier), "Certifier shutdown worked");
    certifier = NULL;

    XFREE(g_mock_http_expected_body);
    g_mock_http_expected_body = NULL;
}
#else

static int setUp(void ** state)
{
    certifier = certifier_new();

    if (certifier == NULL)
    {
        return 1;
    }

    certifier_set_property(certifier, CERTIFIER_OPT_MEASURE_PERFORMANCE, (void *) true);

    return 0;
}

static int tearDown(void ** state)
{
    int rc    = certifier_destroy(certifier);
    certifier = NULL;

    XFREE(g_mock_http_expected_body);
    g_mock_http_expected_body = NULL;

    return rc;
}

#endif

static void test_base64(void)
{
    char buf[64];

    assert_int_equal(9, base64_encode_len(5));

    assert_int_equal(7, base64_decode_len("padpad00"));
    assert_int_equal(7, base64_decode_len("padpad00======="));
    assert_int_equal(7, base64_decode_len("padpad00========================="));

    assert_int_equal(13, base64_encode_len(7));
    assert_int_equal(13, base64_encode_len(8));
    assert_int_equal(13, base64_encode_len(9));
    assert_int_equal(17, base64_encode_len(10));

    assert_int_equal(1, base64_encode(buf, (const unsigned char *) "", 0));
    assert_string_equal("", buf);

    assert_int_equal(5, base64_encode(buf, (const unsigned char *) "\x01", 1));
    assert_string_equal("AQ==", buf);

    assert_int_equal(5, base64_encode(buf, (const unsigned char *) "\x01\x02", 2));
    assert_string_equal("AQI=", buf);

    assert_int_equal(5, base64_encode(buf, (const unsigned char *) "\x01\x02\xFF", 3));
    assert_string_equal("AQL/", buf);

    assert_int_equal(9, base64_encode(buf, (const unsigned char *) "\x01\x02\xFF\x80\x81\x7F", 6));
    assert_string_equal("AQL/gIF/", buf);

    assert_int_equal(13, base64_encode(buf, (const unsigned char *) "\x01\x02\xFF\x80\x81\x7F\x42", 7));
    assert_string_equal("AQL/gIF/Qg==", buf);
    assert_int_equal(13, base64_encode(buf, (const unsigned char *) "\x01\x02\xFF\x80\x81\x7F\x42\x42", 8));
    assert_string_equal("AQL/gIF/QkI=", buf);

    assert_int_equal(3, base64_decode((unsigned char *) buf, "AQL/"));
    assert_memory_equal("\x01\x02\xFF", buf, 3);

    assert_int_equal(8, base64_decode((unsigned char *) buf, "AQL/gIF/QkI="));
    assert_memory_equal("\x01\x02\xFF\x80\x81\x7F\x42\x42", buf, 8);
}

static void test_base58(void)
{
    char b58[128];
    uint8_t input[26];
    for (size_t i = 0; i != sizeof(input); ++i)
        input[i] = 'A' + i;

    const char * expected_b58[26] = { "",         "28",         "5y3",         "NvLz",         "2fkTDm",         "8N2njLQ",
                                      "ZVptqrdj", "3USEPpe57c", "Bv6N7jGdAAj", "qBLgChZxbTwe", "4fedr2e4UP7vBb", "HBb7dQEaKrdXjkN",
                                      0

    };

    for (size_t i = 0; i != 26; ++i)
    {
        const char * expected = expected_b58[i];
        if (expected == NULL)
            break;
        const size_t expected_len = XSTRLEN(expected);
        assert_int_equal(expected_len + 1, base58_b58enc(b58, input, i));
        assert_string_equal(expected, b58);
    }

    // Test special case handling for leading initial zero bytes

    const uint8_t zeros3[3] = { 0, 0, 1 };
    base58_b58enc(b58, zeros3, 3);
    assert_string_equal("112", b58);

    const uint8_t zeros4[4] = { 0, 0, 0, 1 };
    base58_b58enc(b58, zeros4, 4);
    assert_string_equal("1112", b58);
}

static void test_file_utils(void)
{
    char temp_file[128];
    XSTRCPY(temp_file, "/tmp/certifier_test.XXXXXXX");

    int fd = mkstemp(temp_file);

    assert_true(fd >= 0);

    assert_int_equal(false, util_file_exists("/tmp/moved_temp"));
    assert_int_equal(true, util_file_exists(temp_file));

    assert_int_equal(0, util_rename_file(temp_file, "/tmp/moved_temp"));
    // trying again fails (file no longer exists)
    assert_int_equal(-1, util_rename_file(temp_file, "/tmp/moved_temp.2"));

    assert_int_equal(false, util_file_exists(temp_file));
    assert_int_equal(true, util_file_exists("/tmp/moved_temp"));

    assert_int_equal(0, util_delete_file("/tmp/moved_temp"));
    assert_int_equal(-1, util_delete_file("/tmp/moved_temp"));
}

void test_sha256_ripemd_b58(void)
{

#define NUM_HASH_INPUTS 180

    const char * expected[NUM_HASH_INPUTS] = {
        "1NNxidgJSTbS4fQoQR4bGkTq6ESTG1LHp5", "1MDWiN3b143Sgb8mf3z6KmskYm7KNiUPAj", "1PebNTSBENJoWytXn2n1hLNSwXGfvHxMF3",
        "1KXtu7CCAia6n9R4FKz25znTRkYwS6Pkgn", "18aNVeSpNt5p6JLvbmSDaCFPNyJsGMGyLV", "1VRkqwoadtqckjbt3ZxDvBWJKY5hbcJTA",
        "1MS57Mr6JmYZVgDDkqmN5fo9h5opVJqwkB", "1JT7UouJv9ZuJ9biQhzBTiBqw7BSz1jvvE", "1JRPLSWBSxdkwVQB1nmGDdi1VUDSwfwUeC",
        "12UumSYbgWRaR7pAiSuY8tnipbraiaw9jM", "1QFR7k23n2bqZ3B4LXxdFukK3qPQz7Gy8",  "1GHyrLRpwgPWt2eLUownPsmQ4eBKyqrKLZ",
        "1hxGZxpRg9gaxNX22r4aKK4gnT3V1qU4U",  "1NQaLLB5q6vsgXL91Hzu9KDMBQRjzYuYQq", "1AX4U7XjWv14qVJwoNo5mcAtqxEuu2xz2u",
        "1HNs1GLTJ3rSnyMpPr6fVnJqfnqSFgwang", "1BS4CNv9LpgqvXFf5n9H4Gqrhg1JK1TFfT", "1AGA7qaiUQFNqts33Dpbm5MrBBBDKZydP9",
        "12GBEZ8qULCeHggNdQoJpv1obCSp7CAhDd", "1CJGJSKEx74i5b4SPmUNoiYw4DPy6DHLKc", "16irfNjkr8TF7ceZTXe1Ck9PPjATLec397",
        "1KSvZPPpVBzEuZiv8neFvDtX1iiZRUSnHt", "1BaSr6m6nhGQbavMjeEf5JPqo3W6LWBNq4", "14J9F492maajuUmTzwEJ9A5FPP4e9MV5LN",
        "1MiMQ3APWoRjRqdfYnr8t9TjmGuwiTWuPt", "1CKs5tkdZKxMGUKF8g89DM43Ti3JdGaNhv", "1GKcwi8RXDG4j398heiBC9qCo7q43j9Diu",
        "1FAphK3Ciw9D1jG9x8V8cHS915DfitPcki", "17qT5k5otv4bWxSCY7FxKu4fkN4XWYEtTy", "1EdmnqBdgp9CTUrjUC2SBs5VoxzzMqWUNQ",
        "1BSd1kHhmZczzaRpr318ZJVhSrjuu85Kdt", "16TdgaZ3f3QtyHfqaPvYsCCS1R5ydN39Xt", "1FB8DYJVbdbxXTXmmHpDikdgBv51m9ScRT",
        "1H9PxeGcqEvvPA8N2iLHgy49ohoCaHQAib", "1QDJ56zTMvLsxNCLwHsn8SRUdZjN4bLMfX", "16SYC9ZR165NmKwc47yN9MNR6AifvC39g6",
        "1GaaPDkvfHp1UvYEVt9DTQmCYPhEJCovkc", "1FhWDhyTDxnvp3SutEHGSFmbtNAzuxZcJQ", "1At4zr5MbBUsRdQVthp6G8DreCBzvq5nmN",
        "1T1kAwPjB9U9p3TPB4A9EwzvWKRNWZT4M",  "1Ljvp3Ktg3veSopthnidBuJNDkJ3trZoSn", "1LBnX6rvuDvwiuYHpDRjCXaFrrdcMW39wL",
        "1CdLr34cCHKNmm1KG5RQSwpYWo8kTymBY8", "17Jfstgu5zQi3vgYQXiPmGKFyTsvmmgR6r", "17HyGbFMuStcwMvfkeCHkN1S7QCv29Jwh1",
        "1A2K3tQG8PQqUov8hiCJ1RkTiLHJAvSAj7", "1PSVUMp8FHUpVtB8K9kee9MeEQqmVrAzVp", "1Pz658K2LWaSjE9JaXsTtweEvxtPmxRrdj",
        "1D8FttooS5diyxKyTJ25629nkSLQGQX9i",  "18n1fAKtHHLTsxcUFA6br5zYn57XpNnHso", "1CtjuEWywvbUb2tabfr3AdtVSa3U6J4mqe",
        "1NMsgHaZs9E5XGkCb2rKkwPyjG8fmUxBvb", "1Fbm4fFr2wyLdmh5wSD1SWswy7Po5otqjn", "17mfXydyYGafN86xALJwQPv8gvN8kUxDkK",
        "12RPb7j2t1hE8FaWD3mRHYx3feFXLD3fUe", "1BzFMHgGJuanAS7X2PeR8zF1kHRQHAz6gZ", "1HFkSXhetVhZG72yJVAQnBian3rCCAMSWU",
        "1Q2fscubUNZu41cfrLnkVeX1Wfm5PtRnrM", "16EVNRxSjXACbnEFvg4rcUQERf9VwUWtSi", "197RZmMrdzBYNJZPu5JiPNFKpKeBrDnSQs",
        "1Nx74yjrPKD1RdmGmbwnMr8gu6thr2m9x6", "13s5NtcbbE6CriankLTtcXKye8H54iwRC2", "1LuE28PcJq9qoMmDjqu2GVmhsMnadKe1Np",
        "1D7xZLY4vTsSPdNfgQc2kbFYfnSUYFwysf", "16d3jGNsgi3i5ayUME8sqvqspW6udVkXZL", "1F7pttLh7Vva75wAPL34bPjHsdWcgrw8hS",
        "1QH9VzTsx6tmQrC8sHWGVC9EsG3zfPKbHU", "147N3d3ti4AycfYicUXsCdvXekLLyqag7q", "1G9yt77yv2vwdFu327EteWLafuMQMSZVjz",
        "17WXGEEy2GpMZenkBLPPvhc8QKW9Xp53Dk", "1EZdrTgYRfBv7VPM1quF2jucDv8sRHu2zQ", "14i3YWQxxXfMnka4BguKWY35fwVgDKxmfv",
        "12ncBw48hmSsFVuepLJBNQqZzpmvgeVy1W", "1HJtrnSKCUfgyVzvjztYf58qLwZXRr73RF", "1Bx91ZQgALzrXYrToiEmZPymqKSGU2MTz6",
        "196tWdMES1H3AUsf1ZeMcrcvvEPedP31ho", "1GKqBxqVwvTpP8ePvmcCVxsKxGUB5WJg84", "1FHQscwArPnhqtGTu7xu5VNm9rxdV6726k",
        "1BWsAcBNeJSLCPHhvEb6sietuLKbqgRTCJ", "1KePeRWBg2ihp7vjD2jX1zbJTiWfzkgmqQ", "1KEaQKsmkxqURm4FWwLX8Lm2NLEPUVpWR6",
        "113Wcdz1diggFJWY3ZEZP3S599ShwGYPdN", "1K8nPGCMakMDz6H2sLyT55Rgjew5bByLmd", "19P5vU9XLMfamgTwdra3ajY6GMtM5QUtyL",
        "17GZVm1JsKgZrpBuGdmpGMZMRhL1SLjuR2", "1GyXYVVjiPFWi5ntNM9SXFZFmfMALDPy9u", "1DwbWX2wNRW5yK26g49Aw6xAWg2CYeEkpp",
        "1MdMTWrQ5vhGUhZ86nrwLoaTLJ7DLAVZUu", "1CZmoSMjGszFsqQXMCigHYHWgj1wnKhChM", "18KHuHTdKjxwvJATTCb3sf85VDpTiREKEb",
        "1LyyS6ePsnKDGRocEJJPFaY4xEotqJcoNY", "1Ceo2VBHYmys7uAuxHsNXvVjhiS5bg9w4a", "14GVpVBj9k7D4XLCW2XUjRHn78qX8T98tw",
        "1M7gmyZ1xW6DB2AA714odproLqSosAs23T", "16AvNztruvvTDXYczadyBT7kWXevVgfAxd", "12MR5vYEcQ3J91zoBkVv6D1EYWHYMDrzmz",
        "1NSBpkh4A3YmCp7QFdRC6issrt3Bb182up", "1CFHkuuGM1uyr1Q1ubMbGqT9qRtmbvDmfJ", "19S9cvRUPvMZ67jbS8gZcjP9QJoobspmhe",
        "13xCNsm91WWLqz6F9ExXb73zePa9GuPhro", "19Me7edibRDQScHAgcNbvFepqbRAJeGP2V", "1Er97Sr9cMB2yBhXHcoE6DtUvuZLYKkaSB",
        "12Vf8utam4jTNyuPkH8oapiwV2qw9RuGv7", "1EwAnjiYx6pZ62gMTEKdE5cGvRDAUEtuiK", "12HbRaVawMaSkhqJnB4QDvPGe4J7zJvDLC",
        "12vy5etzW8B79Aq78z8hEJ86Mnv487mJ1C", "13HccbUHQNztm5KzDexE6ScjnwEE6r8KPb", "19MNPB3FFUJe7J26thQgD68XeNnRiRxvtS",
        "1Dnjp9Hiuyot7fAuUsLeZhcFVFCoBD9DwF", "1MW7JgnWWvVAg72WxTS777bW7xwkJi1PSq", "1CaWB7EV2N3hZWnjtBrSMc138petK1QFeB",
        "114weTGvngQJUEpstWvCCHSpUdF5uDAbYX", "13LvQFzJgTdE17iKFKgsTEHvJx4FJoZ7U8", "16MaVG7CupRaaeHP1tusKUCgmZUQ6t1iYP",
        "151pJMU1jjXJhq9GsgvKWj5evnSF52b1Ym", "16uKVpFGqYBgKV1fJGyEvCDKBx6ZMybFe5", "16TmTuduiuEvP3Jh4KQ2C1GZevM6px3wM4",
        "19mENBAekPySaQjYYHDAFAVUaaBBDnvQRB", "13conUmJzkmuM32hmXKJaMtAJdmRiDVpb1", "1BFsmbv72E4YBGPhnMnqivTc64awMaxVMN",
        "1KyxfdDa1gaDf2DfwhS7rbgDA3j5Sr8C4k", "18B64b9tfRD1KuWvMfWZ9v8tzKQRfSuW9c", "18tMC1nFj79toYjCiuAYNfF9ko1yE96Xe9",
        "12tJrmqT3fbVk6JnFDiFTDwaxtWewHgCTC", "1Je3JbwAeyc3VN6ShCEKNeDepp64axFQU4", "1DYdFP8gW8DR1BCVz82Vpu7859W25e1ya6",
        "1CiVZ9BVvQprR7PT7UfDaCeyQbFaEkJdWa", "1FGJAfTwiAYf6xwvLZFqHuc9q4ZGJNCKaG", "1F27ab2bLrXm2RUhr3kXxpoUxW4LHqKDGd",
        "15vHDhTFVLJSFYKyB6DRXHbiTcrMLZbJA7", "1KwJ4gRTCrYYtSUn573C4Eh7bq7abEcJ72", "1DbJHbhwaX24rxHmjEYa1xfhu2H6yQcUoq",
        "14TojY6m1vsyEzoc9RJp1xPpwrcYYnm8Sk", "1Eg721dA6UwvvcLqs9ZA9fY5LCPd3eeC5r", "1Kgdhqz9TxSudTUkZnpS4V21iHx6XXi48q",
        "1vrdCHJV9KskPMdNY5j7SAnmeLTjAoyUD",  "1JyPxb6kndqwWRv8mvhUMEBxCY5tGR2G4f", "18WNuLPpBbjDfscsTtteDdzXxPBDd7it4f",
        "16sSnASZe4UypNoYDD3o9eBFW1tLGoW1Lw", "1AXXXdsUE7qJ7mQtQWr9m88w91ZbYWMs8W", "13rrQnztUYoVkurSqRBHojfSTc92oGdqzq",
        "17qAvXbGVzNtH2x2ycLPJQGD6yWaLWqPzb", "1hpvpRcFZUqoQXSY8JaAc4GS4far37rw1",  "1A7AHQdELEgzHNNEtqXGLEmh3GMkFYZi1Y",
        "1KTehrtxLZZpbWFp27BAum8rUgLhQbB8m9", "14Z3Egm37S1S3uhYRvUCMvvKpLrpYL68FB", "1NtUxH4DsWNkPEwJf7xKSAaTqq3bAsWJMy",
        "1BqbnCjbPpjQbgh1hKEprKAmjg7qsC3HQa", "1LEtn6jfT8ew1HfH7J2cLfLcXnSDgmm7S7", "1QA7ZqCk8HbVUtQ9he2xV83D2exKt3do3V",
        "1LXE8odvaZ4ZqSTpPvhQDxvF9z44fmeHyi", "1Po35zQSgCo1Rs48RFzvvSbETM1tkSwjEp", "143FNoU4qsrv3jfrdtjhX7FERH6Hgun9Sz",
        "1M7xHfZv5TryZb2rVfJdHfHfKHLWHY6BCm", "1BWvCdC6QXGyLPpHctedYe8wVCpjNvueDT", "18A4BhYsPcBv43et15Ptx2AxNtcqyhxdWt",
        "1GuT9Uv1zr8dYqJ8nG7b2TYxGcUn5ZKvHt", "1NrpZVdSbYBKjW698n57DNtCNpe91CjALJ", "1MrTjean1C3xJEjne4KrjSFNp61vf2j9LT",
        "1L7k1LBq916ymyyDPkVrVJXr4zzwNL8fho", "15MwXzF2zom7ZZGXbkUWHXuF9bZbrwEJ1x", "1EcxWgDMUgHWyXnsmjKMgMU3uMMfWXfJLX",
        "1HEE5R1hrsuA7yTBNMHYXR7ncPv1eV4AFR", "1KW3JNFiBcYdukqHHztaCi1TRXLaE7gamh", "1G9s9uBDKWNR5qRAzaBcVg9hb6XjGAqsKA",
        "1A3oCchBBGJPu1LTw9gcm6wUGYsY9Wezxh", "17ExKmtdgAtXycF7DDC1sBaUrSxRJT7muM", "1HqSR3XCEp8sfQnKnQJqLAGFSv2qzqn6QD",
        "1QA29Jx814qeY1oWMkPLbvUrdUTLjosfZk", "1GoQ9VZCnbFAoYGGi5u2cmy1CwkaeufB93", "1DF2JETtY6RMq17zSRA4qcvzXDdVWEu7UX",
        "1EfU5rsdqJvoEDN3zNAXs94t5nwwrvf2tR", "1DS8xLpuq1VX745ppgvZ9tKgwD6c23ogbi", "17Uez8UyYH4VvUnhoUJq6MekNGr5ppFVtH",
        "1Fd5Euh4omyEvsfC92ruAud4D1HSsF2SAS", "1MbbGw9tRoLF8LhFHUhUnWKS2kLeJTMGUv", "1As3eegWVHSa33NjqhsmZ597JA5d9Te2Kp",
        "1q5foM2R1zuxxPA7srTFWjg46ams3sCot",  "1PYStn9NSS7fvFWGrPcifvV4BdFdjBjpwu", "1BXKDkH2sGey4yC5YeY5KPnSwdYprH6bY2"
    };

    for (size_t i = 1; i != NUM_HASH_INPUTS; ++i)
    {
        uint8_t input[256];
        for (size_t j = 0; j != sizeof(input); ++j)
            input[j] = j;

        const char * expected_hash = expected[i];

        int rc        = 0;
        char * result = security_encode(input, i, &rc);
        assert_string_equal(expected_hash, result);
        // XFPRINTF(stderr, "%d %s %s\n", strcmp(result, expected_hash) == 0, result, expected_hash);
        XFREE(result);
    }
}

static void test_set_curl_error(void)
{
    char errbuf[1024] = { "some error" };
    int res           = 0;
    int http_code     = 500;
    char * err        = util_format_curl_error("test_set_curl_error", http_code, res, errbuf, "test payload", __FILE__, __LINE__);
    assert_non_null(err);
    XFREE(err);
}

static void test_str_utils(void)
{
    char str[128] = { 0 };

    // for testing split
    char buf[1024];
    size_t argc;
    char * argv[20];

    assert_true(util_starts_with("https://www.google.com", "https://"));
    assert_false(util_starts_with("https://www.google.com", "http://"));

    XSTRCPY(str, "ABABABCAB");
    util_trim(str);
    assert_string_equal("ABABABCAB", str);

    XSTRCPY(str, "\nABABABCAB\n");
    util_trim(str);
    assert_string_equal("ABABABCAB", str);

    XSTRCPY(str, "ABABABCAB\n");
    util_trim(str);
    assert_string_equal("ABABABCAB", str);

    XSTRCPY(str, "   ABABABCAB\n");
    util_trim(str);
    assert_string_equal("ABABABCAB", str);

    XSTRCPY(str, "   ABABABCAB   \n");
    util_trim(str);
    assert_string_equal("ABABABCAB", str);

    XSTRCPY(str, "\r\nABABABCAB\r\n");
    util_trim(str);
    assert_string_equal("ABABABCAB", str);

    XSTRCPY(buf, "'some text in quotes' plus four simple words p'lus something strange'");
    argc = util_split(buf, argv, 20, ' ');

    assert_string_equal("some text in quotes", argv[0]);
    assert_string_equal("plus", argv[1]);
    assert_string_equal("four", argv[2]);
    assert_string_equal("simple", argv[3]);
    assert_string_equal("words", argv[4]);
    assert_string_equal("p'lus", argv[5]);
    assert_string_equal("something", argv[6]);
    assert_string_equal("strange'", argv[7]);

    assert_int_equal(8, argc);

    char * line0 = "";
    char * line1 = "ads";
    char * line2 = "\tds";
    char * line3 = "\tds\r";
    char * line4 = "\t\v\n";

    assert_true(util_is_empty(line0));
    assert_false(util_is_empty(line1));
    assert_false(util_is_empty(line2));
    assert_false(util_is_empty(line3));
    assert_true(util_is_empty(line4));
}

static void test_random_val(void)
{

    char * str = util_generate_random_value(5, "");
    assert_null(str);
    XFREE(str);

    str = util_generate_random_value(4, "A");
    assert_string_equal("AAAA", str);
    XFREE(str);

    str = util_generate_random_value(5, "B");
    assert_string_equal("BBBBB", str);
    XFREE(str);

    str = util_generate_random_value(128, "AB");
    assert_int_equal(128, XSTRLEN(str));
    size_t a_cnt = 0, b_cnt = 0;
    for (size_t i = 0; i != 128; ++i)
    {
        assert_true(str[i] == 'A' || str[i] == 'B');

        a_cnt += (str[i] == 'A');
        b_cnt += (str[i] == 'B');
    }
    XFREE(str);

    // rough test that at least some As and Bs are both in the output
    assert_true(a_cnt > 32);
    assert_true(b_cnt > 32);
}

static void test_ecc_key(void)
{

    // verify free(NULL) is ok
    security_free_eckey(NULL);

    unsigned char * der_key = NULL;
    int der_key_len         = 0;

    // create a key...

    ECC_KEY * key = security_create_new_ec_key(_certifier_get_properties(certifier), "prime256v1");
    assert_non_null(key);

    ECC_KEY * dup_key = security_dup_eckey(key);
    assert_non_null(dup_key); // add additional assertions

    const uint8_t msg[3] = { 'm', 's', 'g' };

    uint8_t digest[32];

    assert_int_equal(0, security_sha256(digest, msg, 3));

    char * signature = security_sign_hash_b64(key, digest, sizeof(digest));
    assert_non_null(signature);

    CertifierError result = security_verify_signature(key, signature, msg, 3);

    assert_int_equal(0, result.application_error_code);
    error_clear(&result);

    result = security_verify_signature(key, signature, msg, 2);
    // invalid signature (truncated message)
    assert_int_not_equal(0, result.application_error_code);
    error_clear(&result);

    // corrupt signature
    signature[5] = 'A';
    signature[6] = 'B';
    signature[7] = 'C';

    result = security_verify_signature(key, signature, msg, 3);
    assert_true(result.application_error_code > 1);
    error_clear(&result);
    XFREE(signature);

    der_key_len = security_serialize_der_public_key(key, &der_key);

    assert_true(der_key_len > 64);

    // this test is used to generate a dummy key and put public key in it
    ECC_KEY * deserialized_ecc_key = security_get_key_from_der(der_key, der_key_len);
    assert_non_null(deserialized_ecc_key);
    signature = security_sign_hash_b64(key, digest, sizeof(digest));
    assert_non_null(signature);
    result = security_verify_signature(deserialized_ecc_key, signature, msg, 3);
    assert_int_equal(0, result.application_error_code);
    error_clear(&result);
    XFREE(signature);
    XFREE(der_key);
    der_key = NULL;
    security_free_eckey(deserialized_ecc_key);

    // The first portion of the CSR is always fixed, assuming P-256 is used
    const char * csr_prefix = "MIG6MGICAQAwADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI9W9+"
                              "JP3W2tPrmawZnCmEqIcnTQc0UXzgagX6h4ghztGPpFjY1vaahDuyeH2E80U0JPa4kpHutMWcmuLhCdj6KgADAKBggqhkjOPQQDAg"
                              "NIADBFAiEA0YsUpntlvek0i2GpWKsfHJu37eY5mOcF2EcQitBoc+";

    int csr_len = 0;
    char * csr  = security_generate_certificate_signing_request(key, &csr_len);

    // The length will vary slightly due to integer encoding rules
    assert_in_range(csr_len, 10, 256);
    assert_true(XSTRNCMP(csr, csr_prefix, XSTRLEN(csr_prefix)));
    security_free_eckey(key);
    security_free_eckey(dup_key);

    XFREE(csr);
}

static void test_verify_signature_1(void)
{

    const char * pub_key_b64   = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPGYYPEBOW/v/Kori+9rkwyDLijQ+OyOcXWN/"
                                 "qxWSpTjOlpJH6QJ90UkgNfKMqOSV0p+cP6ww6dIiTZqbEIGR1Q==";
    const char * signature_b64 = "MEUCIA2DeJ8DeKNU0y9qAUgAUsltgbyClfUk208jkWFpz1Y7AiEAwmamTey1xtggzWwNr1VLlEhaSK3TrAWAzEsWvFlGYlc=";
    const char * test_input    = "TestInput";

    unsigned char pub_key_der[8192];
    int pub_key_der_len = -1;

    pub_key_der_len = base64_decode(pub_key_der, pub_key_b64);

    ECC_KEY * deserialized_ecc_key = security_get_key_from_der(pub_key_der, pub_key_der_len);
    assert_non_null(deserialized_ecc_key);
    assert_int_equal(
        0,
        security_verify_signature(deserialized_ecc_key, signature_b64, (unsigned char *) test_input, XSTRLEN(test_input))
            .application_error_code);

    security_free_eckey(deserialized_ecc_key);
}

static void test_verify_signature_2(void)
{

    int i = 0;
    for (i = 0; i < 5; i++)
    {
        int size_to_malloc   = 0;
        unsigned char * hash = NULL;

        unsigned char input_public_key_der[8192];

        const char * input_node = "15fc6H7RwSxZnopwHqZK2KSWM8PXqYUXMk";
        size_to_malloc += XSTRLEN(input_node);

        const char * input_public_key_b64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4xdpepHBjc5m6J7xUVn/gd2tyWbFTIg2g/"
                                            "A1+2Gt7f8dgtFe36HDH7OBSHHuR9k2WEqSzuWMP9TKNTBpjFDb6A==";
        int der_public_key_len            = base64_decode(input_public_key_der, input_public_key_b64);
        size_to_malloc += der_public_key_len;

        const char * input_signature =
            "MEUCIQCb2B91miRsgdhcz3KvPTo2Mhkl+D9ntHYofluZUoxqGgIgf8QIMLduO//9OtoN96B0OYoiwVkF5N3d2zb2i1pFUow=";

        const char * action = "allow";
        size_to_malloc += XSTRLEN(action);

        const char * transaction_id = "P1UjdAuW3eEQID2z";
        size_to_malloc += XSTRLEN(transaction_id);

        const char * timestamp_msec_str = "1523662100167";
        size_to_malloc += XSTRLEN(timestamp_msec_str);

        const char * not_before_str = "0";
        size_to_malloc += XSTRLEN(not_before_str);

        const char * exp_str = "0";
        size_to_malloc += XSTRLEN(exp_str);

        const char * target_node = "15fc6H7RwSxZnopwHqZK2KSWM8PXqYUXMk";
        size_to_malloc += XSTRLEN(target_node);

        const char * output_node_address = "12BgUXBWrpyPum74FuLn9HbMVoiCuQHZSn";
        size_to_malloc += XSTRLEN(output_node_address);

        int len       = 0;
        int total_len = 0;

        hash = XMALLOC(size_to_malloc + 1);
        assert_non_null(hash);

        len = XSTRLEN(input_node);
        XMEMCPY(hash, input_node, len);
        total_len += len;

        XMEMCPY(hash + total_len, input_public_key_der, der_public_key_len);
        total_len += der_public_key_len;

        len = XSTRLEN(action);
        XMEMCPY(hash + total_len, action, len);
        total_len += len;

        len = XSTRLEN(transaction_id);
        XMEMCPY(hash + total_len, transaction_id, len);
        total_len += len;

        len = XSTRLEN(timestamp_msec_str);
        XMEMCPY(hash + total_len, timestamp_msec_str, len);
        total_len += len;

        len = XSTRLEN(not_before_str);
        XMEMCPY(hash + total_len, not_before_str, len);
        total_len += len;

        len = XSTRLEN(exp_str);
        XMEMCPY(hash + total_len, exp_str, len);
        total_len += len;

        len = XSTRLEN(target_node);
        XMEMCPY(hash + total_len, target_node, len);
        total_len += len;

        len = XSTRLEN(output_node_address);
        XMEMCPY(hash + total_len, output_node_address, len);
        total_len += len;

        ECC_KEY * ecc_key = security_get_key_from_der(input_public_key_der, der_public_key_len);
        assert_non_null(ecc_key);

        CertifierError result = security_verify_signature(ecc_key, input_signature, hash, total_len);
        assert_int_equal(0, result.application_error_code);
        error_clear(&result);

        // test corrupt hash
        result = security_verify_signature(ecc_key, input_signature, (const unsigned char *) "1", 1);
        assert_true(result.application_error_code >= 2000);
        error_clear(&result);

        // test corrupt signature
        result = security_verify_signature(ecc_key, "1", hash, total_len);
        assert_true(result.application_error_code >= 2000);
        error_clear(&result);

        security_free_eckey(ecc_key);

        XFREE(hash);
    }
}

void test_x509_cert(void)
{

    const char * digicert_pem_pkcs7_blob = "-----BEGIN PKCS7-----\n"
                                           "MIIL2gYJKoZIhvcNAQcCoIILyzCCC8cCAQExADALBgkqhkiG9w0BBwGggguvMIID\n"
                                           "/DCCA4KgAwIBAgIQDrhzYQFt1jtdlPdlPBrABzAKBggqhkjOPQQDAjBVMQwwCgYD\n"
                                           "VQQGEwNVU0ExFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMSwwKgYDVQQDEyNEaWdp\n"
                                           "Q2VydCBUZXN0IEVDQyBJbnRlcm1lZGlhdGUgQ0EtMTAeFw0xNzEyMDgwMDAwMDBa\n"
                                           "Fw0xODEyMDgxMjAwMDBaMIGxMQswCQYDVQQGEwJVUzELMAkGA1UECBMCUEExFTAT\n"
                                           "BgNVBAcTDFBoaWxhZGVscGhpYTEQMA4GA1UEChMHQ29tY2FzdDErMCkGA1UECxMi\n"
                                           "MTIyVEVyMzVtd3NyR2tNeU1VVkJXWUMxTGZZMW9wZXd6aDE/MD0GA1UEAxM2MU1T\n"
                                           "ZmNCMmNxQW9xb0FCRFhjenVvVW5DMXNGanR6dXN6OC5wb2MueGZpbml0eWhvbWUu\n"
                                           "Y29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqFNpbfexnR+rykdzJIYmGedz\n"
                                           "CR95aSk8DCPe9Bi9DrYnoJn6zTSPpu6y14TBOVqux6LQX/0xJSbmcnbf5i3fYKOC\n"
                                           "AdUwggHRMB8GA1UdIwQYMBaAFMJU8eN8uR7zak5mEuzfDRwpCKE5MB0GA1UdDgQW\n"
                                           "BBTzdQIVPrKf7UEkDLGslzQCkArVQDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQE\n"
                                           "AwIFoDATBgNVHSUEDDAKBggrBgEFBQcDAjBCBgNVHSAEOzA5MDcGCWCGSAGG/WwG\n"
                                           "ATAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMIGT\n"
                                           "BgNVHR8EgYswgYgwQqBAoD6GPGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdp\n"
                                           "Q2VydFRlc3RFQ0NJbnRlcm1lZGlhdGVDQS0xLmNybDBCoECgPoY8aHR0cDovL2Ny\n"
                                           "bDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VGVzdEVDQ0ludGVybWVkaWF0ZUNBLTEu\n"
                                           "Y3JsMIGBBggrBgEFBQcBAQR1MHMwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRp\n"
                                           "Z2ljZXJ0LmNvbTBLBggrBgEFBQcwAoY/aHR0cDovL2NhY2VydHMuZGlnaWNlcnQu\n"
                                           "Y29tL0RpZ2lDZXJ0VGVzdEVDQ0ludGVybWVkaWF0ZUNBLTEuY3J0MAoGCCqGSM49\n"
                                           "BAMCA2gAMGUCMEMJOMtq86qwZAM1fuhR3EVOEWVpSIjsC0APeMzGwb92h38n+FnJ\n"
                                           "dVtXK8NrxccF/AIxAJjIqjpF9MMUuXfNR4HSmAn+kiuBSnQ2wIlqx7myO5LKSZKT\n"
                                           "crLMoP5WBDzu4OdXXTCCBAswggLzoAMCAQICEA8+pFzDPZ22y2oEoPby8NkwDQYJ\n"
                                           "KoZIhvcNAQEMBQAwXzELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IElu\n"
                                           "YzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEeMBwGA1UEAxMVRGlnaUNlcnQg\n"
                                           "VGVzdCBSb290IENBMB4XDTE2MDcxMTEyMDQxNVoXDTI2MDcxMTEyMDQxNVowVTEM\n"
                                           "MAoGA1UEBhMDVVNBMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjEsMCoGA1UEAxMj\n"
                                           "RGlnaUNlcnQgVGVzdCBFQ0MgSW50ZXJtZWRpYXRlIENBLTEwdjAQBgcqhkjOPQIB\n"
                                           "BgUrgQQAIgNiAASOYwoRXqFwb+s+dY5Om5jRGWjZh7eri7VCMBvrC7sfkToyNqoG\n"
                                           "1y8sFnXg+iZQEWs/cz6ZVX0yW97O9y+1VAnATMNrW/1Rnw/8md9W6orrjSasRGyb\n"
                                           "XWd6cFIGAVioMOSjggF5MIIBdTAdBgNVHQ4EFgQUwlTx43y5HvNqTmYS7N8NHCkI\n"
                                           "oTkwHwYDVR0jBBgwFoAURrByCPw15fr6/53eURBuYpVd17AwEgYDVR0TAQH/BAgw\n"
                                           "BgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsG\n"
                                           "AQUFBwMCMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0cDovL29jc3Au\n"
                                           "ZGlnaWNlcnQuY29tMHsGA1UdHwR0MHIwN6A1oDOGMWh0dHA6Ly9jcmwzLmRpZ2lj\n"
                                           "ZXJ0LmNvbS9EaWdpQ2VydFRlc3RSb290Q0FHMi5jcmwwN6A1oDOGMWh0dHA6Ly9j\n"
                                           "cmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRlc3RSb290Q0FHMi5jcmwwPQYDVR0g\n"
                                           "BDYwNDAyBgRVHSAAMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRpZ2ljZXJ0\n"
                                           "LmNvbS9DUFMwDQYJKoZIhvcNAQEMBQADggEBADusW2iI7iPl8KK3u2whL35lg/FC\n"
                                           "fm8CY0iuZsAwBCjl2Jyu6zaSt57i8StSOIKlLKQS12ceCPVmkkNdqOfh9sg3Ptgv\n"
                                           "pJcYQGTbSuxgLU6clzI6/VZ3SrsbpxH6Ipf4aTfCQNCk5ljZ5ZY8ZKulGoQ8k4DM\n"
                                           "SDnB1KxRHD+8mrV3jCBxwsxIC9rFXtsLDKLI448rrYmwPNv42SAPwl8gv1XTv3tK\n"
                                           "a0xIBBC7Y0s0OvKYpBqpzVI+m5y/wBjvlKVaj1guGcLjWF/XN9LpiLc71gw0VTWj\n"
                                           "V+FQh7EUDI/XrV6CNZEHczf9kz3yQlDJNssrK0gg6HtxGzK+tkJszoUEOoMwggOc\n"
                                           "MIIChKADAgECAgERMA0GCSqGSIb3DQEBBQUAMF8xCzAJBgNVBAYTAlVTMRUwEwYD\n"
                                           "VQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xHjAc\n"
                                           "BgNVBAMTFURpZ2lDZXJ0IFRlc3QgUm9vdCBDQTAeFw0wNjExMTAwMDAwMDBaFw0z\n"
                                           "MTExMTAwMDAwMDBaMF8xCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJ\n"
                                           "bmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xHjAcBgNVBAMTFURpZ2lDZXJ0\n"
                                           "IFRlc3QgUm9vdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALaY\n"
                                           "QS/U2JVZvXHsaVFXCZbu0BRCGyVOv7kjPy0etSrWXX7usDGOQvOi+Jt6yv6ite4v\n"
                                           "77OWkEBArEg5DVP0rDyb44oO0CNGIyE/gzHo7ZCl7g3c+tqzakI8ZOhesp//ryU+\n"
                                           "a3nYWep3whKhoGHT6L5JRYzZo2bp74kWrohD+ITZys5cEdpGm/j8g4wJ+tPrMBoW\n"
                                           "eyZahSMZzohKpvafCxgww4Jm0fnvKBzngZwinu3qaYndL8zJ7C2SST4AauaFECCL\n"
                                           "z94Tp5T76NCgatnxR+BhlqFNJmQkdm1GP6b2xJSwxfYvDhTGTaBRSR00e+g53N36\n"
                                           "wEuaLDnPq8j13Rhh/AECAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB\n"
                                           "/wQFMAMBAf8wHQYDVR0OBBYEFEawcgj8NeX6+v+d3lEQbmKVXdewMB8GA1UdIwQY\n"
                                           "MBaAFEawcgj8NeX6+v+d3lEQbmKVXdewMA0GCSqGSIb3DQEBBQUAA4IBAQBZzKkb\n"
                                           "dQ6SQXD4US1CZdAPE8FaZLforBDribIleepx3jVmyRiPIITraJd3ap9A5DRqhORt\n"
                                           "wijc6/tFf0zn6beSnNmaUcfB5/R493mnV21WyadHbZNd2anLE8M4u1jPvB3cNMbY\n"
                                           "bl9Q3b92B5MryYhOid62tU6SlXHxa0mQwaBU3kOHLqBVjDRek1/B7I81pyq7QHCt\n"
                                           "6UufmpMFcJjCDshYU/YJrfheva0txDXvMT49fnVOicDtF0Hh45nYkTpwmn3kPR3J\n"
                                           "j9GNC9Cmfx3tmNJoerQfMEzBxeRUxygqOE6mbCgnP+wnOW3tYWmN37HI0SsKFb+1\n"
                                           "07Ev6/LQcGzs1jORMQA=\n"
                                           "-----END PKCS7-----\n";

    const char * ejbca_with_hsm_pem_cert_only_blob = "-----BEGIN CERTIFICATE-----\n"
                                                     "MIICrzCCAlagAwIBAgIUFyT+PQAA6a69yqnwjvXz/7Pyp6wwCgYIKoZIzj0EAwIw\n"
                                                     "LTErMCkGA1UEAwwiWGZpbml0eSBTdWJzY3JpYmVyIElzc3VpbmcgRUNDIElDQTAe\n"
                                                     "Fw0yMDAzMjEwMDEyMTBaFw0yMTAzMjEwMjEyMTBaMIHOMRUwEwYDVQQHDAxQaGls\n"
                                                     "YWRlbHBoaWExCzAJBgNVBAgMAlBBMQswCQYDVQQGEwJVUzE7MDkGA1UEAwwyMTVh\n"
                                                     "cmVlVnRVY0VOVXRuZVdqV1JmUzFzOEh2cVVKWlI3Ui54ZmluaXR5aG9tZS5jb20x\n"
                                                     "KzApBgNVBAsMIjFHb3RaVWt6NkJSc1JRTDRyQVdWVHZnNHVnWkQ1UGVuSEUxEDAO\n"
                                                     "BgNVBAoMB0NvbWNhc3QxHzAdBgoJkiaJk/IsZAEBDA9kdW1teV9zYW5fZmllbGQw\n"
                                                     "WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATgtJgWH1w19GiD9O++XvrVdHfh5igx\n"
                                                     "/UxXSnc9C4Ilxw8oFRjLMA80oObFg10MklbKTZKZYyqSEFBNutCsS1UQo4GxMIGu\n"
                                                     "MAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAU19TMeHNZg7oMU074qyszSbjb/AYw\n"
                                                     "LwYIKwYBBQUHAQEEIzAhMB8GCCsGAQUFBzABhhNodHRwOi8vb2NzcC54cGtpLmlv\n"
                                                     "MB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAdBgNVHQ4EFgQUZ3RQh45A\n"
                                                     "/gE5vHX6Y8cFMwuqIGcwDgYDVR0PAQH/BAQDAgKkMAoGCCqGSM49BAMCA0cAMEQC\n"
                                                     "IA4YxVhgdUDga1uk1M5TbGWiRPlsBKzqW8piX1B0BWLCAiANFRaadyMZhFh4m9jK\n"
                                                     "ePHDgMD6rthte8kvu7bpWStlPg==\n"
                                                     "-----END CERTIFICATE-----";

    const char * ejbca_with_hsm_pem_pkcs7_blob = "-----BEGIN PKCS7-----\n"
                                                 "MIAGCSqGSIb3DQEHAqCAMIACAQExDzANBglghkgBZQMEAgEFADCABgkqhkiG9w0B\n"
                                                 "BwGggCSAAAAAAAAAoIAwggKxMIICVqADAgECAhR+vxrLZ6FBXktXzbA8Pgqw6qZa\n"
                                                 "YDAKBggqhkjOPQQDAjAtMSswKQYDVQQDDCJYZmluaXR5IFN1YnNjcmliZXIgSXNz\n"
                                                 "dWluZyBFQ0MgSUNBMB4XDTIwMDMxNDE2NTgyM1oXDTIxMDMxNDE4NTgyM1owgc4x\n"
                                                 "FTATBgNVBAcMDFBoaWxhZGVscGhpYTELMAkGA1UECAwCUEExCzAJBgNVBAYTAlVT\n"
                                                 "MTswOQYDVQQDDDIxNDVEeGNhZXdwNzZqR3RiZGNkc1ppVkFHN3BLRjllNFc4Lnhm\n"
                                                 "aW5pdHlob21lLmNvbTErMCkGA1UECwwiMUdvdFpVa3o2QlJzUlFMNHJBV1ZUdmc0\n"
                                                 "dWdaRDVQZW5IRTEQMA4GA1UECgwHQ29tY2FzdDEfMB0GCgmSJomT8ixkAQEMD2R1\n"
                                                 "bW15X3Nhbl9maWVsZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABO30ViP5F+Md\n"
                                                 "dUdvRquHekNL7lpruaAIF2K+Xwejz7/WAbAOcoXZ65v9+zP0IWi0c7oGrOh1xHbs\n"
                                                 "dYDlt1N+Uu+jgbEwga4wDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBTX1Mx4c1mD\n"
                                                 "ugxTTvirKzNJuNv8BjAvBggrBgEFBQcBAQQjMCEwHwYIKwYBBQUHMAGGE2h0dHA6\n"
                                                 "Ly9vY3NwLnhwa2kuaW8wHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMB0G\n"
                                                 "A1UdDgQWBBSnVl0zVboVin/o4zT7wsM5+uEdoDAOBgNVHQ8BAf8EBAMCAqQwCgYI\n"
                                                 "KoZIzj0EAwIDSQAwRgIhAJl9IO5gtR/mcu0EHVmIUNyF9iqLxlBM3v76KK3QcfQX\n"
                                                 "AiEAkyDNpa+4hYmvjOlKcD8AOOQS7piFcyfEY3i4RGuyB6gwggG6MIIBYaADAgEC\n"
                                                 "AhQMWxKFiZprelJJ8aMfQOqieG4WhjAKBggqhkjOPQQDAjAmMSQwIgYDVQQDDBtY\n"
                                                 "ZmluaXR5IFN1YnNjcmliZXIgRUNDIFJvb3QwHhcNMTkxMDA3MTgzOTEyWhcNNDQw\n"
                                                 "OTMwMTgzMjA4WjAtMSswKQYDVQQDDCJYZmluaXR5IFN1YnNjcmliZXIgSXNzdWlu\n"
                                                 "ZyBFQ0MgSUNBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcywXAZ1XCDx1BxAr\n"
                                                 "+pbhtc+QmzegKTh6Hy/mqXP4hkEsgzBJeDgG8DWFIc6JDi0Q3JqW3uckBo2iPF+H\n"
                                                 "RnVIraNmMGQwEgYDVR0TAQH/BAgwBgEB/wIBADAfBgNVHSMEGDAWgBSVn8KUP9J2\n"
                                                 "ueLExe2EjezHdq/fpzAdBgNVHQ4EFgQU19TMeHNZg7oMU074qyszSbjb/AYwDgYD\n"
                                                 "VR0PAQH/BAQDAgGGMAoGCCqGSM49BAMCA0cAMEQCIAK7icIBza/Y4AQKeWnqBdw9\n"
                                                 "i4wLyV+UOH1d4ToYz1wOAiB4d18vRrcuwpYKqzpeJTRV+BYwwcTtYxhQT+7xzdU5\n"
                                                 "tTCCAbQwggFaoAMCAQICFGLz2Y458hBA3pPMlmKDNhjCIJzFMAoGCCqGSM49BAMC\n"
                                                 "MCYxJDAiBgNVBAMMG1hmaW5pdHkgU3Vic2NyaWJlciBFQ0MgUm9vdDAeFw0xOTEw\n"
                                                 "MDcxODMyMDhaFw00NDA5MzAxODMyMDhaMCYxJDAiBgNVBAMMG1hmaW5pdHkgU3Vi\n"
                                                 "c2NyaWJlciBFQ0MgUm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGbk87y6\n"
                                                 "zvuxtvmJa+DtjxzIm1atalSTMyr0LSfCQHtQy9B5CV0Z5Ylk9UAuYqibmgODYId9\n"
                                                 "U49k9bTiXGK+gd+jZjBkMBIGA1UdEwEB/wQIMAYBAf8CAQEwHwYDVR0jBBgwFoAU\n"
                                                 "lZ/ClD/SdrnixMXthI3sx3av36cwHQYDVR0OBBYEFJWfwpQ/0na54sTF7YSN7Md2\n"
                                                 "r9+nMA4GA1UdDwEB/wQEAwIBhjAKBggqhkjOPQQDAgNIADBFAiAqTgVrulFoBCIo\n"
                                                 "B9+Q3mHjcgGR7Bkb+v3pwb25kFMxhQIhAIEeA4bq9Z0DtTUg8JB0HlLM9x1eQIaY\n"
                                                 "J+Xh5IcgJ9ktAAAxggEBMIH+AgEBMD4wJjEkMCIGA1UEAwwbWGZpbml0eSBTdWJz\n"
                                                 "Y3JpYmVyIEVDQyBSb290AhQMWxKFiZprelJJ8aMfQOqieG4WhjANBglghkgBZQME\n"
                                                 "AgEFAKCBmDAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEP\n"
                                                 "Fw0yMDAzMTQxODU4MjNaMC0GCSqGSIb3DQEJNDEgMB4wDQYJYIZIAWUDBAIBBQCh\n"
                                                 "DQYJKoZIhvcNAQELBQAwLwYJKoZIhvcNAQkEMSIEIOOwxEKY/BwUmvv0yJlvuSQn\n"
                                                 "rkHkZJuTTKSVmRt4UrhVMA0GCSqGSIb3DQEBCwUABAAAAAAAAAA=\n"
                                                 "-----END PKCS7-----";

    // XFPRINTF(stderr, "%s", digicert_pem_pkcs7_blob);
    const time_t ref_time = 1512754662;
    X509_LIST * cert_list = NULL;
    X509_CERT * cert1     = NULL;
    X509_CERT * cert1_dup = NULL;
    X509_CERT * cert2     = NULL;
    X509_CERT * cert3     = NULL;
    X509_CERT * cert4     = NULL;
    char * cert1_ou       = NULL;
    char * cert2_ou       = NULL;
    char * cert3_ou       = NULL;

    // try cert only format
    CertifierError rc = security_load_certs_from_pem(ejbca_with_hsm_pem_cert_only_blob, &cert_list, false);
    assert_int_equal(0, rc.application_error_code);
    assert_non_null(cert_list);
    cert1 = security_cert_list_get(cert_list, 0);
    assert_non_null(cert1);
    cert1_ou = security_get_field_from_cert(cert1, "organizationalUnitName");
    assert_string_equal(cert1_ou, "1GotZUkz6BRsRQL4rAWVTvg4ugZD5PenHE");
    XFREE(cert1_ou);
    security_free_cert_list(cert_list);
    cert_list = NULL;

    // try ejbca pkcs7 format
    rc = security_load_certs_from_pem(ejbca_with_hsm_pem_pkcs7_blob, &cert_list, false);
    assert_int_equal(0, rc.application_error_code);
    assert_non_null(cert_list);
    cert1 = security_cert_list_get(cert_list, 0);
    assert_non_null(cert1);
    cert1_ou = security_get_field_from_cert(cert1, "organizationalUnitName");
    assert_string_equal(cert1_ou, "1GotZUkz6BRsRQL4rAWVTvg4ugZD5PenHE");
    XFREE(cert1_ou);
    security_free_cert_list(cert_list);
    cert_list = NULL;

    // try digicert pkcs7 format (original tests)
    rc = security_load_certs_from_pem(digicert_pem_pkcs7_blob, &cert_list, false);
    assert_int_equal(0, rc.application_error_code);
    assert_non_null(cert_list);

    cert1 = security_cert_list_get(cert_list, 0);
    assert_non_null(cert1);
    cert2 = security_cert_list_get(cert_list, 1);
    assert_non_null(cert2);
    cert3 = security_cert_list_get(cert_list, 2);
    assert_non_null(cert3);
    cert4 = security_cert_list_get(cert_list, 3);
    assert_null(cert4);

    assert_null(security_cert_list_get(NULL, 5));

    cert1_ou = security_get_field_from_cert(cert1, "organizationalUnitName");
    assert_string_equal(cert1_ou, "122TEr35mwsrGkMyMUVBWYC1LfY1opewzh");

    cert2_ou = security_get_field_from_cert(cert2, "organizationalUnitName");
    assert_null(cert2_ou);
    cert3_ou = security_get_field_from_cert(cert3, "organizationalUnitName");
    assert_string_equal(cert3_ou, "www.digicert.com");

    XFREE(cert1_ou);
    XFREE(cert2_ou);
    XFREE(cert3_ou);

    CertifierError result = security_check_x509_valid_range(ref_time, 0, cert1, NULL, NULL);
    assert_int_equal(0, result.application_error_code);
    error_clear(&result);

    result = security_check_x509_valid_range(ref_time, 2147483643, cert1, NULL, NULL);
    assert_int_not_equal(0, result.application_error_code);
    error_clear(&result);

    result = security_check_x509_valid_range(5000, 0, cert1, NULL, NULL);
    assert_int_not_equal(0, result.application_error_code);
    error_clear(&result);

    result = security_check_x509_valid_range(ref_time, 0, cert2, NULL, NULL);
    assert_int_equal(0, result.application_error_code);
    error_clear(&result);

    result = security_check_x509_valid_range(ref_time, 0, cert3, NULL, NULL);
    assert_int_equal(0, result.application_error_code);
    error_clear(&result);

    result = security_check_x509_valid_range(1000, 0, cert1, NULL, NULL);
    assert_int_not_equal(0, result.application_error_code);
    error_clear(&result);

    result = security_check_x509_valid_range(2147483647, 0, cert1, NULL, NULL);
    assert_int_not_equal(0, result.application_error_code);
    error_clear(&result);

    result = security_check_x509_valid_range(1000, 0, cert1, "Not a Time", NULL);
    assert_int_not_equal(0, result.application_error_code);
    error_clear(&result);

    result = security_check_x509_valid_range(1513650902, 0, cert1, NULL, "Also not a time");
    assert_int_not_equal(0, result.application_error_code);
    error_clear(&result);

    // Check simulation
    result = security_check_x509_valid_range(100000, 0, cert1, "19700101010101Z", NULL);
    assert_int_equal(0, result.application_error_code);
    error_clear(&result);

    result = security_check_x509_valid_range(100000, 0, cert1, "19700101010101Z", "20380101235959Z");
    assert_int_equal(0, result.application_error_code);
    error_clear(&result);

    result = security_check_x509_valid_range(2147403647, 0, cert1, "19700101010101Z", "20380201235959Z");
    assert_int_equal(0, result.application_error_code);
    error_clear(&result);

    // security_print_certs_in_list(cert_list, stdout);

    cert1_dup = security_dup_cert(cert1);
    assert_non_null(cert1_dup);
    cert1_ou = security_get_field_from_cert(cert1_dup, "organizationalUnitName");
    assert_string_equal(cert1_ou, "122TEr35mwsrGkMyMUVBWYC1LfY1opewzh");
    XFREE(cert1_ou);
    security_free_cert(cert1_dup);

    security_free_cert_list(cert_list);
}

static void test_pkcs12(void)
{
    const char * pkcs12_blob_base64 =
        "MIII6AIBAzCCCK4GCSqGSIb3DQEHAaCCCJ8EggibMIIIlzCCB2oGCSqGSIb3DQEHAaCCB1sEggdXMIIHUzCCAz8GCyqGSIb3DQEMCgEDoIIC8DCCAuwGCiqGSI"
        "b3DQEJFgGgggLcBIIC2DCCAtQwggJ5oAMCAQICFFRPP8EU6z0JUu6yez2Q8S1pmmMOMAoGCCqGSM49BAMCMEsxMzAxBgNVBAMMKk5vbiBQcm9kdWN0aW9uIE9O"
        "TFkgLSBYRk4gREwgUEFJIDEgQ2xhc3MgMzEUMBIGCisGAQQBgqJ8AgEMBEZGRjQwHhcNMjIxMDIxMTQwMTE0WhcNMjMxMDIxMTYwMTE0WjCBzDELMAkGA1UEBh"
        "MCVVMxCzAJBgNVBAgMAlBBMRUwEwYDVQQHDAxQaGlsYWRlbHBoaWExEzARBgNVBAoMCk9wZW5Tb3VyY2UxEDAOBgNVBAsMB1hmaW5pdHkxKDAmBgNVBAMMH2Nl"
        "cnRpZmllci5tYXR0ZXIub3BlbnNvdXJjZS5jb20xMjAwBgoJkiaJk/"
        "IsZAEBDCIxRjViNVlScWI4YlJlTWlkR2NoZlRmWUJITlQ1NGlWZEN0MRQwEgYKKwYBBAGConwCAQwERkZGNDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGtc"
        "MCYunl1z9dn+IL9tXcIvlsGspr/HBNNWosUD1zCRLhuSYrejPHiF7yKve2UUEsZOtzJ/"
        "FJarKXKRgvQ1bDijgbgwgbUwMgYDVR0RBCswKaAnBgsrBgEEAYGGdoN0AaAYDBZ4MTpjZXJ0aWZpZXI6eDUwOTpzZWVkMA8GA1UdDwEB/"
        "wQFAwMAgAAwIAYDVR0lAQH/BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/"
        "wQCMAAwHwYDVR0jBBgwFoAUlXKz2gKpJV6PUrqkzLBJMqBkVgcwHQYDVR0OBBYEFGSGMed6EqDmh83cKzDFOQzsBXl4MAoGCCqGSM49BAMCA0kAMEYCIQDcMdo"
        "6ZNuIPSBn9qxrpUD74LnVybT4Y0Fw6c9Bkm2uowIhAI5zqADOMs2nmF3K+awzxPsrh3QFY6eJ/QO6rWc3EfWkMTwwIwYJKoZIhvcNAQkVMRYEFJsQpRtVp/"
        "Ux81z8soiJa5LWpLs5MBUGCSqGSIb3DQEJFDEIHgYASwBlAHkwggIRBgsqhkiG9w0BDAoBA6CCAgAwggH8BgoqhkiG9w0BCRYBoIIB7ASCAegwggHkMIIBi6AD"
        "AgECAhQSVd3gMQwxqymRVduObbuN3nTUgTAKBggqhkjOPQQDAjAwMS4wLAYDVQQDDCVOb24gUHJvZHVjdGlvbiBPTkxZIC0gWEZOIFBBQSBDbGFzcyAzMCAXDT"
        "IyMDEyODAwMDAwNloYDzIwNTExMjA3MDMyNzM2WjBLMTMwMQYDVQQDDCpOb24gUHJvZHVjdGlvbiBPTkxZIC0gWEZOIERMIFBBSSAxIENsYXNzIDMxFDASBgor"
        "BgEEAYKifAIBDARGRkY0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEELoMjUkVQN6aNiReXovV2vcAuaV4VMrwSup0duhvbZTPO9pjYYWvfEGPgBdc6JE6FD"
        "gMHCEEdW3hFH1ckpxXfKNmMGQwEgYDVR0TAQH/BAgwBgEB/"
        "wIBADAfBgNVHSMEGDAWgBT4manVrXFx5MOBfxQQf3jw2fdi6TAdBgNVHQ4EFgQUlXKz2gKpJV6PUrqkzLBJMqBkVgcwDgYDVR0PAQH/"
        "BAQDAgEGMAoGCCqGSM49BAMCA0cAMEQCIAq2MhX1qloqIr/IbM/1J1+j9qjyvqKUx7BnjjeWb/"
        "QtAiAGHoLk2r8ToO26Q1WdL65RI1k+"
        "R87OaSGwb2CocKKgIjCCAfcGCyqGSIb3DQEMCgEDoIIB5jCCAeIGCiqGSIb3DQEJFgGgggHSBIIBzjCCAcowggFwoAMCAQICFBZHVul2jw0A7Cd+"
        "d9HkZIjrWG1kMAoGCCqGSM49BAMCMDAxLjAsBgNVBAMMJU5vbiBQcm9kdWN0aW9uIE9OTFkgLSBYRk4gUEFBIENsYXNzIDMwIBcNMjExMjE0MDMyNzM2WhgPMj"
        "A1MTEyMDcwMzI3MzZaMDAxLjAsBgNVBAMMJU5vbiBQcm9kdWN0aW9uIE9OTFkgLSBYRk4gUEFBIENsYXNzIDMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQf"
        "lJ6vCnTLkOsVhSrQFRq3gxsw5ci66bkiGfOnjLMILuMb44o2DeopY4mtR48VU00XYnkTmu5qaCw+6hFAuco5o2YwZDASBgNVHRMBAf8ECDAGAQH/"
        "AgEBMB8GA1UdIwQYMBaAFPiZqdWtcXHkw4F/FBB/"
        "ePDZ92LpMB0GA1UdDgQWBBT4manVrXFx5MOBfxQQf3jw2fdi6TAOBgNVHQ8BAf8EBAMCAYYwCgYIKoZIzj0EAwIDSAAwRQIgWCLI3mriNpw5J1NU4RA88hn4OB"
        "fbS0pIrk60yRq+RKkCIQDBV28U84Dn8dET4KRFPLMhRGMlwgXL+"
        "IVdeK1nXXNPBjCCASUGCSqGSIb3DQEHAaCCARYEggESMIIBDjCCAQoGCyqGSIb3DQEMCgECoIG8MIG5MBwGCiqGSIb3DQEMAQMwDgQIduVNwg4xPGACAggABIG"
        "YnPIryTvSmAFIq9B9AcmOIK9ir9U8qO2wlPudLJbQtb1bvGQeEpC9/nF/GELq6xSfnsM3RJyhUN+ZxZuF0WYI6erkrdi9xzXPxunCBG3xLS12uE/"
        "2w0IFR5MYDXUwtvb5nUVcoqm3BLDNHONqBs4FhCJVn2kCpg6Aq5FJKXglitDsAPRhGoPkoYUjcnBefBw7eOH+"
        "Jj381qYxPDAjBgkqhkiG9w0BCRUxFgQUmxClG1Wn9THzXPyyiIlrktakuzkwFQYJKoZIhvcNAQkUMQgeBgBLAGUAeTAxMCEwCQYFKw4DAhoFAAQUQvDgZTxPep"
        "6LVyiYwaMc8EfQaIAECMyAnLmnljCMAgIIAA==";

    const char * pkcs12_file_name   = "/tmp/test.p12";
    const char * pkcs12_file_name_2 = "/tmp/write_test.p12";
    const char * pkcs12_file_name_3 = "/tmp/write_test1.p12";
    const char * pkcs12_passwd      = "changeit";

    unsigned char pkcs12_blob[8192];
    int blob_len            = 0;
    XFILE pkcs12_file       = NULL;
    X509_LIST * certs       = NULL;
    ECC_KEY * key           = NULL;
    X509_CERT * cert        = NULL;
    char * certifier_id     = NULL;
    char * generated_crt    = NULL;
    char * signature        = NULL;
    unsigned char hash[32]  = { 0 };
    unsigned char * der_key = NULL;
    int der_key_len         = 0;
    int ret                 = 0;
    int rc               = 0;

    certifier_set_property(certifier, CERTIFIER_OPT_OUTPUT_NODE, "dummy output node");

    blob_len = base64_decode(pkcs12_blob, pkcs12_blob_base64);

    assert_int_equal(2284, blob_len);

    // coverity[returned_null] assert_non_null() fail()s when this returns NULL
    pkcs12_file = XFOPEN(pkcs12_file_name, "w");
    assert_non_null(pkcs12_file);
    XFWRITE(pkcs12_blob, 1, blob_len, pkcs12_file);
    XFCLOSE(pkcs12_file);
    pkcs12_file = NULL;

    certs = security_new_cert_list();
    assert_non_null(certs);

    CertifierError result = security_find_or_create_keys(_certifier_get_properties(certifier), pkcs12_file_name,
                                                         "this is not the password at all", NULL, "prime256v1", &key);
    assert_int_not_equal(0, result.application_error_code);
    assert_non_null(result.library_error_msg);
    error_clear(&result);
    assert_null(key);

    // begin positive case
    result = security_find_or_create_keys(_certifier_get_properties(certifier), pkcs12_file_name, pkcs12_passwd, certs,
                                          "prime256v1", &key);
    assert_int_equal(0, result.application_error_code);
    error_clear(&result);
    assert_non_null(key);

    assert_non_null(security_cert_list_get(certs, 0));
    assert_non_null(security_cert_list_get(certs, 1));
    assert_non_null(security_cert_list_get(certs, 2));

    cert = security_cert_list_pop(certs, 2);
    assert_non_null(cert);

    // now, let's write out what we just read...
    util_delete_file(pkcs12_file_name_3);
    rc = security_persist_pkcs_12_file(pkcs12_file_name_3, pkcs12_passwd, key, cert, certs, &result);
    assert_int_equal(0, rc);
    error_clear(&result);
    security_free_eckey(key);
    security_free_cert(cert);
    security_free_cert_list(certs);

    // let's read it back in again
    // coverity[returned_null] assert_non_null() fail()s when this returns NULL
    certs = security_new_cert_list();
    assert_non_null(certs);

    result = security_find_or_create_keys(_certifier_get_properties(certifier), pkcs12_file_name_3, pkcs12_passwd, certs,
                                          "prime256v1", &key);
    assert_int_equal(0, result.application_error_code);
    error_clear(&result);
    assert_non_null(key);

    assert_non_null(security_cert_list_get(certs, 0));
    assert_non_null(security_cert_list_get(certs, 1));
    assert_non_null(security_cert_list_get(certs, 2));

    cert = security_cert_list_pop(certs, 0);
    assert_non_null(cert);
    security_free_cert(cert);

    // end positive case

    result = security_get_X509_PKCS12_file(pkcs12_file_name, "fake_password", NULL, &cert, NULL);
    assert_true(result.application_error_code >= 1);
    error_clear(&result);
    assert_null(cert);
    security_free_cert(cert);

    result = security_get_X509_PKCS12_file(pkcs12_file_name, pkcs12_passwd, NULL, &cert, NULL);
    assert_int_equal(0, result.application_error_code);
    error_clear(&result);
    assert_non_null(cert);

    assert_int_equal(0, security_generate_x509_crt(&generated_crt, cert, key));
    _certifier_set_x509_cert(certifier, cert);
    _certifier_set_ecc_key(certifier, key);

    assert_non_null(generated_crt);
    XFREE(generated_crt);

    size_t der_len      = 0;
    unsigned char * der = security_X509_to_DER(cert, &der_len);
    assert_non_null(der);
    assert_true(der_len >= 64);
    XFREE(der);

    certifier_id = security_get_field_from_cert(cert, "organizationalUnitName");
    assert_non_null(certifier_id);
    assert_string_equal("Xfinity", certifier_id);
    XFREE(certifier_id);

    der_key_len = security_serialize_der_public_key(key, &der_key);
    assert_non_null(der_key);
    assert_true(der_key_len >= 32);
    XFREE(der_key);
    der_key = NULL;

    signature = security_sign_hash_b64(key, hash, sizeof(hash));
    assert_non_null(signature);
    XFREE(signature);

    security_persist_pkcs_12_file(pkcs12_file_name_2, "beware the ninjas", key, cert, certs, &result);
    assert_int_equal(0, result.application_error_code);
    error_clear(&result);
    security_free_eckey(key);
    security_free_cert(cert);
    security_free_cert_list(certs);
    key = NULL;

    result = security_find_or_create_keys(_certifier_get_properties(certifier), pkcs12_file_name_2, "beware the ninjas", NULL,
                                          "prime256v1", &key);
    assert_int_equal(0, result.application_error_code);
    error_clear(&result);
    assert_non_null(key);
    security_free_eckey(key);

    result = security_get_X509_PKCS12_file(pkcs12_file_name_2, "beware the ninjas", NULL, &cert, NULL);
    assert_int_equal(0, result.application_error_code);
    error_clear(&result);
    assert_non_null(cert);
    assert_int_equal(0, ret);

    result = security_find_or_create_keys(_certifier_get_properties(certifier), pkcs12_file_name_2, "beware the ninjas", NULL,
                                          "prime256v1", &key);
    assert_int_equal(0, result.application_error_code);
    error_clear(&result);
    assert_non_null(key);
    security_free_eckey(key);

    certifier_id = security_get_field_from_cert(cert, "organizationalUnitName");
    assert_non_null(certifier_id);
    assert_string_equal("Xfinity", certifier_id);
    XFREE(certifier_id);
    security_free_cert(cert);

    // test public certifier methods
    certifier_set_property(certifier, CERTIFIER_OPT_INPUT_P12_PASSWORD, pkcs12_passwd);
    certifier_set_property(certifier, CERTIFIER_OPT_ECC_CURVE_ID, "prime256v1");
    certifier_set_property(certifier, CERTIFIER_OPT_INPUT_P12_PATH, pkcs12_file_name);
    ret = certifier_setup_keys(certifier);
    assert_int_equal(0, ret);
    assert_non_null(certifier_get_node_address(certifier));
    // assert_non_null(certifier_get_certifier_id(certifier));

    char * pem = certifier_get_x509_pem(certifier);
    assert_non_null(pem);
    XFREE(pem);
    pem = NULL;

    certifier_set_property(certifier, CERTIFIER_OPT_INPUT_P12_PATH, "");
    ret = certifier_setup_keys(certifier);
    assert_int_equal(4, ret);

    certifier_set_property(certifier, CERTIFIER_OPT_INPUT_P12_PATH, pkcs12_file_name);
    certifier_set_property(certifier, CERTIFIER_OPT_INPUT_P12_PASSWORD, "");
    ret = certifier_setup_keys(certifier);
    assert_int_equal(5, ret);

    pem = certifier_get_x509_pem(certifier);
    assert_null(pem);
    XFREE(pem);
    pem = NULL;

    certifier_set_property(certifier, CERTIFIER_OPT_INPUT_P12_PASSWORD, pkcs12_passwd);
    certifier_set_property(certifier, CERTIFIER_OPT_ECC_CURVE_ID, "");
    ret = certifier_setup_keys(certifier);
    assert_int_equal(6, ret);

    certifier_set_property(certifier, CERTIFIER_OPT_INPUT_P12_PATH, pkcs12_file_name);
    certifier_set_property(certifier, CERTIFIER_OPT_INPUT_P12_PASSWORD, pkcs12_passwd);
    certifier_set_property(certifier, CERTIFIER_OPT_ECC_CURVE_ID, "prime256v1");

    ret = certifier_get_device_registration_status(certifier);
    assert_int_equal(0, ret);

    // TODO:  Revisit this.  s
    // char *output_x509_cert = NULL;
    // ret = certifier_create_x509_crt(certifier, &output_x509_cert);
    // assert_int_equal(0, ret);
    // assert_non_null(output_x509_cert);

    certifier_set_property(certifier, CERTIFIER_OPT_INPUT_P12_PATH, "/tmp/test.p12");
    certifier_set_property(certifier, CERTIFIER_OPT_INPUT_P12_PASSWORD, "fake_password");
    ret = certifier_setup_keys(certifier);
    assert_int_equal(1, ret);

    delete_file(pkcs12_file_name);
    delete_file(pkcs12_file_name_2);
    // delete_file(pkcs12_file_name_3);
}

/*
 * The Java equivalent test took ~ 5189 ms to complete 1 million iterations.
 * This took ~ 4852 ms seconds in C (using -Os compiler flag).
 */
static void test_sha256_ripemd_b58_performance(void)
{

    const char * value_prefix = "value12345678890000000000000000000000-0";

    clock_t t;
    t = clock();

    for (size_t i = 1; i < 1000000; i++)
    {
        uint8_t arr[256];
        char iteration[256];
        XSNPRINTF(iteration, sizeof iteration, "%zu", i);
        XMEMCPY(arr, value_prefix, XSTRLEN(value_prefix));
        XMEMCPY(arr + XSTRLEN(value_prefix), iteration, XSTRLEN(iteration));
        int rc        = 0;
        char * result = security_encode(arr, sizeof arr, &rc);
        assert_true(rc == 0);
        assert_true(result != NULL);
        // XFPRINTF(stderr, "Result=%s", result);
        XFREE(result);
        XMEMSET(arr, 0, sizeof arr);
    }

    t                 = clock() - t;
    double time_taken = ((double) t) / CLOCKS_PER_SEC; // in seconds
    XFPRINTF(stderr, "test_sha256_ripemd_b58_performance took %f seconds to execute \n", time_taken);
}

static void cleanup_logs(void)
{
    const char * log_file_name     = "/tmp/test_logging.log";
    const char * old_log_file_name = "/tmp/test_logging.log.old";

    int ret = 0;

    log_destroy();
    if (util_file_exists(log_file_name))
    {
        ret = remove(log_file_name);
        assert_int_equal(0, ret);
    }

    if (util_file_exists(old_log_file_name))
    {
        ret = remove(old_log_file_name);
        assert_int_equal(0, ret);
    }
}

// still a WIP - need more testing
static void test_logging(void)
{

    int i;
    const char * log_file_name     = "/tmp/test_logging.log";
    const char * old_log_file_name = "/tmp/test_logging.log.old";

    cleanup_logs();

    log_set_file_name(log_file_name);
    log_set_max_size(100);

    assert_false(util_file_exists(log_file_name));
    assert_false(util_file_exists(old_log_file_name));

    for (i = 0; i < 101; i++)
    {
        log_info("A");
    }

    // assert_true(util_file_exists(log_file_name));
    // assert_false(util_file_exists(old_log_file_name));

    cleanup_logs();
}

static void test_options(void)
{
    CertifierPropMap * props = _certifier_get_properties(certifier);

    certifier_set_property(certifier, CERTIFIER_OPT_CERTIFICATE_LITE, (void *) true);
    assert_true(certifier_get_property(certifier, CERTIFIER_OPT_CERTIFICATE_LITE));
    assert_true(property_is_option_set(props, CERTIFIER_OPTION_CERTIFICATE_LITE));

    certifier_set_property(certifier, CERTIFIER_OPT_CERTIFICATE_LITE, false);
    assert_false(certifier_get_property(certifier, CERTIFIER_OPT_CERTIFICATE_LITE));
    assert_false(property_is_option_set(props, CERTIFIER_OPTION_CERTIFICATE_LITE));
}

int main(int argc, char ** argv)
{
    log_set_quiet(1);

#ifdef CMOCKA_ENABLED
    int rc = 0;
    if ((argc == 2) && (XSTRNCMP(argv[1], "--performance", XSTRLEN(argv[1])) == 0))
    {
        const struct CMUnitTest tests[] = { CREATE_TEST(test_sha256_ripemd_b58_performance) };
        rc                              = cmocka_run_group_tests(tests, NULL, NULL);
    }
    else
    {
        const struct CMUnitTest tests[] = {
            CREATE_TEST(test_base64), CREATE_TEST(test_base58), CREATE_TEST(test_file_utils), CREATE_TEST(test_random_val),
            CREATE_TEST(test_str_utils), CREATE_TEST(test_set_curl_error), CREATE_TEST(test_sha256_ripemd_b58),
            CREATE_TEST(test_ecc_key), CREATE_TEST(test_verify_signature_1), CREATE_TEST(test_verify_signature_2),
            CREATE_TEST(test_x509_cert),

            CREATE_TEST(test_pkcs12),

            CREATE_TEST(test_certifier_client_requests), CREATE_TEST(test_certifier_client_requests1),

            CREATE_TEST(test_certifier_create_crt1), CREATE_TEST(test_certifier_create_node_address),
            CREATE_TEST(test_certifier_get_version),

            //                CREATE_TEST(test_logging),

            CREATE_TEST(test_options)
        };

        rc = cmocka_run_group_tests(tests, NULL, NULL);
    }

    rc |= run_easy_api_tests();

    return rc;
#else
    UNITY_BEGIN();

    log_set_file_name("/tmp/certifier.log");
    log_set_quiet(0);

    if ((argc == 2) && (XSTRNCMP(argv[1], "--performance", XSTRLEN(argv[1])) == 0))
    {
        RUN_TEST(test_sha256_ripemd_b58_performance);
    }
    else
    {
        printf("starting base64 test \n");
        RUN_TEST(test_base64);
        printf("ending base64 test \n");
        printf("starting base58 test \n");
        RUN_TEST(test_base58);
        printf("ending base58 test \n");
        printf("starting test_file_utils test \n");
        RUN_TEST(test_file_utils);
        printf("ending test_file_utils test \n");
        fflush(stdout);
        RUN_TEST(test_random_val);
        RUN_TEST(test_str_utils);
        RUN_TEST(test_set_curl_error);
        RUN_TEST(test_sha256_ripemd_b58);
        RUN_TEST(test_ecc_key);
        RUN_TEST(test_verify_signature_1);
        RUN_TEST(test_verify_signature_2);
        RUN_TEST(test_x509_cert);

        RUN_TEST(test_pkcs12);

        RUN_TEST(test_certifier_client_requests);
        RUN_TEST(test_certifier_client_requests1);
        RUN_TEST(test_certifier_create_crt1);
        RUN_TEST(test_certifier_create_node_address);
        RUN_TEST(test_certifier_get_version);

        RUN_TEST(test_logging);

        RUN_TEST(test_options);
    }
    return UNITY_END();
#endif
}
