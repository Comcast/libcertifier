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

#ifdef CMOCKA_ENABLED

#include "easy_api_tests.h"
#include "certifier/base64.h"
#include "certifier/certifier_api_easy.h"
#include "certifier/types.h"
#include "certifier/util.h"
#include "cmocka.h"
#include "tests.h"

static CERTIFIER * easy;

static int setUp(void ** state)
{
    easy = certifier_api_easy_new();

    int err = 0;
    if (easy == NULL)
    {
        err = 1;
    }

    return err;
}

static int tearDown(void ** state)
{
    certifier_api_easy_destroy(easy);
    easy = NULL;

    return 0;
}

static void _check_version(const char * version, const int line)
{
    ASSERT_TRUE_MESSAGE(version, "version null at line: %d", line);
    ASSERT_TRUE_MESSAGE(XSTRSTR(version, "libcertifier " CERTIFIER_VERSION) == version,
                        "certifier version '%s' not in expected format", version);
}

#define check_version(ver) _check_version(ver, __LINE__)

static void test_api_easy(void ** state)
{
    certifier_api_easy_set_opt(easy, CERTIFIER_OPT_INPUT_P12_PATH, "/tmp/fake.p12");
    certifier_api_easy_set_mode(easy, CERTIFIER_MODE_GET_CERT_STATUS);

    int rc = certifier_api_easy_perform(easy);
    assert_int_not_equal(0, rc); // this fails for some reason

    char * version = certifier_api_easy_get_version(easy);
    check_version(version);
    free(version);
}

static inline void _check_crt(const char * b64_token, const char * type, const int line)
{
    static const char * type_fmt     = "\"tokenType\": \"%s\"";
    static const char * token_needle = "\"token\": \"fake token\"";

    ASSERT_TRUE_MESSAGE(b64_token != NULL, "token null at line %d", line);

    char * decoded    = XMALLOC(base64_decode_len(b64_token));
    int decoded_chars = base64_decode((unsigned char *) decoded, b64_token);
    ASSERT_TRUE_MESSAGE(decoded_chars > 0, "Could not decode token at line %d", line);

    char * tmp = util_format_str(type_fmt, type);
    ASSERT_TRUE_MESSAGE(XSTRSTR(decoded, tmp), "Incorrect or missing token type in '%s' at line %d", decoded, line);
    free(tmp);

    ASSERT_TRUE_MESSAGE(XSTRSTR(decoded, token_needle) != NULL, "Could not find token in wrapper '%s' at line %d", decoded, line);
    free(decoded);
}

#define check_crt(token, type) _check_crt(token, type, __LINE__)

static void test_api_easy_create_tokens(void ** state)
{
    certifier_api_easy_set_mode(easy, CERTIFIER_MODE_CREATE_CRT);
    certifier_api_easy_set_opt(easy, CERTIFIER_OPT_AUTH_TYPE, "CRT_TYPE_1");
    int rc = certifier_api_easy_perform(easy);
    ASSERT_TRUE_MESSAGE(rc != 0, "CRT created with no token!");

    certifier_api_easy_set_opt(easy, CERTIFIER_OPT_AUTH_TOKEN, "fake token");

    rc = certifier_api_easy_perform(easy);
    assert_int_equal(0, rc);
    check_crt(certifier_api_easy_get_result(easy), "CRT_TYPE_1");

    certifier_api_easy_set_mode(easy, CERTIFIER_MODE_CREATE_CRT);
    certifier_api_easy_set_opt(easy, CERTIFIER_OPT_AUTH_TYPE, "CRT_TYPE_2");
    rc = certifier_api_easy_perform(easy);
    assert_int_equal(0, rc);
    check_crt(certifier_api_easy_get_result(easy), "CRT_TYPE_2");

    certifier_api_easy_set_mode(easy, CERTIFIER_MODE_CREATE_CRT);
    certifier_api_easy_set_opt(easy, CERTIFIER_OPT_AUTH_TYPE, "CRT_TYPE_3");
    rc = certifier_api_easy_perform(easy);
    assert_int_equal(0, rc);
    check_crt(certifier_api_easy_get_result(easy), "CRT_TYPE_3");
}

static void test_api_easy_cmdline(void ** state)
{
    char * argv[]  = { "certifierTests", "-m", "128", "-S", "fake token", "-D", "CERTIFIER_OPT_ACTION=allow", "-X",
                       "CRT_TYPE_1",     NULL };
    const int argc = sizeof(argv) / sizeof(char *) - 1;

    certifier_api_easy_set_cli_args(easy, argc, argv);
    certifier_api_easy_perform(easy);

    check_crt(certifier_api_easy_get_result(easy), "CRT_TYPE_1");
}

int run_easy_api_tests(void)
{
    struct CMUnitTest tests[] = { CREATE_TEST(test_api_easy), CREATE_TEST(test_api_easy_create_tokens),
                                  CREATE_TEST(test_api_easy_cmdline) };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

#endif