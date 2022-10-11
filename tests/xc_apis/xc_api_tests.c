/**
 * Copyright 2022 Comcast Cable Communications Management, LLC
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

#include <certifier/certifier.h>
#include <certifier/xpki_client.h>

#include <unity.h>

static void test_get_cert()
{
    get_cert_param_t params = { 0 };

    xc_get_default_cert_param(&params);

    params.auth_type          = XPKI_AUTH_X509_CRT;
    params.fabric_id          = 0xABCDABCDABCDABCD;
    params.node_id            = 0x1234123412341234;
    params.input_p12_password     = "changeit";
    params.input_p12_path  = "seed.p12";
    params.output_p12_password    = "newpass";
    params.output_p12_path = "output-xc-test-renewable.p12";
    params.overwrite_p12      = true;
    params.product_id         = 0xABCD;
    params.profile_name       = XFN_Matter_OP_Class_3_ICA;
    params.validity_days      = 90;
    params.lite               = true;

    XPKI_CLIENT_ERROR_CODE error = xc_get_cert(&params);
    TEST_ASSERT_EQUAL_INT(XPKI_CLIENT_SUCCESS, error);

    params.validity_days      = 100;
    params.output_p12_path = "output-xc-test-not-renewable.p12";
    error                     = xc_get_cert(&params);
    TEST_ASSERT_EQUAL_INT(XPKI_CLIENT_SUCCESS, error);
}

static void test_get_cert_status()
{
    XPKI_CLIENT_ERROR_CODE error = xc_get_cert_status("output-xc-test-renewable.p12", "newpass");
    TEST_ASSERT_EQUAL_INT(XPKI_CLIENT_CERT_ABOUT_TO_EXPIRE, error);

    error = xc_get_cert_status("output-xc-test-not-renewable.p12", "newpass");
    TEST_ASSERT_EQUAL_INT(XPKI_CLIENT_CERT_VALID, error);
}

static void test_renew_cert()
{
    XPKI_CLIENT_ERROR_CODE error = xc_renew_cert("output-xc-test-not-renewable.p12", "newpass");
    TEST_ASSERT_EQUAL_INT(XPKI_CLIENT_CERT_ALREADY_VALID, error);
#if 0 // disable test below because we're not allowed to mess with the certifier url during run-time.
    get_cert_param_t params = { 0 };

    xc_get_default_cert_param(&params);

    params.auth_type          = XPKI_AUTH_X509_CRT;
    params.input_password     = "SE051";
    params.input_pkcs12_path  = "stage-seed.p12";
    params.output_password    = "newpass";
    params.output_pkcs12_path = "stage-output-renewable.p12";
    params.overwrite_p12      = true;
    params.profile_name       = Xfinity_Default_Issuing_ECC_ICA;
    params.validity_days      = 20;
    params.lite               = false;

    char * certifier_url = XSTRDUP(certifier_get_property(certifier, CERTIFIER_OPT_CERTIFIER_URL));
    certifier_set_property(certifier, CERTIFIER_OPT_CERTIFIER_URL, "https://certifier-stage.xpki.io/v1/certifier");

    error = xc_get_cert(&params);
    TEST_ASSERT_EQUAL_INT(XPKI_CLIENT_SUCCESS, error);

    error = xc_renew_cert("stage-output-renewable.p12", "newpass");
    TEST_ASSERT_EQUAL_INT(XPKI_CLIENT_SUCCESS, error);

    certifier_set_property(certifier, CERTIFIER_OPT_CERTIFIER_URL, certifier_url);
    XFREE(certifier_url);
#endif
}

int main(int argc, char ** argv)
{
    UNITY_BEGIN();

    RUN_TEST(test_get_cert);
    RUN_TEST(test_get_cert_status);
    RUN_TEST(test_renew_cert);

    return UNITY_END();
}
