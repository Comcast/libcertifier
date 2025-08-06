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
#include <certifier/sectigo_client.h>
#include <unity.h>

static const char * token = NULL;

static void test_get_cert()
{
    XPKI_CLIENT_ERROR_CODE error;
    get_cert_param_t params = { 0 };

    xc_get_default_cert_param(&params);

    params.auth_type           = XPKI_AUTH_X509;
    params.fabric_id           = 0xABCDABCDABCDABCD;
    params.node_id             = 0x1234123412341234;
    params.input_p12_password  = "changeit";
    params.input_p12_path      = "seed.p12";
    params.output_p12_password = "newpass";
    params.output_p12_path     = "output-xc-test-renewable.p12";
    params.overwrite_p12       = true;
    params.product_id          = 0xABCD;
    params.profile_name        = "XFN_Matter_OP_Class_3_ICA";
    params.validity_days       = 90;
    params.lite                = true;
    params.common_name         = "X9c0XXBqIosRCg35keK8XsWC2PAdjQrG";
    params.source_id           = "libcertifier-opensource";

#ifdef RDK_BUILD
    error = xc_get_cert(&params);
    TEST_ASSERT_EQUAL_INT(XPKI_CLIENT_INVALID_ARGUMENT, error);
#endif // RDK_BUILD

    params.mac_address = "00:B0:D0:63:C2:26";

    error = xc_get_cert(&params);
    TEST_ASSERT_EQUAL_INT(XPKI_CLIENT_SUCCESS, error);

    params.validity_days   = 100;
    params.output_p12_path = "output-xc-test-not-renewable.p12";
    error                  = xc_get_cert(&params);
    TEST_ASSERT_EQUAL_INT(XPKI_CLIENT_SUCCESS, error);

    params.output_p12_path = "output-xc-test-san.p12";
    params.profile_name    = "XFN_DL_PAI_1_Class_3";
    params.ip_san          = "[\"1.2.3.4\"]";
    params.email_san       = "[\"testemail@test.com\"]";
    params.serial_number   = "ABCD22";
    params.lite            = false;
    error                  = xc_get_cert(&params);
    TEST_ASSERT_EQUAL_INT(XPKI_CLIENT_SUCCESS, error);
}

static void test_get_cert_auth_token()
{
    XPKI_CLIENT_ERROR_CODE error;
    get_cert_param_t params = { 0 };

    xc_get_default_cert_param(&params);

    params.auth_type           = XPKI_AUTH_SAT;
    params.auth_token          = token;
    params.fabric_id           = 0xABCDABCDABCDABCD;
    params.node_id             = 0x1234123412341234;
    params.output_p12_password = "newpass";
    params.output_p12_path     = "output-xc-auth-token-test-renewable.p12";
    params.overwrite_p12       = true;
    params.product_id          = 0xABCD;
    params.profile_name        = "XFN_Matter_OP_Class_3_ICA";
    params.validity_days       = 90;
    params.lite                = true;
    params.common_name         = "X9c0XXBqIosRCg35keK8XsWC2PAdjQrG";
    params.source_id           = "libcertifier-opensource";
    params.mac_address         = "00:B0:D0:63:C2:26";

    error = xc_get_cert(&params);
    TEST_ASSERT_EQUAL_INT(XPKI_CLIENT_SUCCESS, error);
}

static void  test_get_seed_cert_auth_token()
{
    XPKI_CLIENT_ERROR_CODE error;
    get_cert_param_t params = { 0 };

    xc_get_default_cert_param(&params);

    params.auth_type           = XPKI_AUTH_SAT;
    params.auth_token          = token;
    params.output_p12_password = "newpass";
    params.output_p12_path     = "output-xc-auth-token-test-seed-cert-renewable.p12";
    params.overwrite_p12       = true;
    params.profile_name        = "Xfinity_Subscriber_Issuing_ECC_ICA";
    params.validity_days       = 90;
    params.lite                = false;
    params.use_scopes          = true;
    params.common_name         = "X9c0XXBqIosRCg35keK8XsWC2PAdjQrG";
    params.source_id           = "libcertifier-opensource";
    params.mac_address         = "00:B0:D0:63:C2:26";

    error = xc_get_cert(&params);
    TEST_ASSERT_EQUAL_INT(XPKI_CLIENT_SUCCESS, error);
}

static void test_get_cert_status()
{
    XPKI_CLIENT_ERROR_CODE error;
    XPKI_CLIENT_CERT_STATUS status;
    get_cert_status_param_t params = { 0 };

    xc_get_default_cert_status_param(&params);

    params.p12_password = "newpass";
    params.p12_path     = "output-xc-test-renewable.p12";

    error = xc_get_cert_status(&params, &status);
    TEST_ASSERT_EQUAL_INT(XPKI_CLIENT_SUCCESS, error);
    TEST_ASSERT_EQUAL_INT(XPKI_CLIENT_CERT_ABOUT_TO_EXPIRE, status);

    params.p12_password = "newpass";
    params.p12_path     = "output-xc-test-not-renewable.p12";

    error = xc_get_cert_status(&params, &status);
    TEST_ASSERT_EQUAL_INT(XPKI_CLIENT_SUCCESS, error);
    TEST_ASSERT_EQUAL_INT(XPKI_CLIENT_CERT_VALID, status);
}

static void test_renew_cert()
{
    get_cert_status_param_t params = { 0 };

    xc_get_default_cert_status_param(&params);

    params.p12_password = "newpass";
    params.p12_path     = "output-xc-test-not-renewable.p12";

    XPKI_CLIENT_ERROR_CODE error = xc_renew_cert(&params);
    TEST_ASSERT_EQUAL_INT(XPKI_CLIENT_CERT_ALREADY_VALID, error);
#if 0 // disable test below because we're not allowed to mess with the certifier url during run-time.
    get_cert_param_t params = { 0 };

    xc_get_default_cert_param(&params);

    params.auth_type          = XPKI_AUTH_X509;
    params.input_password     = "SE051";
    params.input_pkcs12_path  = "stage-seed.p12";
    params.output_password    = "newpass";
    params.output_pkcs12_path = "stage-output-renewable.p12";
    params.overwrite_p12      = true;
    params.profile_name       = "Xfinity_Default_Issuing_ECC_ICA";
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

static void test_renew_cert_auth_token()
{
    renew_cert_param_t params = { 0 };

    xc_get_default_renew_cert_param(&params);

    params.p12_password = "newpass";
    params.p12_path     = "output-xc-auth-token-test-renewable.p12";
    params.auth_type    = XPKI_AUTH_SAT;
    params.auth_token   = token;

    XPKI_CLIENT_ERROR_CODE error = xc_renew_cert(&params);
    TEST_ASSERT_EQUAL_INT(XPKI_CLIENT_SUCCESS, error);
}

static void test_print_cert_validity()
{
   XPKI_CLIENT_ERROR_CODE error;
   get_cert_status_param_t params = { 0 };

   xc_get_default_cert_status_param(&params);

   params.p12_password = "newpass";
   params.p12_path     = "output-xc-test-renewable.p12";

   error = xc_print_cert_validity(params.p12_path, params.p12_password);
   TEST_ASSERT_EQUAL_INT(XPKI_CLIENT_SUCCESS, error);
}

static void test_get_cert_validity()
{
    XPKI_CLIENT_ERROR_CODE error;
    XPKI_CLIENT_CERT_STATUS status;
    get_cert_validity_param_t params = { 0 };

    xc_get_default_cert_validity_param(&params);

    params.p12_password = "newpass";
    params.p12_path     = "output-xc-test-not-renewable.p12";

    error = xc_get_cert_validity(&params, &status);

    TEST_ASSERT_EQUAL_INT(XPKI_CLIENT_SUCCESS, error);
    TEST_ASSERT_EQUAL_INT(XPKI_CLIENT_CERT_VALID , status);

    xc_get_default_cert_validity_param(&params);
    params.p12_password = "newpass";
    params.p12_path     = "output-xc-test-renewable.p12";

    error = xc_get_cert_validity(&params, &status);

    TEST_ASSERT_EQUAL_INT(XPKI_CLIENT_SUCCESS, error);
    TEST_ASSERT_EQUAL_INT(XPKI_CLIENT_CERT_ABOUT_TO_EXPIRE, status);
}
static void test_get_sectigo_cert()
{
    SECTIGO_CLIENT_ERROR_CODE error;
    get_cert_sectigo_param_t params = { 0 };

    // Fill parameters (simulate config or CLI)
    params.sectigo_auth_token           = "token";
    params.sectigo_common_name          = "sectigotest.comcast.com";
    params.sectigo_group_name           = "GroupName";
    params.sectigo_group_email          = "example@comcast.com";
    params.sectigo_id                   = "exid";
    params.sectigo_owner_fname          = "First";
    params.sectigo_owner_lname          = "Last";
    params.sectigo_employee_type        = "associate";
    params.sectigo_server_platform      = "other";
    params.sectigo_sensitive            = "false";
    params.sectigo_project_name         = "Testing create with SAT";
    params.sectigo_business_justification = "Testing create with SAT";
    params.sectigo_subject_alt_names    = "*";
    params.sectigo_ip_addresses         = "*";
    params.sectigo_cert_type            = "comodo";
    params.sectigo_owner_phonenum       = "2670000000";
    params.sectigo_owner_email          = "first_last@comcast.com";
    params.sectigo_url                  = "https://certs-dev.xpki.io/api/createCertificate";
    params.sectigo_source               = "libcertifier";

    // Call the API
    error = xc_sectigo_get_cert(&params);

    TEST_ASSERT_EQUAL_INT(SECTIGO_CLIENT_SUCCESS, error);
}
int main(int argc, char ** argv)
{
    UNITY_BEGIN();

    RUN_TEST(test_get_cert);
    if (argv[1] != NULL)
    {
        token = argv[1];
        RUN_TEST(test_get_cert_auth_token);
        RUN_TEST(test_get_seed_cert_auth_token);
        RUN_TEST(test_renew_cert_auth_token);
    }
    RUN_TEST(test_get_cert_status);
    RUN_TEST(test_renew_cert);
    RUN_TEST(test_print_cert_validity);
    RUN_TEST(test_get_cert_validity);
    RUN_TEST(test_get_sectigo_cert);

    return UNITY_END();
}
