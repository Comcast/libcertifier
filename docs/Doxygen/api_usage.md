\page docs/Doxygen/api_usage.md API usage 
[Back to Manual](docs/Doxygen/libcertifier.md) 

Include the Header file
=======================

    #import "certifier/certifier_api_easy.h"

Instantiate a CERTIFIER Structure
=================================

    CERTIFIER *easy = certifier_api_easy_new();

OPTIONAL - Get the version of the API
=====================================

    char *version = certifier_api_easy_get_version(easy);

Setup Parameters
================

    certifier_api_easy_set_opt(easy, CERTIFIER_OPT_CFG_FILENAME, cfgFilePath);
    certifier_api_easy_set_opt(easy, CERTIFIER_OPT_CA_INFO, cacertFilePath);
    certifier_api_easy_set_opt(easy, CERTIFIER_OPT_KEYSTORE, p12FilePath);
    certifier_api_easy_set_opt(easy, CERTIFIER_OPT_PASSWORD, keystore_password);

Create a CRT Token from a "TEST" Token type
===========================================

    int rc;
    certifier_api_easy_set_opt(easy, CERTIFIER_OPT_CRT_TYPE, "TEST");
    certifier_api_easy_set_mode(easy, CERTIFIER_MODE_CREATE_CRT);
    certifier_api_easy_set_opt(easy, CERTIFIER_OPT_AUTH_TOKEN, token);
    rc = certifier_api_easy_perform(easy);
    char * crt = (char *) certifier_api_easy_get_result(easy);

Create a public/private keypair, fetch x509 from server and store in PKCS12 file
================================================================================

    certifier_api_easy_set_mode(easy, CERTIFIER_MODE_RENEW_CERT);
    certifier_api_easy_set_opt(easy, CERTIFIER_OPT_CRT, crt);
    rc = certifier_api_easy_perform(easy);

Cleanup
=======

    certifier_api_easy_destroy(easy);
