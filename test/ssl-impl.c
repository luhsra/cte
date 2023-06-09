#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <string.h>
#include <stdbool.h>



char* pemCertString = "-----BEGIN CERTIFICATE-----\n"
    "MIIGCTCCBPGgAwIBAgISBBWrp8J35VPLEOkvVra2+g0XMA0GCSqGSIb3DQEBCwUA\n"
    "MDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD\n"
    "EwJSMzAeFw0yMTExMjYwNjAwMTBaFw0yMjAyMjQwNjAwMDlaMBkxFzAVBgNVBAMT\n"
    "DmF0Yy51c2VuaXgub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n"
    "x+Fy6lRKEyIZ8COj8IDiMXPv2Gml/gJNS0Sd3F/C3DpfbzM48DM5WfzNdbZfM6q2\n"
    "uBX97zKjg/iQUeoa4pZIxdH5qe0uTd3XkaNMCdBPwPKCNBakvYkzitWL/rtVNyQX\n"
    "qKcRx3DbR5m4oW4ntg3OC97WdKLkl9ql9xv9/iXNg9VllNMXj9yKEU0x3CaWNX57\n"
    "fIC8uG1/rFOjybq4wXKMj8i/UXs+uZY53At6vwArC7bf+m8ogGAR7v4YhHqK9Uab\n"
    "W5GKO0XYN6DGOfP3OSXKArxcDj7uh3HSYwJCvljLKb+oauOez3DQ2M+erz/0l5W9\n"
    "dsri7beIqnTofYzZiI403QIDAQABo4IDMDCCAywwDgYDVR0PAQH/BAQDAgWgMB0G\n"
    "A1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1Ud\n"
    "DgQWBBSQQb2R+fDXI89TwYGVWzPmGp0u6jAfBgNVHSMEGDAWgBQULrMXt1hWy65Q\n"
    "CUDmH6+dixTCxjBVBggrBgEFBQcBAQRJMEcwIQYIKwYBBQUHMAGGFWh0dHA6Ly9y\n"
    "My5vLmxlbmNyLm9yZzAiBggrBgEFBQcwAoYWaHR0cDovL3IzLmkubGVuY3Iub3Jn\n"
    "LzCB/wYDVR0RBIH3MIH0gg5hdGMudXNlbml4Lm9yZ4IQYmxvZ3MudXNlbml4Lm9y\n"
    "Z4INZGIudXNlbml4Lm9yZ4IRZW5pZ21hLnVzZW5peC5vcmeCD2Zhc3QudXNlbml4\n"
    "Lm9yZ4IPbGlzYS51c2VuaXgub3Jngg9uc2RpLnVzZW5peC5vcmeCD29zZGkudXNl\n"
    "bml4Lm9yZ4ITc2VjdXJpdHkudXNlbml4Lm9yZ4IRc3JlY29uLnVzZW5peC5vcmeC\n"
    "CnVzZW5peC5jb22CCnVzZW5peC5uZXSCCnVzZW5peC5vcmeCDnd3dy51c2VuaXgu\n"
    "bmV0gg53d3cudXNlbml4Lm9yZzBMBgNVHSAERTBDMAgGBmeBDAECATA3BgsrBgEE\n"
    "AYLfEwEBATAoMCYGCCsGAQUFBwIBFhpodHRwOi8vY3BzLmxldHNlbmNyeXB0Lm9y\n"
    "ZzCCAQQGCisGAQQB1nkCBAIEgfUEgfIA8AB3ACl5vvCeOTkh8FZzn2Old+W+V32c\n"
    "YAr4+U1dJlwlXceEAAABfVsLW/UAAAQDAEgwRgIhAKL98Umg3QAzyPeVY0QODKpq\n"
    "hmLeYarNCsF2eVxY878eAiEAobv4yHE1lc8mkdPDnJX40r/4Bbw2PgH+sZdGJLH4\n"
    "dmwAdQDfpV6raIJPH2yt7rhfTj5a6s2iEqRqXo47EsAgRFwqcwAAAX1bC133AAAE\n"
    "AwBGMEQCIECA8IeowFRwI2otxKIGLie3oMf2JhesWgOH4JHkxSvrAiAvXDcurbrY\n"
    "9cNYoE4Qmch1xaIY7yhn4e8uCpyoW0glCzANBgkqhkiG9w0BAQsFAAOCAQEAkflT\n"
    "rTGMSVb48qhxbkKN6KlIyXFzVXck5Bkic693BL2ZWzh2YrcrvBcSj0R+FrNS2Uhd\n"
    "PFQjNADLvVwSM5BgLLMO6GX7oDOZ23Iqb2iob0XEYWnIMizGzzDcHM0IdSlfyzmo\n"
    "Muf9+RRJ6WRIk4dUO+B0E8xq927L+cwHgt9hJuKllsma94pDxD1W6OU7ZUu/G52k\n"
    "2QyfcevK8B7Re8qfLXwuQ9vmwBgmvWflXNwfCsQtri+Q/DD7c9uMMGbhFj4bVoEA\n"
    "wxhmMD95H0ROpL40vmcKq8HeTGBw/uWmtY/I7OnojYV8oiEDTmr8iqqyb8bqcdTk\n"
    "cEwjRTG2J+Y0PUJg6g==\n"
    "-----END CERTIFICATE-----\n";

unsigned char realFingerprint[] = {
    0x2c, 0xd5, 0x1a, 0x73, 0x47, 0x4f,
    0x69, 0xbb, 0xc4, 0x7c, 0x65, 0xbf,
    0xa7, 0x25, 0x3e, 0xd3, 0xc8, 0x77,
    0x4f, 0x7d, 0x6e, 0x8e, 0x1d, 0x29,
    0x5a, 0x5a, 0x45, 0x20, 0xca, 0x10,
    0xc4, 0x21
};

bool check_cert(void) {
    bool ret = true;
    size_t certLen = strlen(pemCertString);
    BIO* certBio   = BIO_new(BIO_s_mem());
    BIO_write(certBio, pemCertString, certLen);
    X509* certX509 = PEM_read_bio_X509(certBio, NULL, NULL, NULL);
    if (!certX509) {
        fprintf(stderr, "unable to parse certificate in memory\n");
        ret = 2;
        goto out;
    }
    const EVP_MD * fprint_type = EVP_sha256();
    unsigned int fprint_size;
    unsigned char fprint[EVP_MAX_MD_SIZE];
    if (!X509_digest(certX509, fprint_type, fprint, &fprint_size))
        printf("Error creating the certificate fingerprint.\n");

    for (unsigned j=0; j < fprint_size; ++j) {
        if (fprint[j] != realFingerprint[j]) {
            ret = 0;
            goto out;
        }
    }
out:
    BIO_free(certBio);
    X509_free(certX509);
    return ret;
}

bool check_empty() {
    return false;
}

