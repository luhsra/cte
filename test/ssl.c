#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <cte.h>
#include <time.h>
#include <mmview.h>
#include <fcntl.h>
#include <unistd.h>

#include "cte_mprotect.h"

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

__attribute__((weak))
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


__attribute__((weak))
bool check_cert_wipe(long mmview)  {
    long previous = mmview_migrate(mmview);
    // printf("%ld -> %ld\n",  previous, mmview);
    bool ret = check_cert();
    int rc = mmview_migrate(previous); (void) rc;
    // printf("%ld -> %ld (%ld)\n",  mmview, rc, previous);

    return ret;
}

__attribute__((weak))
bool check_cert_mprotect(struct cte_range*range, unsigned ranges)  {
    cte_range_mprotect(range, ranges, PROT_READ);
    bool ret = check_cert();
    cte_range_mprotect(range, ranges, PROT_READ|PROT_EXEC);
    return ret;
}

#define SSL_ROUNDS  10000


#define timespec_diff_ns(ts0, ts)   (((ts).tv_sec - (ts0).tv_sec)*1000LL*1000LL*1000LL + ((ts).tv_nsec - (ts0).tv_nsec))
int main(int argc, char *argv[]) {

    OpenSSL_add_all_algorithms();

    unsigned int repeat = 1;
    if (argc > 1) {
        repeat = atoi(argv[1]);
    }

    struct timespec ts0;
    struct timespec ts1;

    for (unsigned _i = 0; _i < repeat; _i ++) {
        clock_gettime(CLOCK_REALTIME, &ts0);
        for (unsigned i = 0; i < SSL_ROUNDS; i++) {
            check_cert();
        }
        clock_gettime(CLOCK_REALTIME, &ts1);
        fprintf(stderr, "ssl,plain,%f,%d\n", timespec_diff_ns(ts0, ts1) / 1e6, SSL_ROUNDS);
    }


    // And now with mmview and libcte
    cte_init(CTE_STRICT_CALLGRAPH | CTE_STRICT_CTEMETA);
    cte_mmview_unshare();
    long global_mmview, ssl_mmview;
    long previous;
    int fd;

    global_mmview = mmview_current();
    ssl_mmview = mmview_create();

    // Prepare Function mmview
    {
        cte_rules *R = cte_rules_init(CTE_KILL);
        unsigned x = 0;
        x += cte_rules_set_indirect(R, CTE_WIPE);
        x += cte_rules_set_func(R, CTE_WIPE, &check_cert_wipe, 1);
        cte_rules_set_func(R, CTE_LOAD, &check_cert_wipe, 0);
        // cte_rules_set_func(R, CTE_LOAD, &check_cert_mprotect, 0);
        printf("CTE_WIPE: %d funcs\n", x);

        long previous = mmview_migrate(ssl_mmview);
        cte_wipe(R);
        mmview_migrate(previous);
        cte_rules_free(R);
    }


    check_cert_wipe(ssl_mmview);
    for (unsigned _i = 0; _i < repeat; _i ++) {
        clock_gettime(CLOCK_REALTIME, &ts0);
        for (unsigned i = 0; i < SSL_ROUNDS; i++) {
            check_cert_wipe(ssl_mmview);
        }
        clock_gettime(CLOCK_REALTIME, &ts1);
        fprintf(stderr, "ssl,migrate,%f,%d\n", timespec_diff_ns(ts0, ts1) / 1e6, SSL_ROUNDS);
    }

    struct cte_range *ranges = malloc(sizeof(struct cte_range) * 10000); 
    fd = open("ssl.migrate.dict", O_RDWR|O_CREAT|O_TRUNC, 0644);
    cte_dump_state(fd, 0);
    previous = mmview_migrate(ssl_mmview); 
    cte_dump_state(fd, CTE_DUMP_FUNCS|CTE_DUMP_TEXTS);
    unsigned range_count = cte_get_wiped_ranges(ranges);
    mmview_migrate(previous);
    if (mmview_delete(ssl_mmview) == -1) die("mmview_delete");

    unsigned mprotect_count=0, mprotect_bytes=0;
    cte_range_stat(ranges, range_count, mprotect_count, mprotect_bytes);
    printf("mprotect Ranges: %d, %d\n", mprotect_count, mprotect_bytes);

    for (unsigned _i = 0; _i < repeat; _i ++) {
        clock_gettime(CLOCK_REALTIME, &ts0);
        for (unsigned i = 0; i < SSL_ROUNDS; i++) {
            check_cert_mprotect(ranges, range_count);
        }
        clock_gettime(CLOCK_REALTIME, &ts1);
        fprintf(stderr, "ssl,mprotect,%f,%d,%d,%d\n", timespec_diff_ns(ts0, ts1) / 1e6, SSL_ROUNDS,
                mprotect_count, mprotect_bytes);
    }

    close(fd);
}
