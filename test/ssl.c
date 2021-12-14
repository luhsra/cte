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
#include <cte.h>
#include <time.h>

bool check_cert();
bool check_empty();


#define timespec_diff_ns(ts0, ts)   (((ts).tv_sec - (ts0).tv_sec)*1000LL*1000LL*1000LL + ((ts).tv_nsec - (ts0).tv_nsec))
int main(int argc, char *argv[]) {
    OpenSSL_add_all_algorithms();

    cte_init(0);

    unsigned int repeat = 1; 
    if (argc > 1) {
        repeat = atoi(argv[1]);
    }

    struct timespec ts0;
    struct timespec ts1;

    for (unsigned _i = 0; _i < repeat; _i ++) {
        unsigned count = 1000000;
        clock_gettime(CLOCK_REALTIME, &ts0);
        for (unsigned i = 0; i < count; i++) {
            check_empty();
        }
        clock_gettime(CLOCK_REALTIME, &ts1);
        printf("empty,plain,%f\n", timespec_diff_ns(ts0, ts1) / 1e6);
    }

    for (unsigned _i = 0; _i < repeat; _i ++) {
        unsigned count = 10000;
        clock_gettime(CLOCK_REALTIME, &ts0);
        for (unsigned i = 0; i < count; i++) {
            check_cert();
        }
        clock_gettime(CLOCK_REALTIME, &ts1);
        printf("ssl,plain,%f\n", timespec_diff_ns(ts0, ts1) / 1e6);
    }
}
