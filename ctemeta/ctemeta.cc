#include <cstdint>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <string>
#include <utility>
#include "ctemeta.hh"
#include "util.hh"

int main(int argc, char *argv[]) {
    if (argc != 2)
        error(Error::IO, "Argument error");

    const char *filename = argv[1];

    int fd = open(filename, O_RDONLY);
    if (fd < 0)
        error(Error::IO, "IO error: %s: %s\n", filename, strerror(errno));

    Cte cte = Cte::from_elf(fd);

    close(fd);

    cte.analyze();

    int c_total = 0;
    int c_definition = 0;
    int c_address_taken = 0;
    for (auto it = cte.functions.begin(); it != cte.functions.end(); it++) {
        Function &fn = it->second;
        c_total++;
        if (fn.definition)
            c_definition++;
        if (fn.address_taken)
            c_address_taken++;

        printf("%s %s%s%s\n", fn.str().c_str(),
               (fn.definition) ? "" : " extern",
               (fn.address_taken) ? " address-taken" : "",
               (fn.has_indirect_calls) ? " icalls" : "");
        for (auto a = fn.siblings.begin(); a != fn.siblings.end(); a++) {
            Function &cf = cte.functions.at(*a);
            printf("  S -> %s\n", cf.str().c_str());
        }
        for (auto a = fn.callees.begin(); a != fn.callees.end(); a++) {
            Function &cf = cte.functions.at(*a);
            printf("  C -> %s\n", cf.str().c_str());
        }
        for (auto a = fn.jumpees.begin(); a != fn.jumpees.end(); a++) {
            Function &cf = cte.functions.at(*a);
            printf("  J -> %s\n", cf.str().c_str());
        }
    }
    printf("total: %d, definition: %d, address_taken: %d\n",
           c_total, c_definition, c_address_taken);

    return 0;
}
