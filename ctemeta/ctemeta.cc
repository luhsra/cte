#include <cstdint>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <string>
#include <utility>
#include <fstream>
#include "ctemeta.hh"
#include "util.hh"

int main(int argc, char *argv[]) {
    if (argc != 3)
        error(Error::IO, "Usage: ctmeta <input-binary> <output>\n");

    const char *in_filename = argv[1];
    const char *out_filename = argv[2];

    int fd = open(in_filename, O_RDONLY);
    if (fd < 0)
        error(Error::IO, "IO error: %s: %s\n", in_filename, strerror(errno));
    Cte cte = Cte::from_elf(fd);
    close(fd);

    cte.analyze();
    cte.propagate();

    int c_total = 0;
    int c_definition = 0;
    int c_address_taken = 0;
    int c_has_indirect_calls = 0;
    for (auto it = cte.functions.begin(); it != cte.functions.end(); it++) {
        Function &fn = it->second;
        c_total++;
        if (fn.definition)
            c_definition++;
        if (fn.address_taken)
            c_address_taken++;
        if (fn.has_indirect_calls)
            c_has_indirect_calls++;
    }
    info("total: %d, definition: %d, address_taken: %d, has_indirect_calls: %d\n",
         c_total, c_definition, c_address_taken, c_has_indirect_calls);

    auto buffer = cte.dump();
    auto myfile = std::ofstream(out_filename, std::ios::out | std::ios::binary);
    myfile.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    myfile.close();
    if (!myfile)
        error(Error::IO, "Cannot write: %s\n", out_filename);

    return 0;
}
