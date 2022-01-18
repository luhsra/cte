#include <iostream>
#include <unistd.h>
#include <string>
#include <utility>
#include <fstream>
#include "ctemeta.hh"
#include "util.hh"

void info_stat(Cte &cte) {
    int c_total = 0;
    int c_definition = 0;
    int c_address_taken = 0;
    int c_has_indirect_calls = 0;
    for (auto &it : cte.functions) {
        Function &fn = it.second;
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
}

void write_file(Cte &cte, const char *filename) {
    auto buffer = cte.dump();
    auto myfile = std::ofstream(filename, std::ios::out | std::ios::binary);
    myfile.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    myfile.close();
    if (!myfile)
        error(Error::IO, "Cannot write: %s\n", filename);
    info("Written: %s\n", filename);
}

void print_usage() {
    std::cerr << "USAGE: ctemeta [options] <input file> [<output file>]\n\n"
              << "OPTIONS:\n"
              << "  -i            Print instructions\n"
              << "  -c            Print callgraph information\n"
              << "  -k            Keep sizes: Do not aggressively enlarge functions\n"
              << "  -l <level>    Set log level to <level>\n"
              << "                <level>: none, error, warn, info, debug\n"
              << "                The default log level is 'info'\n"
              << "  -h            Print help message\n\n";
}

int main(int argc, char *argv[]) {
    const char *in_filename = NULL;
    const char *out_filename = NULL;
    bool print_cgraph = false;

    while (true) {
        int result = getopt(argc, argv, "ickl:h");
        if (result == -1)
            break;
        switch (result) {
        case '?':
        case ':':
            print_usage();
            return 255;
        case 'i':
            dump_instructions = true;
            break;
        case 'c':
            print_cgraph = true;
            break;
        case 'k':
            keep_sizes = true;
            break;
        case 'l': {
            std::string optstr = optarg;
            if (optstr == "none")
                log_level = LogLevel::NONE;
            else if (optstr == "error")
                log_level = LogLevel::ERROR;
            else if (optstr == "warn")
                log_level = LogLevel::WARN;
            else if (optstr == "info")
                log_level = LogLevel::INFO;
            else if (optstr == "debug")
                log_level = LogLevel::DEBUG;
            else {
                std::cerr << argv[0] << ": Invalid log level\n";
                print_usage();
                return 255;
            }
            break;
        }
        case 'h':
            print_usage();
            return 0;
        default:
            break;
        }
    }
    if (optind == argc) {
        std::cerr << argv[0] << ": Missing input file\n";
        print_usage();
        return 255;
    } else {
        in_filename = argv[optind++];
    }
    if (optind < argc) {
        out_filename = argv[optind++];
    }
    if (optind < argc) {
        std::cerr << argv[0] << ": Too many arguments\n";
        print_usage();
        return 255;
    }

    // Run cte
    Cte cte = Cte::from_elf(in_filename);
    cte.analyze();
    cte.propagate();

    // Output results
    info_stat(cte);
    if (out_filename)
        write_file(cte, out_filename);
    if (print_cgraph)
        cte.print(std::cout);

    return 0;
}
