#include <cstdio>
#include <cstdarg>
#include <cstdlib>
#include <string>
#include "ctemeta.hh"
#include "util.hh"

const std::string ERROR = "\033[31mERROR:\033[0m ";
const std::string WARN = "\033[33mWARNING:\033[0m ";
const std::string INFO = "\033[32mINFO:\033[0m ";
const std::string DEBUG = "\033[34mDEBUG:\033[0m ";

LogLevel log_level = LogLevel::INFO;

bool dump_instructions = false;

void error(Error rc, const char *fmt, ...) {
    if (log_level >= LogLevel::ERROR) {
        va_list va;
        va_start(va, fmt);
        vfprintf(stderr, (ERROR + fmt).c_str(), va);
        va_end(va);
    }
    exit(static_cast<int>(rc));
}

void warn(const char *fmt, ...) {
    if (log_level >= LogLevel::WARN) {
        va_list va;
        va_start(va, fmt);
        vfprintf(stderr, (WARN + fmt).c_str(), va);
        va_end(va);
    }
}

void info(const char *fmt, ...) {
    if (log_level >= LogLevel::INFO) {
        va_list va;
        va_start(va, fmt);
        vfprintf(stderr, (INFO + fmt).c_str(), va);
        va_end(va);
    }
}

void debug(const char *fmt, ...) {
    if (log_level >= LogLevel::DEBUG) {
        va_list va;
        va_start(va, fmt);
        vfprintf(stderr, (DEBUG + fmt).c_str(), va);
        va_end(va);
    }
}
