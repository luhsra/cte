#pragma once

enum class Error {
    IO = 1,
    ELF = 2,
    CODE = 3,
};

enum class LogLevel {
  NONE = 0,
  ERROR = 1,
  WARN = 2,
  INFO = 3,
  DEBUG = 4,
};

extern LogLevel log_level;
extern bool dump_instructions;

__attribute__((format(printf, 2, 3)))
void error(Error rc, const char *fmt, ...);

__attribute__((format(printf, 1, 2)))
void warn(const char *fmt, ...);

__attribute__((format(printf, 1, 2)))
void info(const char *fmt, ...);

__attribute__((format(printf, 1, 2)))
void debug(const char *fmt, ...);
