#pragma once

#include "cte-impl.h"

#ifdef CONFIG_PRINT
CTE_ESSENTIAL int cte_vsprintf(char * buf, const char * fmt, va_list va);
CTE_ESSENTIAL int cte_sprintf(char * buf, const char * fmt, ...);
CTE_ESSENTIAL int cte_fdprintf(int fd, const char * fmt, ...);
#define cte_printf(...) cte_fdprintf(1, __VA_ARGS__)
#define cte_debug(...) cte_fdprintf(2, "DEBUG: " __VA_ARGS__)
#define cte_die(...) do { cte_fdprintf(2, "ERROR: "  __VA_ARGS__); asm("int3"); } while(0)
#else
#define cte_vsprintf(...) 0
#define cte_sprintf(...) 0
#define cte_fdprintf(...) 0
#define cte_printf(...)
#define cte_debug(...)
#define cte_die(...) asm("int3")
#endif
