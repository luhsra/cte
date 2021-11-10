#pragma once

#include "cte-impl.h"

CTE_ESSENTIAL int cte_vsprintf(char * buf, const char * fmt, va_list va);
CTE_ESSENTIAL int cte_sprintf(char * buf, const char * fmt, ...);
CTE_ESSENTIAL int cte_fdprintf(int fd, const char * fmt, ...);
#define cte_printf(fmt,...) cte_fdprintf(1, fmt, __VA_ARGS__)


