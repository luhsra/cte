// This is the public API of libcte

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

enum cte_error {
    CTE_ERROR_ELF = -1,
    CTE_ERROR_FORMAT = -2,
    CTE_ERROR_MPROTECT = -3,
    CTE_ERROR_SIGNAL = -4,
};

int cte_init(void);

int cte_wipe(void);

#ifdef __cplusplus
}
#endif

