#ifdef __cplusplus
extern "C" {
#endif
// This is the public API of libcte

#pragma once

enum cte_error {
    CTE_ERROR_ELF = -1,
    CTE_ERROR_FORMAT = -2,
    CTE_ERROR_MPROTECT = -3,
    CTE_ERROR_SIGNAL = -4,
};

enum cte_flags {
    CTE_STRICT_CALLGRAPH = 1,
};

int cte_init(int flags);

int cte_mmview_unshare(void);

void cte_enable_threshold();
int cte_wipe_threshold(int threshold, int min_wipe);
#define cte_wipe() cte_wipe_threshold(0, 0)



#define CTE_DUMP_TEXTS (1 << 0)
#define CTE_DUMP_FUNCS (1 << 1)
#define CTE_DUMP_FUNCS_LOADABLE (1 << 2)  // only together with CTE_DUMP_FUNCS

void cte_dump_state(int fd, unsigned flags);

#ifdef __cplusplus
}
#endif
