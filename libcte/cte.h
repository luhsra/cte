#ifndef _CTE_H_
#define _CTE_H_

enum cte_error {
    CTE_ERROR_ELF = -1,
    CTE_ERROR_FORMAT = -2,
    CTE_ERROR_MPROTECT = -3,
    CTE_ERROR_SIGNAL = -4,
};

int cte_init(void);

int cte_wipe(void);

#endif
