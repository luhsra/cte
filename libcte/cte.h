#ifndef _CTE_H_
#define _CTE_H_

#ifdef __cplusplus
extern "C" {
#endif

    enum cte_error {
        CTE_ERROR_FORMAT = -1,
        CTE_ERROR_MPROTECT = -2,
        CTE_ERROR_SIGNAL = -3,
    };

    int cte_init(void);

    int cte_wipe(void);

#ifdef __cplusplus
}
#endif

#endif