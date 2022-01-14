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

#define  CTE_LOAD   1
#define  CTE_WIPE   2
#define  CTE_KILL   3
#define  CTE_SYSTEM_FORCE  0x40
#define  CTE_FORCE  0x80

typedef unsigned char cte_wipe_policy;
typedef struct cte_rules {
    // Threshold Wiping
    int threshold;
    int min_wipe;

    // Length
    unsigned length;
    cte_wipe_policy policy[];
} cte_rules;

cte_rules *cte_rules_init(cte_wipe_policy def);
void cte_rules_free(cte_rules *);
unsigned cte_rules_set(cte_rules *,  cte_wipe_policy pol);
unsigned cte_rules_set_func(cte_rules *, cte_wipe_policy pol,  void *func, char children);


int cte_init(int flags);

int cte_mmview_unshare(void);

void cte_enable_threshold();
int cte_wipe_rules(cte_rules *rules);
static inline int cte_wipe() { return cte_wipe_rules(NULL); }



#define CTE_DUMP_TEXTS (1 << 0)
#define CTE_DUMP_FUNCS (1 << 1)
#define CTE_DUMP_FUNCS_LOADABLE (1 << 2)  // only together with CTE_DUMP_FUNCS

void cte_dump_state(int fd, unsigned flags);

struct cte_range {
    char *address;
    size_t length;
    size_t file_offset;
};
unsigned cte_get_wiped_ranges(struct cte_range *ranges);

#ifdef __cplusplus
}
#endif
