#include <stdio.h>
#include <stdint.h>
#include <cte.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>


__attribute__((weak))
int foo (void)  {
    return 1;
}

__attribute__((weak))
int bar (void)  {
    return foo() + 1;
}

int main(void) {
    int rc = cte_init(0);
    if (rc < 0) {
        perror("CTE Error");
        return 2;
    }

    int x = 0;

    cte_rules *R0 = cte_rules_init(CTE_KILL);
    x += cte_rules_set_func(R0, CTE_WIPE, &foo, 0);
    x += cte_rules_set_func(R0, CTE_WIPE, &bar, 0);
    printf("R0: length: %u, wiped: %d\n", R0->length, x);

    cte_rules *R1 = cte_rules_init(CTE_WIPE);

    cte_wipe_rules(R0);

    bar();

    cte_wipe_rules(R1);

    cte_dump_state(0, CTE_DUMP_TEXTS);

    return 0;
}
