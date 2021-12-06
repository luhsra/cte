#include "syscall.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline long mmview_create(void) {
    return syscall(443);
}

static inline long mmview_delete(long id) {
    return syscall(446, id);
}

static inline long mmview_migrate(long id) {
    return syscall(444, id);
}

static inline long mmview_current(void) {
    return syscall(444, -1);
}

static inline long mmview_unshare(void *start, size_t len) {
    return syscall(445, start, len);
}

#ifdef __cplusplus
}
#endif
