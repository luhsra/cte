#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline long mmview_create(void) {
    return syscall(1000);
}

static inline long mmview_delete(long id) {
    return syscall(1003, id);
}

static inline long mmview_migrate(long id) {
    return syscall(1001, id);
}

static inline long mmview_current(void) {
    return syscall(1001, -1L);
}

static inline long mmview_unshare(void *start, size_t len) {
    return syscall(1002, start, len);
}

#ifdef __cplusplus
}
#endif
