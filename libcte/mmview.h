#ifndef MMVIEW_H
#define MMVIEW_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/syscall.h>

#define SYS_mmview		1000

/*
 * mmview() operations:
 */
#define MMVIEW_CREATE		0
#define MMVIEW_DELETE		1
#define MMVIEW_CURRENT		2
#define MMVIEW_MIGRATE		3
#define MMVIEW_UNSHARE		4
#define MMVIEW_SHARE		5
#define MMVIEW_SWITCH_BASE	6

#define mmview_create() 		syscall(SYS_mmview, MMVIEW_CREATE)
#define mmview_delete(id) 		syscall(SYS_mmview, MMVIEW_DELETE, (long) (id))
#define mmview_current() 		syscall(SYS_mmview, MMVIEW_CURRENT)
#define mmview_migrate(id)		syscall(SYS_mmview, MMVIEW_MIGRATE, (long) (id))
#define mmview_unshare(start, len)	syscall(SYS_mmview, MMVIEW_UNSHARE, (void *) (start), (size_t) (len))
#define mmview_share(start, len)	syscall(SYS_mmview, MMVIEW_SHARE, (void *) (start), (size_t) (len))
#define mmview_switch_base()		syscall(SYS_mmview, MMVIEW_SWITCH_BASE)

#ifdef __cplusplus
}
#endif

#endif
