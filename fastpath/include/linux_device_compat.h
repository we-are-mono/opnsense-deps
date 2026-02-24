/*
 * Linux-to-FreeBSD kernel compatibility shim — device model stubs
 *
 * CDX uses Linux device_register/device_unregister in cdx_main.c for
 * a "cdx" pseudo-device. On FreeBSD, the KLD module itself serves this
 * role. These are stubbed out.
 *
 * Also stubs class_create/device_create used by cdx_dev.c (replaced
 * by make_dev on FreeBSD) and call_usermodehelper used by cdx_main.c
 * (replaced by rc.d scripts).
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _LINUX_DEVICE_COMPAT_H_
#define _LINUX_DEVICE_COMPAT_H_

/*
 * Stub Linux device model. CDX only uses these for sysfs presence
 * which is handled differently on FreeBSD (sysctl, devfs).
 */
struct device {
	const char *init_name;
	void (*release)(struct device *);
};

static inline int device_register(struct device *dev)
{
	return (0);
}

static inline void device_unregister(struct device *dev)
{
}

/* class_create / device_create — used by cdx_dev.c on Linux,
 * replaced by make_dev() on FreeBSD */
struct class;
#define class_create(owner, name)	((struct class *)1)	/* non-NULL stub */
#define class_destroy(cls)		do { } while (0)
#define device_create(cls, parent, devt, drvdata, fmt, ...) \
	((struct device *)1)	/* non-NULL stub */
#define device_destroy(cls, devt)	do { } while (0)

/* call_usermodehelper — cdx_main.c uses this to launch dpa_app at
 * module load. On FreeBSD, use rc.d script instead. */
#define UMH_WAIT_PROC		0
#define UMH_WAIT_EXEC		1
static inline int call_usermodehelper(const char *path, char **argv,
    char **envp, int wait)
{
	return (0);
}

#endif /* _LINUX_DEVICE_COMPAT_H_ */
