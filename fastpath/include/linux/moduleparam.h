/*
 * Shadow header for <linux/moduleparam.h> — all macros are no-ops.
 */
#ifndef _LINUX_MODULEPARAM_H_COMPAT_
#define _LINUX_MODULEPARAM_H_COMPAT_

#define module_param(name, type, perm)
#define module_param_named(name, value, type, perm)
#define MODULE_PARM_DESC(parm, desc)

#endif
