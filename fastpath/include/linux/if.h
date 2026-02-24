/*
 * Shadow header for <linux/if.h>
 * Provides IFNAMSIZ on FreeBSD.
 */
#ifndef _LINUX_IF_H_COMPAT_
#define _LINUX_IF_H_COMPAT_

#include <sys/socket.h>	/* struct sockaddr — needed before net/if.h */
#include <net/if.h>	/* FreeBSD IFNAMSIZ */

#endif
