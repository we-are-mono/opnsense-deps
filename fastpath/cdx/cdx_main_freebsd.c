/*
 * CDX module init/exit — FreeBSD port
 *
 * Replaces cdx_main.c.  Uses DECLARE_MODULE/DEV_MODULE instead of
 * module_init/module_exit.  Removes device_register (unnecessary on
 * FreeBSD).  Launches dpa_app from kernel context via fork1/kern_execve
 * (FreeBSD equivalent of Linux call_usermodehelper).
 *
 * Copyright 2014-2016 Freescale Semiconductor, Inc.
 * Copyright 2017-2018,2021 NXP
 * Copyright 2026 Mono Technologies Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/malloc.h>

#include "portdefs.h"
#include "cdx.h"
#include "cdx_cmdhandler.h"
#include "cdx_dpa_bridge.h"
#include "dpa_ipsec.h"

/* IP reassembly init/deinit (cdx_reassm_freebsd.c) */
extern void cdx_deinit_ip_reassembly(void);

/* Forwarding FQ diagnostics (cdx_devman_freebsd.c) */
extern void cdx_diag_dump_fwd_fqs(void);

/*
 * Define CDX global variables.  The prelude force-includes cdx.h
 * (which includes globals.h) before DEFINE_GLOBALS can be set,
 * so all globals end up as extern declarations.  Re-include
 * globals.h with the guard cleared and DEFINE_GLOBALS set to
 * actually allocate storage.
 */
#undef _GLOBALS_H_
#undef GLOBAL_DEFINE
#undef GLOBAL_INIT
#define DEFINE_GLOBALS
#include "globals.h"

MALLOC_DEFINE(M_ASK, "ask", "ASK CDX module");
MALLOC_DEFINE(M_CDX, "cdx", "CDX IPsec allocations");

/* RCU lock used by linux_mutex_compat.h */
struct sx ask_rcu_lock;

static uint32_t init_level;
static cdx_deinit_func deinit_fn[MAX_CDX_INIT_FUNCTIONS];

void
register_cdx_deinit_func(cdx_deinit_func func)
{
	if (init_level == MAX_CDX_INIT_FUNCTIONS) {
		printf("%s: can't register deinit function, "
		    "increase MAX_CDX_INIT_FUNCTIONS\n", __func__);
		return;
	}
	deinit_fn[init_level] = func;
	init_level++;
}

static void
cdx_ctrl_deinit(void)
{
	struct _cdx_ctrl *ctrl = &cdx_info->ctrl;

	mutex_lock(&ctrl->mutex);
	cdx_cmdhandler_exit();
	mutex_unlock(&ctrl->mutex);
}

static int
cdx_ctrl_init(struct _cdx_info *info)
{
	struct _cdx_ctrl *ctrl = &info->ctrl;
	int rc;

	mutex_init(&ctrl->mutex);
	spin_lock_init(&ctrl->lock);
	INIT_WORK(&ctrl->work, comcerto_fpp_workqueue);
	INIT_LIST_HEAD(&ctrl->msg_list);

	ctrl->dev = &info->dev;
	rc = cdx_ctrl_timer_init(ctrl);
	if (rc)
		goto error;

	mutex_lock(&ctrl->mutex);
	rc = cdx_cmdhandler_init();
	mutex_unlock(&ctrl->mutex);

	/* Timer thread already started by kthread_add in timer_init */

	register_cdx_deinit_func(cdx_ctrl_deinit);
error:
	return (rc);
}

/* Forward declarations — cdx_sysctl.c */
int cdx_init_fqid_procfs(void);
void cdx_sysctl_init(void);
void cdx_sysctl_fini(void);

/* Forward declarations — cdx_qos_freebsd.c */
int cdx_qos_init_ff_profiles(void);
void cdx_qos_cleanup_ff_profiles(void);

/* cdx_usermodehelper.c */
extern int cdx_call_usermodehelper(const char *path, char *const argv[],
    char *const envp[], int *statusp);

/*
 * start_dpa_app — Launch dpa_app from kernel context.
 *
 * dpa_app opens /dev/fm0*, programs FMan PCD via FMC (from XML configs
 * at /etc/cdx_*.xml), then sends CDX_CTRL_DPA_SET_PARAMS ioctl to
 * /dev/cdx_ctrl.  The ioctl handler (cdx_dpa_takeover.c) binds the
 * NCSW hash tables to CDX enhanced format via ExternalHashTableBindNCSW.
 *
 * This is the FreeBSD equivalent of Linux's start_dpa_app() which
 * uses call_usermodehelper(UMH_WAIT_PROC).
 */
static int
start_dpa_app(void)
{
	static char *dpa_app_path = "/usr/local/sbin/dpa_app";
	static char *argv[] = { "/usr/local/sbin/dpa_app", NULL };
	static char *envp[] = {
		"HOME=/",
		"TERM=dumb",
		"PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/sbin",
		NULL
	};
	int error;

	printf("cdx: launching %s\n", dpa_app_path);
	error = cdx_call_usermodehelper(dpa_app_path, argv, envp, NULL);
	if (error != 0)
		printf("cdx: %s failed: %d\n", dpa_app_path, error);
	else
		printf("cdx: %s completed successfully\n", dpa_app_path);

	return (error);
}

static void
cdx_module_deinit(void)
{
	int ii;

	cdx_sysctl_fini();

	if (init_level > 0) {
		ii = (int)(init_level - 1);
		while (1) {
			if (deinit_fn[ii])
				deinit_fn[ii]();
			if (ii == 0)
				break;
			ii--;
		}
	}
	kfree(cdx_info);
}

static int
cdx_module_init(void)
{
	int rc = 0;
	int ii;

	printf("cdx: initializing CDX module\n");

	for (ii = 0; ii < MAX_CDX_INIT_FUNCTIONS; ii++)
		deinit_fn[ii] = NULL;
	init_level = 0;

	cdx_info = kzalloc(sizeof(struct _cdx_info), GFP_KERNEL);
	if (!cdx_info) {
		printf("cdx: error allocating cdx_info\n");
		return (-ENOMEM);
	}

	/* Skip device_register — KLD module itself is the presence indicator */

	/*
	 * Initialize sysctl tree early so that cdx_sysctl_fini() in the
	 * cleanup path always has a valid context, even if init fails
	 * before the module is fully operational.
	 */
	cdx_sysctl_init();

	rc = cdx_ctrl_init(cdx_info);
	if (rc != 0) {
		printf("cdx: cdx_ctrl_init failed\n");
		goto exit;
	}

	rc = devman_init_linux_stats();
	if (rc != 0) {
		printf("cdx: devman_init_linux_stats failed\n");
		goto exit;
	}

	/*
	 * Discover FMan/dtsec handles and populate fman_info globals.
	 * Hash tables are NOT created here — dpa_app (via start_dpa_app)
	 * programs FMan PCD and registers tables via ioctl.
	 */
	rc = cdx_dpa_bridge_init();
	if (rc != 0) {
		printf("cdx: cdx_dpa_bridge_init failed\n");
		goto exit;
	}
	register_cdx_deinit_func(cdx_dpa_bridge_destroy);

	/*
	 * Create fast-forward policer profiles for all dtsec ports.
	 * Must happen after cdx_dpa_bridge_init() (PCD handle available)
	 * and before start_dpa_app() (which calls FM_PORT_SetPCD).
	 * The kernel already called FM_PORT_PcdPlcrAllocProfiles(rxph, 1)
	 * at boot, so the profile slots are reserved.
	 */
	cdx_qos_init_ff_profiles();
	register_cdx_deinit_func(cdx_qos_cleanup_ff_profiles);

	rc = cdx_driver_init();
	if (rc != 0) {
		printf("cdx: cdx_driver_init failed\n");
		goto exit;
	}

	cdx_init_fqid_procfs();

	/*
	 * Launch dpa_app to program FMan PCD and register hash tables.
	 * Must happen after cdx_driver_init() (creates /dev/cdx_ctrl
	 * that dpa_app sends the ioctl to) and after
	 * cdx_dpa_bridge_init() (fman discovery).
	 */
	rc = start_dpa_app();
	if (rc != 0) {
		printf("cdx: start_dpa_app failed\n");
		goto exit;
	}

	/*
	 * Register all dtsec interfaces in CDX onif table.
	 * Must happen after start_dpa_app() (hash tables now bound in
	 * CDX enhanced format).  This is the FreeBSD equivalent of
	 * Linux dpa_cfg.c calling cdx_add_eth_onif().
	 */
	rc = cdx_dpa_bridge_register_dtsec();
	if (rc != 0) {
		printf("cdx: dtsec registration failed: %d\n", rc);
		goto exit;
	}

	/* VWD (Virtual WiFi Driver) not applicable — no WiFi offload */

	/*
	 * Initialize frag/common-db module: allocates MURAM block for
	 * the microcode common database (frag params + DSCP-to-FQID map).
	 * Every hash table entry's ENQUEUE_PKT opcode references this
	 * MURAM block via word2.  Without it, word2 contains a garbage
	 * pointer and the microcode reads corrupt data.
	 *
	 * On FreeBSD, CDX_FRAG_USE_BUFF_POOL is not defined, so the
	 * fragment buffer pool creation is skipped — only the MURAM
	 * common database is allocated and zero-initialized.
	 */
	if (cdx_init_frag_module()) {
		printf("cdx: cdx_init_frag_module failed\n");
		/* Non-fatal for init, but flow offload will not work */
	}

	/*
	 * Initialize IP reassembly: create BMan pools, TX-confirm FQR,
	 * start timer thread, configure EHASH tables.
	 * Must run after start_dpa_app() (needs ipr_info from ioctl).
	 */
	if (cdx_init_ip_reassembly()) {
		printf("cdx: cdx_init_ip_reassembly failed\n");
		/* Non-fatal — flow offload works without reassembly */
	}
	register_cdx_deinit_func(cdx_deinit_ip_reassembly);

	/* IPsec SA management done via FCI/CMM path (dpa_ipsec_freebsd.c) */

exit:
	if (rc) {
		printf("cdx: module initialization FAILED\n");
		cdx_module_deinit();
	}
	return (rc);
}

static int
cdx_modevent(module_t mod, int type, void *unused)
{
	switch (type) {
	case MOD_LOAD:
		sx_init(&ask_rcu_lock, "ask_rcu");
		return (cdx_module_init());

	case MOD_UNLOAD:
		printf("cdx: unloading CDX module\n");
		cdx_diag_dump_fwd_fqs();
		cdx_module_deinit();
		sx_destroy(&ask_rcu_lock);
		return (0);

	default:
		return (EOPNOTSUPP);
	}
}

DEV_MODULE(cdx, cdx_modevent, NULL);
MODULE_VERSION(cdx, 1);
MODULE_DEPEND(cdx, fci, 1, 1, 1);
