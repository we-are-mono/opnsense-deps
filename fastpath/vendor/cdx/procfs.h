/*
 *  Copyright 2022 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
#ifdef CONFIG_PROC_FS

#include <linux/version.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/proc_fs.h>
#include <linux/fsl_bman.h>
#include <linux/fsl_qman.h>
#include "list.h"

struct fqid_file_list_node_s
{
	struct dlist_head list;
	uint32_t fqid;
	uint8_t name[50];
	struct qman_fq *fq;
	struct proc_dir_entry *proc_fs;
};

typedef struct cdx_proc_dir_entry_s
{
	struct proc_dir_entry *proc_dir;
}cdx_proc_dir_entry_t;

enum {
	UNSPECIFIED, /* unspecified  0 */
	TX_DIR, /* TX 1 */
	RX_DIR, /* RX 2 */
	PCD_DIR, /* PCD 3 */
	SA_DIR, /* SA 4 */
};


int cdx_init_fqid_procfs(void);
void cdx_remove_fqid_info_in_procfs(uint32_t fqid);
ssize_t read_fqid4stats(struct file *fp, char __user *buff, size_t size, loff_t *ppos);
void cdx_create_fqid_info_in_procfs(uint32_t fqid, struct qman_fq *fq);
int cdx_create_dir_in_procfs(void **proc_dir_entry, char *name,uint32_t type);
int cdx_create_type_fqid_info_in_procfs(struct qman_fq *fq, uint32_t type, 
			void *tx_fwd_fq_proc_entry, uint8_t *fq_alias_name);

#endif /* endif for #ifdef CONFIG_PROC_FS */
