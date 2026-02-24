/*
 *  Copyright 2022 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#ifdef CONFIG_PROC_FS
#include "procfs.h"
#include <linux/slab.h>

static struct proc_dir_entry *proc_fqid_dir = NULL ;
static struct proc_dir_entry *proc_tx_dir = NULL ;
static struct proc_dir_entry *proc_rx_dir = NULL ;
static struct proc_dir_entry *proc_pcd_dir = NULL ;
static struct proc_dir_entry *proc_sa_dir = NULL ;
static struct fqid_file_list_node_s *fqid_files_g = NULL;

static ssize_t proc_fqid_stats_read(struct file *fp, char __user *buff, size_t size, loff_t *ppos)
{
	struct qman_fq *fq_info = NULL;
	struct qm_mcr_queryfq_np np;
	struct qm_fqd fqd_inst,*fqd;
	struct fqid_file_list_node_s *node;
	int len = 0;
	uint8_t *name;

	name = (uint8_t *)fp->f_path.dentry->d_name.name;

	if (*ppos)
		return 0;

	node = PDE_DATA(file_inode(fp));
	printk("%s()::%d node %p\n", __func__, __LINE__, node);

	if (!node || !node->fq)
	{
		len += sprintf(buff, "===========================================\n::file %s\n", name);
		len += sprintf(buff + len, "corresponding FQ ID not created by CDX module\n");
		*ppos +=len;
		return len;
	}

	fq_info = node->fq;		
	len += sprintf(buff, "===========================================\n::fqid %x(%d)\n", node->fqid, node->fqid);
	if (qman_query_fq(fq_info, &fqd_inst)) {
		len += sprintf(buff + len, "error getting fq fields\n");
		*ppos +=len;
		return len;
	}
	fqd = &fqd_inst;
	len += sprintf(buff+len, "fqctrl\t%x\n", fqd->fq_ctrl);
	len += sprintf(buff+len, "channel\t%x\n", fqd->dest.channel);
	len += sprintf(buff+len, "Wq\t%d\n", fqd->dest.wq);
	len += sprintf(buff+len, "contextb\t%x\n", fqd->context_b);
	len += sprintf(buff+len, "contexta\t%p\n", (void *)fqd->context_a.opaque);
	if (qman_query_fq_np(fq_info, &np)) {
		len += sprintf(buff + len, "error getting fq fields\n");
		*ppos +=len;
		return len;
	}
	len += sprintf(buff+len, "state\t%d\n", np.state);
	len += sprintf(buff+len, "byte count\t%d\n", np.byte_cnt);
	len += sprintf(buff+len, "frame count\t%d\n", np.frm_cnt);
	*ppos +=len;
	return len;
}

static const struct file_operations proc_fqid_stats = {
         .owner          = THIS_MODULE,
         .read           = proc_fqid_stats_read,
};


int cdx_init_fqid_procfs(void)
{
	proc_fqid_dir = proc_mkdir("fqid_stats", NULL);
	if (!proc_fqid_dir)
	{
		printk("%s(%d) proc_mkdir failed \n",__FUNCTION__,__LINE__);
		return -1;
	}

	proc_tx_dir = proc_mkdir("tx", proc_fqid_dir);
	if (!proc_tx_dir)
	{
		printk("%s(%d) proc_mkdir failed \n",__FUNCTION__,__LINE__);
		return -1;
	}

	proc_pcd_dir = proc_mkdir("pcd", proc_fqid_dir);
	if (!proc_pcd_dir)
	{
		printk("%s(%d) proc_mkdir failed \n",__FUNCTION__,__LINE__);
		return -1;
	}

	proc_rx_dir = proc_mkdir("rx", proc_fqid_dir);
	if (!proc_rx_dir)
	{
		printk("%s(%d) proc_mkdir failed \n",__FUNCTION__,__LINE__);
		return -1;
	}

	proc_sa_dir = proc_mkdir("sa", proc_fqid_dir);
	if (!proc_sa_dir)
	{
		printk("%s(%d) proc_mkdir failed \n",__FUNCTION__,__LINE__);
		return -1;
	}

	return 0;
}

int cdx_create_dir_in_procfs(void **proc_dir_entry, char *name,uint32_t type)
{
	cdx_proc_dir_entry_t *proc_entry;
	struct proc_dir_entry *proc_parent_dir_entry;
	char parent_dir[16]="";

	switch(type)
	{
		case TX_DIR:
			proc_parent_dir_entry = proc_tx_dir;
			strcpy(parent_dir, "tx");
			break;

		case RX_DIR:
			proc_parent_dir_entry = proc_rx_dir;
			strcpy(parent_dir, "rx");
			break;

		case PCD_DIR:
			proc_parent_dir_entry = proc_pcd_dir;
			strcpy(parent_dir, "pcd");
			break;

		case SA_DIR:
			proc_parent_dir_entry = proc_sa_dir;
			strcpy(parent_dir, "sa");
			break;

		default:
			printk("%s()::%d Invalid type %d\n", __func__, __LINE__, type);
			return -1;

	}

	if((proc_entry = kmalloc(sizeof(cdx_proc_dir_entry_t), GFP_KERNEL)) == NULL)
	{
		printk("%s()::%d memory allocation failure:\n", __func__, __LINE__);
		return -1;
	}

	proc_entry->proc_dir = proc_mkdir(name, proc_parent_dir_entry);
	if (!proc_entry->proc_dir)
	{
		printk("%s(%d) proc_mkdir failed \n",__FUNCTION__,__LINE__);
		return -1;
	}
	printk("/proc/fqid_stats/%s/%s directory created.\n", parent_dir,name);
	*proc_dir_entry = (void *)proc_entry;
	printk("%s()::%d proc_entry %p proc dir %p\n", __func__, __LINE__, proc_entry, proc_entry->proc_dir);

	return 0;
}

void cdx_remove_fqid_info_in_procfs(uint32_t fqid)
{
	struct fqid_file_list_node_s *node;

	node = fqid_files_g;
	while (node)
	{
		if (node->fqid == fqid)
		{
			proc_remove(node->proc_fs);
			if (node == fqid_files_g)
			{
				fqid_files_g = 
					(struct fqid_file_list_node_s *)fqid_files_g->list.next;
				break;
			}
			node->list.prev->next = node->list.next;
			if (node->list.next)
				node->list.next->prev = node->list.prev;
			break;
		}
		node = (struct fqid_file_list_node_s *)node->list.next;
	}
	if (node)
		kfree(node);
	else
		printk("ERROR:: unable to find fqid %d node\n", fqid);
	return;
}

static int cdx_create_fq_in_procfs(struct qman_fq *fq, 
		struct proc_dir_entry *proc_dir, uint8_t *fq_alias_name/*, 
		struct fqid_file_list_node_s **fqid_file_list*/)
{
	struct fqid_file_list_node_s *node;

	if (!proc_dir)
	{
		printk("%s(%d) Proc Dir is not present.\n", __FUNCTION__,__LINE__);
		return -1;
	}

	if((node = kmalloc(sizeof(struct fqid_file_list_node_s), GFP_KERNEL)) == NULL)
	{
		printk("%s()::%d memory allocation failed:\n", __func__, __LINE__);
		return -1;
	}

	memset(node, 0, sizeof(struct fqid_file_list_node_s ));
	node->fqid = fq->fqid;
	if (fq_alias_name)
		sprintf(node->name,"%d_%s",fq->fqid, fq_alias_name);
	else
		sprintf(node->name,"%d",fq->fqid);
	node->fq = fq;
	node->proc_fs = proc_create_data(node->name, 0444,proc_dir,  &proc_fqid_stats, node);
	if (!node->proc_fs)
	{
		kfree(node);
		printk("%s(%d) proc_create_data failed\n",__FUNCTION__,__LINE__);
		return -1;
	}
	if (fqid_files_g)
	{
		node->list.next = (struct dlist_head *)fqid_files_g;
		fqid_files_g->list.prev = (struct dlist_head *)node;
	}
	fqid_files_g = node;

	return 0;
}

int cdx_create_type_fqid_info_in_procfs(struct qman_fq *fq, uint32_t type, void *proc_entry, uint8_t *fq_alias_name)
{
	struct proc_dir_entry *proc_dir;

	if (!proc_entry)
		type = UNSPECIFIED;

	switch(type)
	{
		case UNSPECIFIED:
			proc_dir = proc_fqid_dir;
	 		printk("Going to create /proc/fqid_stats/%d \n", fq->fqid);
			break;

		case RX_DIR:
		case TX_DIR:
		case PCD_DIR:
		case SA_DIR:
			proc_dir = ((cdx_proc_dir_entry_t *)proc_entry)->proc_dir;
			break;

		default:
	 		printk("%s():%d Invalid type %d \n", __func__, __LINE__, type);
			return -1;

	}
	if (cdx_create_fq_in_procfs(fq, proc_dir/*, &fqid_files_g*/, fq_alias_name) != 0)
	{
		printk("%s()::%d failed to create fq in /proc/fqid_stats:\n", __func__, __LINE__);
		return -1;
	}
	return 0;
}

#endif /* endif for #ifdef CONFIG_PROC_FS */
