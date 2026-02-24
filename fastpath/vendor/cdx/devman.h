/*
 * Copyright 2018,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

int devman_init_linux_stats(void);
int dpa_get_num_vlan_iface_stats_entries(uint32_t iif_index,
			uint32_t underlying_iif_index, uint32_t *num_entries);
int dpa_get_fm_port_index(uint32_t itf_index, uint32_t underlying_iif_index , 
			uint32_t *fm_index, uint32_t *port_index, uint32_t *portid);
int dpa_get_iface_stats_entries(uint32_t iif_index,
			uint32_t underlying_iif_index, uint8_t *offset,
			uint32_t stats_type, uint32_t iface_type);
int dpa_get_tx_l2info_by_itf(struct dpa_l2hdr_info *l2_info, POnifDesc itf, uint32_t hash);
int dpa_check_for_logical_iface_types(struct _itf *input_itf, 
			struct _itf *underlying_input_itf,
			struct dpa_l2hdr_info *l2_info,
			struct dpa_l3hdr_info *l3_info);
int dpa_get_tx_fqid_by_name(char *name, uint32_t *fqid, uint8_t *is_dscp_fq_map, uint32_t hash);
int dpa_get_out_tx_info_by_itf_id(PRouteEntry rt_entry , 
				struct dpa_l2hdr_info *l2_info,
				struct dpa_l3hdr_info *l3_info);
int dpa_get_iface_info_by_ipaddress(int sa_family, uint32_t  *daddr, uint32_t * tx_fqid,
		uint32_t * itf_id, uint32_t * portid , void **netdev, uint32_t hash);
int dpa_get_mac_addr(char *name, char *mac_addr);
uint32_t dpa_get_timestamp_addr(uint32_t id);

int dpa_add_eth_if(char *name, struct _itf *itf, struct _itf *phys_itf); 
int dpa_add_pppoe_if(char *name, struct _itf *itf, struct _itf *phys_itf, 
		uint8_t *mac_addr, uint16_t session_id);
int dpa_add_vlan_if(char *name, struct _itf *itf, struct _itf *phys_itf, uint16_t vlan_id, uint8_t *mac_addr);
int dpa_add_wlan_if(char *name, struct _itf *itf, uint32_t vap_id, unsigned char* mac);
int dpa_update_wlan_if(struct _itf *itf, unsigned char* mac);
int dpa_set_bridged_itf(uint8_t* ifname, uint8_t is_bridged, uint8_t* br_mac_addr);
void dpa_release_interface(uint32_t itf_id);

int ExternalHashTableAddKey(void *h_HashTbl, uint8_t keySize,
		void *tbl_entry);
int ExternalHashTableDeleteKey(void *h_HashTbl, uint16_t index,
		void *tbl_entry);
int ExternalHashTableEntryGetStatsAndTS(void *tbl_entry,
		struct en_tbl_entry_stats *stats);
int ExternalHashSetReasslyPool(uint32_t type, uint32_t ctx_bpid, 
		uint32_t ctx_bpsize, uint32_t frag_bpid, uint32_t frag_size,
		uint32_t spare_bpid, uint32_t ipr_timer_freq);

int get_ip_reassem_info(uint32_t type, struct ip_reassembly_info *info);

void ipr_update_timestamp(void);
int cdx_get_ipr_v4_stats(void *resp);
int cdx_get_ipr_v6_stats(void *resp);

int cdx_create_port_fqs(void);
int cdx_add_eth_onif(char *name);
int cdx_add_oh_iface(char *name);
struct net_device *find_osdev_by_fman_params(uint32_t fm_idx, uint32_t port_idx,
				uint32_t speed);

void *create_ddr_and_copy_from_muram(void *muramptr, void **ddrptr, U32 size);
void copy_ddr_to_muram_and_free_ddr(void *muramptr, void **ddrptr, U32 size);
struct dpa_bp* get_ipsec_bp(void);
struct dpa_bp* get_frag_bp(void);
