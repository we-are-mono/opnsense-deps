/*
 * Shadow fm_ehash.h — FMan External Hash Table API
 *
 * Replaces the SDK header (which contains Linux-specific inline functions).
 * Struct layouts match the NXP SDK exactly:
 *   sdk_fman/inc/Peripherals/fm_ehash.h
 *
 * NOTE: en_exthash_info and en_exthash_node are NOT defined here — they
 * are defined locally in fm_ehash_freebsd.c (EXCLUDE_FMAN_IPR_OFFLOAD
 * variant).  CDX code treats table handles as opaque void*.
 *
 * Copyright 2011, 2014 Freescale Semiconductor, Inc.
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef FM_EHASH_H
#define FM_EHASH_H 1

#include <sys/types.h>

/* ----------------------------------------------------------------
 * Constants
 * ---------------------------------------------------------------- */
#define MAX_KEY_LEN			56
#define MAX_EN_EHASH_EXT_ENTRY_SIZE	320
#define MAX_EN_EHASH_ENTRY_SIZE		256
#define EN_EHASH_ENTRY_ALIGN		256
#define TBLENTRY_OPC_ALIGN		sizeof(uint32_t)
#define MAX_OPCODES			16

/* ----------------------------------------------------------------
 * Entry flag accessors
 * ---------------------------------------------------------------- */
#define SET_INVALID_ENTRY_64BIT(entry)	(entry |= (((uint64_t)1) << 63))
#define SET_INVALID_ENTRY(flags)	(flags |= (1 << 15))
#define SET_TIMESTAMP_ENABLE(flags)	(flags |= (1 << 13))
#define SET_STATS_ENABLE(flags)		(flags |= (1 << 12))
#define SET_OPC_OFFSET(flags, offset)	(flags |= ((offset >> 2) << 6))
#define SET_PARAM_OFFSET(flags, offset)	(flags |= (offset >> 2))

#define GET_INVALID_ENTRY_64BIT(entry)	(entry & (((uint64_t)1) << 63))
#define GET_INVALID_ENTRY(flags)	(flags & (1 << 15))
#define GET_TIMESTAMP_ENABLE(flags)	((flags >> 13) & 1)
#define GET_STATS_ENABLE(flags)		(flags & (1 << 12))
#define GET_OPC_OFFSET(x)		(((x >> 6) & 0x1f) << 2)
#define GET_PARAM_OFFSET(x)		((x & 0x3f) << 2)

/* ----------------------------------------------------------------
 * Hash table entry — on-hardware representation
 * ---------------------------------------------------------------- */
struct en_ehash_entry {
	union {
		struct {
			union {
				struct {
					uint16_t flags;
					uint16_t next_entry_hi;
					uint32_t next_entry_lo;
				};
				uint64_t next_entry;
			};
			uint8_t key[0];
		} __attribute__((packed));
		struct {
			uint8_t hash_entry[MAX_EN_EHASH_ENTRY_SIZE];
			uint64_t packet_count;
			uint64_t packet_bytes;
			uint32_t timestamp;
			uint32_t reserved;
			uint32_t timestamp_counter;
		} __attribute__((packed));
		uint8_t hash_ext_entry[MAX_EN_EHASH_EXT_ENTRY_SIZE];
	} __attribute__((packed));
} __attribute__((packed));

/* ----------------------------------------------------------------
 * DPA Classifier table entry statistics
 * ---------------------------------------------------------------- */
#define STATS_VALID			(1 << 0)
#define TIMESTAMP_VALID			(1 << 1)

struct en_tbl_entry_stats {
	uint64_t	pkts;
	uint64_t	bytes;
	uint32_t	timestamp;
	uint32_t	flags;
};

/* ----------------------------------------------------------------
 * Opcodes
 * ---------------------------------------------------------------- */
#define ENQUEUE_PKT			0x01
#define REPLICATE_PKT			0x02
#define ENQUEUE_ONLY			0x03
#define UPDATE_ETH_RX_STATS		0x04
#define PREEMPTIVE_CHECKS_ON_PKT	0x05
#define PREEMPTIVE_CHECKS_ON_IPSEC_PKT	0x06
#define STRIP_ETH_HDR			0x11
#define STRIP_ALL_VLAN_HDRS		0x12
#define STRIP_PPPoE_HDR			0x14
#define STRIP_L2_HDR			0x17
#define STRIP_FIRST_VLAN_HDR		0x18
#define REMOVE_FIRST_IP_HDR		0x19
#define VALIDATE_IPSEC_ID		0x1a
#define UPDATE_TTL			0x21
#define UPDATE_SIP_V4			0x22
#define UPDATE_DIP_V4			0x24
#define UPDATE_HOPLIMIT			0x29
#define UPDATE_SIP_V6			0x2A
#define UPDATE_DIP_V6			0x2C
#define UPDATE_SPORT			0x31
#define UPDATE_DPORT			0x32
#define INSERT_L2_HDR			0x41
#define INSERT_VLAN_HDR			0x42
#define INSERT_PPPoE_HDR		0x43
#define INSERT_L3_HDR			0x44
#define REPLACE_PPPOE_HDR		0x45
#define NATPT_4to6			0x51
#define NATPT_6to4			0x52
#define PROCESS_RTP_PAYLOAD		0x61
#define PROCESS_RTCP_PAYLOAD		0x62
#define UPDATE_GLOBAL_STATS		0x80

/* ----------------------------------------------------------------
 * Preemptive check parameters
 * ---------------------------------------------------------------- */
#define PREEMPT_TX_VALIDATE		(1 << 0)
#define PREEMPT_DFBIT_HONOR		(1 << 1)
#define PREEMPT_POLICE_PKT		(1 << 2)
#define PREEMPT_MATCH_DSCP		(1 << 3)
#define PREEMPT_REPLACE_DSCP		(1 << 4)

struct en_ehash_preempt_op {
	uint8_t mtu_offset;
	uint8_t OpMask;
	uint8_t dscp_match_value;
	uint8_t pp_no;
	uint8_t new_dscp_val;
	uint8_t pad;
	uint16_t pad1;
} __attribute__((packed));

/* ----------------------------------------------------------------
 * IPSec preemptive check parameters
 * ---------------------------------------------------------------- */
#define MAX_VLAN_PER_FLOW		2
#define MAX_SPI_PER_FLOW		16
#define VALIDATE_SPI			(0x1 << 0)

struct spi_info {
	uint32_t spi;
	uint32_t fqid;
} __attribute__((packed));

struct en_ehash_ipsec_preempt_op {
	uint8_t op_flags;
	uint8_t unused;
	uint16_t natt_arr_mask;
	uint16_t pppoe_session_id;
	uint16_t pad;
	struct spi_info spi_param[MAX_SPI_PER_FLOW];
} __attribute__((packed));

/* ----------------------------------------------------------------
 * Enqueue parameters
 * ---------------------------------------------------------------- */
#define EN_EHASH_DISABLE_FRAG		0xffff

struct en_ehash_enqueue_param {
	uint16_t mtu;
	uint8_t hdr_xpnd_sz;
	uint8_t bpid;
	uint32_t fqid;
	union {
		struct {
			uint32_t rspid:8;
			uint32_t stats_ptr:24;
		};
		uint32_t word;
	};
	union {
		struct {
			uint32_t dscp_fq_enable:8;
			uint32_t muram_frag_param_addr:24;
		};
		uint32_t word2;
	};
} __attribute__((packed));

/* ----------------------------------------------------------------
 * RTP relay parameters
 * ---------------------------------------------------------------- */
#define EEH_RTP_SEND_FIRST_PACKET_TO_CP		0x0001
#define EEH_RTP_DUPLICATE_PKT_SEND_TO_CP	0x0002
#define EEH_RTP_ENABLE_VLAN_P_BIT_LEARN	0x0004

struct en_ehash_rtprelay_param {
	uint32_t rtpinfo_ptr;
	uint32_t in_sock_stats_ptr;
	uint32_t out_sock_stats_ptr;
	union {
		uint32_t src_ipv4_val;
		uint32_t src_ipv6_val[4];
	} __attribute__((packed));
	uint32_t TimeStampIncr;
	uint32_t SSRC_1;
	uint16_t seq_base;
	uint16_t egress_socketID;
	uint8_t DTMF_PT[2];
	uint16_t rtp_flags;
	uint16_t seq_incr;
	uint32_t chksum_ptr;
	uint32_t rtp_hdr;
	uint32_t ts_incr;
	uint32_t cur_ts_msec;
	int32_t rtp_check;
} __attribute__((packed));

/* ----------------------------------------------------------------
 * Replicate parameters (multicast)
 * ---------------------------------------------------------------- */
struct en_ehash_replicate_param {
	union {
		struct {
			uint16_t rsvd;
			uint16_t first_member_flow_addr_hi;
			uint32_t first_member_flow_addr_lo;
		};
		uint64_t first_member_flow_addr;
	};
	void *first_listener_entry;
} __attribute__((packed));

/* ----------------------------------------------------------------
 * Update ethernet RX stats
 * ---------------------------------------------------------------- */
struct en_ehash_update_ether_rx_stats {
	uint32_t stats_ptr;
} __attribute__((packed));

/* ----------------------------------------------------------------
 * Strip first VLAN header
 * ---------------------------------------------------------------- */
struct en_ehash_strip_first_vlan_hdr {
	uint32_t stats_ptr;
	uint16_t vlan_id;
	uint16_t pad;
} __attribute__((packed));

/* ----------------------------------------------------------------
 * Strip all VLAN headers
 * ---------------------------------------------------------------- */
#define OP_SKIP_VLAN_VALIDATE		(1 << 0)
#define OP_VLAN_FILTER_EN		(1 << 1)
#define OP_VLAN_FILTER_PVID_SET		(1 << 2)

struct en_ehash_strip_all_vlan_hdrs {
	uint16_t vlan_id[MAX_VLAN_PER_FLOW];
	union {
		struct {
			uint32_t padding:2;
			uint32_t num_entries:6;
			uint32_t stats_ptr:24;
		};
		uint32_t word;
	};
	uint8_t op_flags;
	uint8_t pad;
	uint16_t pad1;
	uint8_t stats_offsets[0];
} __attribute__((packed));

/* ----------------------------------------------------------------
 * Strip PPPoE header
 * ---------------------------------------------------------------- */
struct en_ehash_strip_pppoe_hdr {
	uint32_t stats_ptr;
} __attribute__((packed));

/* ----------------------------------------------------------------
 * Strip all L2 headers
 * ---------------------------------------------------------------- */
struct en_ehash_strip_l2_hdrs {
	uint16_t vlan_id[MAX_VLAN_PER_FLOW];
	union {
		struct {
			uint32_t padding:2;
			uint32_t num_entries:6;
			uint32_t stats_ptr:24;
		};
		uint32_t word;
	};
	uint8_t stats_offsets[0];
} __attribute__((packed));

/* ----------------------------------------------------------------
 * Validate IPSec ID
 * ---------------------------------------------------------------- */
struct en_ehash_validate_ipsec {
	uint32_t reserved:16;
	uint32_t identifier:16;
} __attribute__((packed));

/* ----------------------------------------------------------------
 * Update IP addresses
 * ---------------------------------------------------------------- */
struct en_ehash_update_ipv4_ip {
	uint32_t ip_v4;
} __attribute__((packed));

struct en_ehash_update_ipv6_ip {
	uint8_t ip_v6[16];
} __attribute__((packed));

/* ----------------------------------------------------------------
 * Update DSCP
 * ---------------------------------------------------------------- */
struct en_ehash_update_dscp {
	union {
		struct {
			uint32_t rsvd:24;
			uint32_t dscp_mark_value:6;
			uint32_t dscp_mark_flag:1;
			uint32_t padding:1;
		};
		uint32_t dscp;
	};
} __attribute__((packed));

/* ----------------------------------------------------------------
 * Update ports
 * ---------------------------------------------------------------- */
struct en_ehash_update_port {
	uint16_t dport;
	uint16_t sport;
} __attribute__((packed));

/* ----------------------------------------------------------------
 * Insert L2 header
 * ---------------------------------------------------------------- */
struct en_ehash_insert_l2_hdr {
	union {
		struct {
			uint8_t replace:1;
			uint8_t header_padding:2;
			uint8_t reserved:5;
			uint8_t stats_count;
			uint8_t reserved_1;
			uint8_t hdr_len;
		};
		uint32_t word;
	};
	uint8_t l2hdr[0];
} __attribute__((packed));

struct en_ehash_insert_l2_hdr_stats {
	union {
		struct {
			uint32_t padding:2;
			uint32_t reserved:6;
			uint32_t stats_ptr:24;
		};
		uint32_t word;
	};
	uint8_t stats_offsets[0];
} __attribute__((packed));

/* ----------------------------------------------------------------
 * Insert VLAN header
 * ---------------------------------------------------------------- */
struct en_ehash_insert_vlan_hdr {
	union {
		struct {
			uint32_t reserved:1;
			uint32_t dscp_vlanpcp_map_enable:1;
			uint32_t num_hdrs:6;
			uint32_t statptr:24;
		} __attribute__((packed));
		uint32_t word;
	} __attribute__((packed));
	uint32_t vlanhdr[0];
} __attribute__((packed));

struct en_ehash_insert_vlan_hdr_stats {
	uint8_t stats_offsets[1];
} __attribute__((packed));

/* ----------------------------------------------------------------
 * Insert/replace PPPoE header
 * ---------------------------------------------------------------- */
#define PPPoE_VERSION	1
#define PPPoE_TYPE	1
#define PPPoE_CODE	0

struct en_ehash_insert_pppoe_hdr {
	uint32_t stats_ptr;
	union {
		struct {
			uint32_t version:4;
			uint32_t type:4;
			uint32_t code:8;
			uint32_t session_id:16;
		};
		uint32_t word;
	};
} __attribute__((packed));

struct en_ehash_replace_pppoe_hdr_params {
	uint8_t destination_mac[6];
	uint8_t source_mac[6];
	uint16_t session_id;
	uint16_t pad;
	uint32_t fqid;
	uint32_t stats_ptr;
} __attribute__((packed));

/* ----------------------------------------------------------------
 * Insert L3 header (tunnels)
 * ---------------------------------------------------------------- */
#define TYPE_CUSTOM	0
#define TYPE_4o6	1
#define TYPE_6o4	2

#define IPID_STARTVAL	1

struct en_ehash_insert_l3_hdr {
	union {
		struct {
			uint8_t reserved:3;
			uint8_t calc_cksum:1;
			uint8_t qos:1;
			uint8_t df:1;
			uint8_t type:2;
			uint8_t hdr_len;
			uint16_t ipident;
		};
		uint32_t word;
	};
	union {
		struct {
			uint32_t route_dest_offset:8;
			uint32_t stats_ptr:24;
		};
		uint32_t word_1;
	};
	uint8_t l3hdr[0];
} __attribute__((packed));

#define COPY_DSCP_OUTER_INNER	(1 << 24)

/* ----------------------------------------------------------------
 * Remove first IP header (tunnel decap)
 * ---------------------------------------------------------------- */
struct en_ehash_remove_first_ip_hdr {
	uint32_t flags:8;
	uint32_t stats_ptr:24;
} __attribute__((packed));

/* ----------------------------------------------------------------
 * Port info / interface stats structures
 * ---------------------------------------------------------------- */
struct en_ehash_portinfo {
	uint32_t reserved[3];
	uint32_t port_info;
} __attribute__((packed));

struct en_ehash_ifportinfo {
	struct en_ehash_portinfo rxpinfo;
	struct en_ehash_portinfo txpinfo;
} __attribute__((packed));

struct en_ehash_stats {
	uint64_t bytes;
	uint32_t pkts;
	uint32_t reserved;
} __attribute__((packed));

struct en_ehash_stats_with_ts {
	uint64_t bytes;
	uint32_t pkts;
	uint32_t pad;
	uint64_t timestamp;
} __attribute__((packed));

struct en_ehash_ifstats {
	struct en_ehash_stats rxstats;
	struct en_ehash_stats txstats;
} __attribute__((packed));

#define STATS_WITH_TS	(1 << 7)

struct en_ehash_ifstats_with_ts {
	struct en_ehash_stats_with_ts rxstats;
	struct en_ehash_stats_with_ts txstats;
} __attribute__((packed));

/* Statistics table */
struct en_ehash_stats_tbl {
	uint32_t table_indicator:1;
	uint32_t num_entries:7;
	uint32_t stats_ptr:24;
} __attribute__((packed));

/* ----------------------------------------------------------------
 * NATPT structures
 * ---------------------------------------------------------------- */
struct en_ehash_natpt_hdr {
	union {
		struct {
			uint32_t reserved:6;
			uint32_t tcu:1;
			uint32_t hlu:1;
			uint32_t hdrlen:8;
			uint32_t reserved1:16;
		} ip4to6;
		struct {
			uint16_t reserved:5;
			uint16_t ipu:1;
			uint16_t tou:1;
			uint16_t tlu:1;
			uint16_t hdrlen:8;
			uint16_t ipident;
		} ip6to4;
		uint32_t word;
	};
	uint8_t l3hdr[0];
} __attribute__((packed));

/* NATPT 4-to-6 flags */
#define NATPT_TCU	(1 << 25)
#define NATPT_HLU	(1 << 24)
/* NATPT 6-to-4 flags */
#define NATPT_IPU	(1 << 26)
#define NATPT_TOU	(1 << 25)
#define NATPT_TLU	(1 << 24)

/* ----------------------------------------------------------------
 * SEC failure statistics
 * ---------------------------------------------------------------- */
typedef struct en_SEC_failure_stats_s {
	uint32_t icv_failures;
	uint32_t hw_errs;
	uint32_t CCM_AAD_size_errs;
	uint32_t anti_replay_late_errs;
	uint32_t anti_replay_replay_errs;
	uint32_t seq_num_overflows;
	uint32_t DMA_errs;
	uint32_t DECO_watchdog_timer_timedout_errs;
	uint32_t input_frame_read_errs;
	uint32_t protocol_format_errs;
	uint32_t ipsec_ttl_zero_errs;
	uint32_t ipsec_pad_chk_failures;
	uint32_t output_frame_length_rollover_errs;
	uint32_t tbl_buff_too_small_errs;
	uint32_t tbl_buff_pool_depletion_errs;
	uint32_t output_frame_too_large_errs;
	uint32_t cmpnd_frame_write_errs;
	uint32_t buff_too_small_errs;
	uint32_t buff_pool_depletion_errs;
	uint32_t output_frame_write_errs;
	uint32_t cmpnd_frame_read_errs;
	uint32_t prehdr_read_errs;
	uint32_t other_errs;
} __attribute__((packed)) en_SEC_failure_stats;

/* ----------------------------------------------------------------
 * DSCP-to-VLAN PCP mapping
 * ---------------------------------------------------------------- */
#define MAX_VLAN_PCP	7

typedef struct en_dscp_vlanpcp_map_cfg_s {
	uint8_t dscp_vlanpcp[MAX_VLAN_PCP + 1];
} __attribute__((packed)) en_dscp_vlanpcp_map_cfg;

/* ----------------------------------------------------------------
 * Global MURAM data area — at pool + EN_INTERNAL_BUFF_POOL_SIZE
 *
 * Contains DSCP-to-VLAN PCP mapping (8 bytes) followed by SEC
 * failure statistics (92 bytes).  Total: 100 bytes within a
 * 256-byte MURAM slot.  CDX microcode reads/writes these at runtime.
 * ---------------------------------------------------------------- */
typedef struct en_exthash_global_mem_s {
	en_dscp_vlanpcp_map_cfg		dscp_vlanpcp_map;	/* +0, 8B  */
	en_SEC_failure_stats		SEC_failure_stats;	/* +8, 92B */
} __attribute__((packed)) en_exthash_global_mem;

/* ----------------------------------------------------------------
 * IP reassembly MURAM parameters — written by FMan microcode,
 * fields configured by ExternalHashSetReasslyPool().
 *
 * This is the hardware layout in MURAM, pointed to by
 * en_exthash_node.word_2 (reassm_param << 8) for REASSM tables.
 * All multi-byte fields are stored big-endian.
 * ---------------------------------------------------------------- */
#define	MAX_REASSM_BUCKETS	16

struct ip_reassembly_stats {
	uint64_t num_frag_pkts;
	uint64_t num_reassemblies;
	uint64_t num_completed_reassly;
	uint64_t num_sess_matches;
	uint64_t num_frags_too_small;
	uint64_t num_reassm_timeouts;
	uint64_t num_overlapping_frags;
	uint64_t num_too_many_frags;
	uint64_t num_failed_bufallocs;
	uint64_t num_failed_ctxallocs;
	uint64_t num_fatal_errors;
	uint64_t num_failed_ctxdeallocs;
	uint32_t reassm_count;
	uint32_t pad;
} __attribute__((packed));

struct ip_reassembly_params {
	uint32_t table_base_hi;
	uint32_t table_base_lo;
	struct ip_reassembly_stats stats;
	uint32_t table_mask;
	uint32_t type;
	uint32_t ipr_timer;
	uint32_t timeout_val;
	uint32_t timeout_fqid;
	uint32_t min_frag_size;
	uint32_t reassem_bpid;
	uint32_t reassem_bsize;
	uint32_t frag_bpid;
	uint32_t frag_bsize;
	uint32_t reassly_dbg;
	uint32_t context_info;
	uint32_t curr_sessions;
	uint32_t txc_fqid;
	uint32_t timer_tnum;
	uint32_t max_frags;
	uint32_t max_con_reassm;
	uint32_t bucket_base;
	uint32_t bucket_lock[MAX_REASSM_BUCKETS];
	uint32_t bucket_head[MAX_REASSM_BUCKETS];
} __attribute__((packed));

/* ----------------------------------------------------------------
 * IP reassembly info (for devman.h forward reference)
 * ---------------------------------------------------------------- */
struct ip_reassembly_info {
	uint64_t num_frag_pkts;
	uint64_t num_reassemblies;
	uint64_t num_completed_reassly;
	uint64_t num_sess_matches;
	uint64_t num_frags_too_small;
	uint64_t num_reassm_timeouts;
	uint64_t num_overlapping_frags;
	uint64_t num_too_many_frags;
	uint64_t num_failed_bufallocs;
	uint64_t num_failed_ctxallocs;
	uint64_t num_fatal_errors;
	uint64_t num_failed_ctxdeallocs;
	uint32_t table_mask;
	uint32_t ipr_timer;
	uint32_t timeout_val;
	uint32_t timeout_fqid;
	uint32_t max_frags;
	uint32_t min_frag_size;
	uint32_t max_con_reassm;
	uint32_t reassem_bpid;
	uint32_t reassem_bsize;
	uint32_t frag_bpid;
	uint32_t frag_bsize;
	uint32_t timer_tnum;
	uint32_t reassly_dbg;
	uint32_t curr_sessions;
	uint32_t txc_fqid;
};

/* ----------------------------------------------------------------
 * Software table entry wrapping the hardware entry
 * ---------------------------------------------------------------- */
struct en_exthash_tbl_entry {
	struct en_ehash_entry hashentry;
	struct en_exthash_tbl_entry *prev;
	struct en_exthash_tbl_entry *next;
	uint8_t *replicate_params;
	union {
		uint8_t *enqueue_params;
		uint8_t *ipsec_preempt_params;
	};
};

/* Hash table bucket */
struct en_exthash_bucket {
	uint64_t h;
	uint64_t pad;
};

/* ----------------------------------------------------------------
 * Debug display — no-op stubs replacing SDK inline functions
 * that use printk/phys_to_virt/etc.  Tier 1 code calls these
 * but they're debug-only and not needed for correct operation.
 * ---------------------------------------------------------------- */
static inline void
display_ehash_tbl_entry(struct en_ehash_entry *entry __attribute__((unused)),
    uint32_t keysize __attribute__((unused)))
{
}

/* ----------------------------------------------------------------
 * ExternalHash API
 * ---------------------------------------------------------------- */
extern void *ExternalHashTableAllocEntry(void *h_HashTbl);
extern void ExternalHashTableEntryFree(void *entry);
extern int ExternalHashTableFmPcdHcSync(void *h_HashTbl);
extern int ExternalHashTableAddKey(void *h_HashTbl, uint8_t keySize,
    void *tbl_entry);
extern int ExternalHashTableDeleteKey(void *h_HashTbl, uint16_t index,
    void *tbl_entry);
extern int ExternalHashTableEntryGetStatsAndTS(void *tbl_entry,
    struct en_tbl_entry_stats *stats);
extern int32_t ExternalHashGetSECfailureStats(en_SEC_failure_stats *stats);
extern int32_t ExternalHashResetSECfailureStats(void);
extern int32_t ExternalHashSetDscpVlanpcpMapCfg(en_dscp_vlanpcp_map_cfg *map);
extern int32_t ExternalHashGetDscpVlanpcpMapCfg(en_dscp_vlanpcp_map_cfg *map);
extern int ExternalHashSetReasslyPool(uint32_t type, uint32_t ctx_bpid,
    uint32_t ctx_bpsize, uint32_t frag_bpid, uint32_t frag_size,
    uint32_t txc_fqid, uint32_t ipr_timer_freq);
extern int ExternalHashReasslyTableExists(uint32_t type);

#endif /* FM_EHASH_H */
