/*
 * CDX FreeBSD build prelude — force-included before every source file.
 *
 * This header pre-includes our shadow headers so that their include guards
 * are set before the compiler processes the Tier 1 source file. When a
 * Tier 1 file does #include "cdx.h" (finding the original in cdx-5.03.1/),
 * the guard _CDX_H_ is already defined and the original is skipped.
 *
 * Copyright 2026 Mono Technologies Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _CDX_PRELUDE_H_
#define _CDX_PRELUDE_H_

/*
 * Table type enum — the original in cdx_ioctl.h is inside #if 0 but the
 * Tier 1 code (cdx_ehash.c, dpa_cfg.c, etc.) uses these constants
 * extensively.  Define before cdx.h includes cdx_ioctl.h.
 */
enum {
	IPV4_UDP_TABLE,
	IPV4_TCP_TABLE,
	IPV6_UDP_TABLE,
	IPV6_TCP_TABLE,
	ESP_IPV4_TABLE,
	ESP_IPV6_TABLE,
	IPV4_MULTICAST_TABLE,
	IPV6_MULTICAST_TABLE,
	PPPOE_RELAY_TABLE,
	ETHERNET_TABLE,
	IPV4_3TUPLE_UDP_TABLE,
	IPV4_3TUPLE_TCP_TABLE,
	IPV6_3TUPLE_UDP_TABLE,
	IPV6_3TUPLE_TCP_TABLE,
	IPV4_REASSM_TABLE,
	IPV6_REASSM_TABLE,
	MAX_MATCH_TABLES
};

/*
 * DPA classifier table type — defined in dpa_app's dpa.c on Linux,
 * used by Tier 1 dpa_cfg.c for table_info.dpa_type.
 */
enum dpa_cls_tbl_type {
	DPA_CLS_TBL_INTERNAL_HASH = 0,
	DPA_CLS_TBL_EXTERNAL_HASH,
	DPA_CLS_TBL_INDEXED,
	DPA_CLS_TBL_EXACT_MATCH
};

/*
 * Linux-specific IPsec constants used by Tier 1 control_ipsec.c.
 *
 * SADB_X_EALG_NULL_AES_GMAC = 23 (from Linux pfkeyv2.h)
 * XFRM_STATE_* enum (from Linux xfrm.h)
 * These have no FreeBSD equivalent — define them here for CDX.
 */
#ifdef DPA_IPSEC_OFFLOAD
#ifndef SADB_X_EALG_NULL_AES_GMAC
#define SADB_X_EALG_NULL_AES_GMAC	23
#endif
enum {
	XFRM_STATE_VOID = 0,
	XFRM_STATE_ACQ,
	XFRM_STATE_VALID,
	XFRM_STATE_ERROR,
	XFRM_STATE_EXPIRED,
	XFRM_STATE_DEAD
};
#endif /* DPA_IPSEC_OFFLOAD */

/* Shadow headers whose originals exist in cdx-5.03.1/ */
#include "cdx.h"
#include "dpa_ipsec.h"
#include "dpa_wifi.h"
#include "fm_ehash.h"
#include "misc.h"

/*
 * Per-interface stats HM opcodes (MURAM-based counters).
 * Enabled — real implementations in cdx_ifstats_freebsd.c and
 * cdx_devman_freebsd.c.  INCLUDE_IFSTATS_SUPPORT is defined in
 * cdx_common.h when any of these are set.
 */

#endif /* _CDX_PRELUDE_H_ */
