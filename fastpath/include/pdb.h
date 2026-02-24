/*
 * CAAM Protocol Data Block (PDB) definitions for IPSec ESP.
 *
 * Ported from Linux drivers/crypto/caam/pdb.h for FreeBSD.
 * Only IPSec-related structures are included — WiFi, WiMAX, MACsec,
 * TLS, SRTP, DSA, RSA PDBs are omitted (not needed by CDX IPSec).
 *
 * Copyright 2008-2016 Freescale Semiconductor, Inc.
 * Copyright 2026 Mono Technologies Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef _CAAM_PDB_H
#define _CAAM_PDB_H

#include <sys/types.h>

/*
 * PDB — IPSec ESP Header Modification Options (HMO)
 */
#define PDBHMO_ESP_DECAP_SHIFT		28
#define PDBHMO_ESP_ENCAP_SHIFT		28

/* Decrement TTL (IPv4) or Hop Limit (IPv6) */
#define PDBHMO_ESP_DECAP_DEC_TTL	(0x02 << PDBHMO_ESP_DECAP_SHIFT)
#define PDBHMO_ESP_ENCAP_DEC_TTL	(0x02 << PDBHMO_ESP_ENCAP_SHIFT)

/* Decap: Copy TOS/TC from outer to inner IP header */
#define PDBHMO_ESP_DIFFSERV		(0x01 << PDBHMO_ESP_DECAP_SHIFT)

/* Encap: Copy DF bit from inner to outer IP header */
#define PDBHMO_ESP_DFBIT		(0x04 << PDBHMO_ESP_ENCAP_SHIFT)

/*
 * Next-Header and Header-Length field positions
 */
#define PDBNH_ESP_ENCAP_SHIFT		16
#define PDBNH_ESP_ENCAP_MASK		(0xff << PDBNH_ESP_ENCAP_SHIFT)

#define PDBHDRLEN_ESP_DECAP_SHIFT	16
#define PDBHDRLEN_MASK			(0x0fff << PDBHDRLEN_ESP_DECAP_SHIFT)

#define PDB_NH_OFFSET_SHIFT		8
#define PDB_NH_OFFSET_MASK		(0xff << PDB_NH_OFFSET_SHIFT)

/*
 * PDB — IPSec ESP Encap/Decap Option flags (low byte of options word)
 */
#define PDBOPTS_ESP_ARSNONE	0x00	/* No anti-replay window */
#define PDBOPTS_ESP_ARS32	0x40	/* 32-entry anti-replay window */
#define PDBOPTS_ESP_ARS128	0x80	/* 128-entry anti-replay window */
#define PDBOPTS_ESP_ARS64	0xc0	/* 64-entry anti-replay window */
#define PDBOPTS_ESP_ARS_MASK	0xc0
#define PDBOPTS_ESP_IVSRC	0x20	/* IV from internal random generator */
#define PDBOPTS_ESP_ESN		0x10	/* Extended Sequence Number */
#define PDBOPTS_ESP_OUTFMT	0x08	/* Output-only decapsulation (decap) */
#define PDBOPTS_ESP_IPHDRSRC	0x08	/* IP header from PDB (encap) */
#define PDBOPTS_ESP_INCIPHDR	0x04	/* Prepend IP header to output */
#define PDBOPTS_ESP_IPVSN	0x02	/* Process IPv6 header */
#define PDBOPTS_ESP_AOFL	0x04	/* Adjust output frame length (decap) */
#define PDBOPTS_ESP_TUNNEL	0x01	/* Tunnel mode next-header byte */
#define PDBOPTS_ESP_IPV6	0x02	/* IP header version is V6 */
#define PDBOPTS_ESP_DIFFSERV	0x40	/* Copy TOS/TC from inner iphdr */
#define PDBOPTS_ESP_UPDATE_CSUM	0x80	/* Encap: update IP header checksum */
#define PDBOPTS_ESP_VERIFY_CSUM	0x20	/* Decap: validate IP header checksum */

/*
 * Encap PDB — cipher-mode-specific sub-structures
 */
struct ipsec_encap_cbc {
	uint8_t		iv[16];
};

struct ipsec_encap_ctr {
	uint8_t		ctr_nonce[4];
	uint32_t	ctr_initial;
	uint64_t	iv;
};

struct ipsec_encap_ccm {
	uint8_t		salt[4];
	uint32_t	ccm_opt;
	uint64_t	iv;
};

struct ipsec_encap_gcm {
	uint8_t		salt[4];
	uint32_t	rsvd1;
	uint64_t	iv;
};

/*
 * ipsec_encap_pdb — PDB for IPSec ESP encapsulation
 *
 * options:  [HMO:4][rsvd:4][next_hdr:8][nh_offset:8][flags:8]
 * ip_hdr_len: [rsvd:16][opt_ip_hdr_len:16]
 * ip_hdr[]:  optional outer IP header content (tunnel mode)
 */
struct ipsec_encap_pdb {
	uint32_t	options;
	uint32_t	seq_num_ext_hi;
	uint32_t	seq_num;
	union {
		struct ipsec_encap_cbc	cbc;
		struct ipsec_encap_ctr	ctr;
		struct ipsec_encap_ccm	ccm;
		struct ipsec_encap_gcm	gcm;
	};
	uint32_t	spi;
	uint32_t	ip_hdr_len;
	uint32_t	ip_hdr[];
} __packed;

/*
 * Decap PDB — cipher-mode-specific sub-structures
 */
struct ipsec_decap_cbc {
	uint32_t	rsvd[2];
} __packed;

struct ipsec_decap_ctr {
	uint8_t		ctr_nonce[4];
	uint32_t	ctr_initial;
} __packed;

struct ipsec_decap_ccm {
	uint8_t		salt[4];
	uint32_t	ccm_opt;
} __packed;

struct ipsec_decap_gcm {
	uint8_t		salt[4];
	uint32_t	rsvd;
} __packed;

/*
 * ipsec_decap_pdb — PDB for IPSec ESP decapsulation
 *
 * options:  [HMO:4][ip_hdr_len:12][nh_offset:8][flags:8]
 * anti_replay[]: window entries, size depends on ARS option
 */
struct ipsec_decap_pdb {
	uint32_t	options;
	union {
		struct ipsec_decap_cbc	cbc;
		struct ipsec_decap_ctr	ctr;
		struct ipsec_decap_ccm	ccm;
		struct ipsec_decap_gcm	gcm;
	};
	uint32_t	seq_num_ext_hi;
	uint32_t	seq_num;
	uint32_t	anti_replay[4];
} __packed;

/*
 * CCM option sub-structures used by CDX PDB builders
 * (b0_flags, ctr_flags, ctr_initial fields)
 */
struct encap_ccm_opt {
	uint8_t		b0_flags;
	uint8_t		ctr_flags;
	uint16_t	ctr_initial;
};

struct decap_ccm_opt {
	uint8_t		b0_flags;
	uint8_t		ctr_flags;
	uint16_t	ctr_initial;
};

#endif /* _CAAM_PDB_H */
