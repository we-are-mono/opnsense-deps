/*
 * Copyright 2008-2016 Freescale Semiconductor Inc.
 * Copyright 2017-2018 NXP
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *      * Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *      * Redistributions in binary form must reproduce the above copyright
 *        notice, this list of conditions and the following disclaimer in the
 *        documentation and/or other materials provided with the distribution.
 *      * Neither the name of the above-listed copyright holders nor the
 *        names of any contributors may be used to endorse or promote products
 *        derived from this software without specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __FSL_ENET_H
#define __FSL_ENET_H

/**
 @Description  Ethernet MAC-PHY Interface
*/

enum enet_interface {
	E_ENET_IF_MII		= 0x00010000, /**< MII interface */
	E_ENET_IF_RMII		= 0x00020000, /**< RMII interface */
	E_ENET_IF_SMII		= 0x00030000, /**< SMII interface */
	E_ENET_IF_GMII		= 0x00040000, /**< GMII interface */
	E_ENET_IF_RGMII		= 0x00050000, /**< RGMII interface */
	E_ENET_IF_TBI		= 0x00060000, /**< TBI interface */
	E_ENET_IF_RTBI		= 0x00070000, /**< RTBI interface */
	E_ENET_IF_SGMII		= 0x00080000, /**< SGMII interface */
	E_ENET_IF_XGMII		= 0x00090000, /**< XGMII interface */
	E_ENET_IF_QSGMII	= 0x000a0000, /**< QSGMII interface */
	E_ENET_IF_XFI		= 0x000b0000  /**< XFI interface */
};

/**
 @Description  Ethernet Speed (nominal data rate)
*/
enum enet_speed {
	E_ENET_SPEED_10		= 10,	/**< 10 Mbps */
	E_ENET_SPEED_100	= 100,	/**< 100 Mbps */
	E_ENET_SPEED_1000	= 1000,	/**< 1000 Mbps = 1 Gbps */
        E_ENET_SPEED_2500       = 2500, /**< 2500 Mbps = 2.5 Gbps */
	E_ENET_SPEED_10000	= 10000	/**< 10000 Mbps = 10 Gbps */
};

enum mac_stat_level {
	/* No statistics */
	E_MAC_STAT_NONE = 0,
	/* Only RMON MIB group 1 (ether stats). Optimized for performance */
	E_MAC_STAT_MIB_GRP1,
	/* Only error counters are available. Optimized for performance */
	E_MAC_STAT_PARTIAL,
	/* All counters available. Not optimized for performance */
	E_MAC_STAT_FULL
};


#endif /* __FSL_ENET_H */
