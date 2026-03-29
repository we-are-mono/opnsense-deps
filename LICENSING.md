# Licensing

This repository contains components under multiple open-source licenses. Each source file carries an SPDX-License-Identifier header which is the authoritative license for that file. Full license texts are in the `LICENSES/` directory.

## BSD-2-Clause — Clean Reimplementations

These drivers were written from scratch for FreeBSD, inspired by hardware datasheets, vendor reference manuals, and existing Linux drivers. They share no code, function names, or struct names with their Linux counterparts.

| Component | Path | Notes |
|---|---|---|
| CAAM crypto | `drivers/caam/` | NXP SEC v5.x crypto accelerator (JR + QI) |
| INA2xx power monitor | `drivers/ina2xx/` | TI INA219/INA226/INA234 |
| EMC2302 fan controller | `drivers/emc2302/` | Microchip EMC2301-2305 |
| TMP431 temp sensor | `drivers/tmp431/` | TI TMP431 dual-channel |
| PCF2131 RTC | `drivers/pcf2131/` | NXP PCF2131 real-time clock |
| LP5812 LED controller | `drivers/lp5812/` | TI LP5812 12-channel LED |
| pf_notify | `fastpath/pf_notify/` | PF state change notifications (no Linux counterpart) |

## GPL-2.0+ — NXP Fastpath Stack

The DPAA1 flow offload stack derives from NXP's ASK (Application Solution Kit) SDK, which is GPL-2.0+ licensed. Some components compile unmodified NXP vendor source from `fastpath/vendor/`; others are FreeBSD rewrites that include GPL headers (`fpp.h`, `list.h`) or are derived from GPL originals. The entire stack is licensed as GPL-2.0+ with original copyright holders (Mindspeed Technologies, Freescale Semiconductor, NXP) retained.

| Component | Path | Description |
|---|---|---|
| CDX | `fastpath/cdx/` | Flow offload kernel module (compiles NXP vendor source + FreeBSD ports) |
| CMM | `fastpath/cmm/` | Connection manager daemon (reimplemented for FreeBSD, includes GPL headers) |
| cmmctl | `fastpath/cmmctl/` | CMM command-line control tool |
| auto_bridge | `fastpath/auto_bridge/` | L2 flow detection kernel module |
| FCI | `fastpath/fci/` | Fast control interface kernel module |
| fci_lib | `fastpath/fci_lib/` | FCI userspace library |
| dpa_app | `fastpath/dpa_app/` | DPA initialization tool (compiles NXP vendor source) |
| include/ | `fastpath/include/` | Shared headers (mix of GPL NXP originals + BSD compat shims) |
| vendor/ | `fastpath/vendor/` | Unmodified NXP ASK source (GPL-2.0+) |

## GPL-2.0 — NXP WiFi Driver

The mwifiex WiFi driver links NXP's GPL-2.0 mlan core library (~127K lines, fetched into `_vendor/` at build time) with a FreeBSD OS abstraction layer (~3K lines). The combined module is GPL-2.0.

| Component | Path | Description |
|---|---|---|
| mwifiex | `drivers/mwifiex/` | NXP 88W9098 PCIe WiFi (mlan core + FreeBSD moal shim) |

## Permissive Third-Party — NXP Libraries

These NXP-provided libraries carry permissive licenses and are used unmodified.

| Component | Path | License | Description |
|---|---|---|---|
| fmlib | `fastpath/fmlib/` | BSD-3-Clause | FMan userspace library |
| fmc | `fastpath/fmc/` | MIT | FMan Configuration Compiler |

## Compliance

All source code is publicly available in this repository. GPL compliance is satisfied through source availability alongside any binary distribution.

Per-file SPDX-License-Identifier headers are the authoritative license for each file. When in doubt, check the file header.
