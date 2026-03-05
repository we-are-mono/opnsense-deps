# WiFi Offload Audit — CDX devman gaps vs Linux vendor code

## Context

The FreeBSD `cdx_devman_freebsd.c` was written from scratch for Ethernet
offload. WiFi (`IF_TYPE_WLAN`) support is being added incrementally as
errors surface. The Linux vendor code (`vendor/cdx/dpa_wifi.c`, ~3000 lines)
has a complete WiFi TX/RX path. We need to audit all devman functions that
walk interface hierarchies or resolve interface properties, and ensure they
handle `IF_TYPE_WLAN` correctly.

## What was already fixed

1. **`dpa_get_fm_port_index()`** — added `IF_TYPE_WLAN` check to return
   `wlan_info.fman_idx/port_idx/portid` instead of walking to eth parent.

2. **`dpa_get_tx_info_by_itf()`** — added `IF_TYPE_WLAN` case in the
   interface hierarchy walk to get TX FQID from OH port and MAC from
   `wlan_info.mac_addr`.

3. **`cdx_ioc_set_dpa_params()`** — added OH port registration loop
   (step 7d) that was present in Linux `dpa_cfg.c` but missing from
   the FreeBSD port.

## Prompt for Claude

Audit ALL functions in `cdx_devman_freebsd.c` that use `devman_find_eth_parent()`,
`IF_TYPE_ETHERNET`, or walk interface hierarchies (VLAN→PPPoE→Ethernet chains).
For each one, determine if it needs `IF_TYPE_WLAN` handling.

Cross-reference with the Linux vendor code:
- `vendor/cdx/dpa_wifi.c` — full WiFi TX/RX/VAP management
- `vendor/cdx/dpa_wifi.h` — WiFi data structures and FD helpers
- `vendor/cdx/devman.c` — Linux devman (compare interface walking)
- `vendor/cdx/devoh.c` — Linux OH port management

Specifically check these functions in `cdx_devman_freebsd.c`:
- `dpa_get_tx_l2info_by_itf()` — uses `devman_find_eth_parent()` for L2 bridge flows
- `add_incoming_iface_info()` — resolves ingress interface info for hash insertion
- `dpa_get_phys_iface()` — returns physical parent interface
- Any function that reads `eth_info.*` fields

Also check `cdx_ehash.c` for WiFi-specific paths:
- `fill_actions()` — builds opcode chain for header modification
- `insert_entry_in_classif_table()` — already fixed fmindex, but check
  other assumptions (e.g., L2 header construction, ethertype handling)
- `fill_sobject()` / `fill_dobject()` — source/dest object fill

And check `cdx_devoh_freebsd.c`:
- `cdxdrv_create_of_fqs()` — creates QMan FQs for OH ports
- Does it create distribution FQs that WiFi needs?

The goal is to find ALL remaining `IF_TYPE_WLAN` gaps before they surface
as runtime errors, rather than fixing them one-by-one.

Do NOT write code — just research and report findings. List each function,
whether it needs a fix, and what the fix would be.
