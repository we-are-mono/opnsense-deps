# CMM FreeBSD Port — Review & Action Items

Comparative review of the FreeBSD CMM port (`ASK/freebsd/cmm/`, ~4300 LOC)
against the original Linux CMM (`ASK/cmm-17.03.1/src/`, ~45000 LOC).

The port is a clean rewrite (not a line-by-line translation). The
architecture — kqueue event loop, push-based PF state events via
`pf_notify.ko`, PF_ROUTE/PF_KEY sockets — is sound.

The FreeBSD port currently implements the **core path** only: conntrack
event handling, route/neighbor resolution, FPP flow programming, and
IPsec SA tracking. The Linux CMM has 20 additional feature modules not yet
ported:

---

## Missing Feature Modules

| # | Module | Linux file | LOC | FPP commands | Description | Done |
|---|--------|-----------|-----|--------------|-------------|------|
| 1 | QoS | `module_qm.c` | 2,788 | 40+ `FPP_CMD_QM_*` | Traffic shaping, scheduling, rate limiting, DSCP mapping | [x] |
| 2 | VLAN | `module_vlan.c` | 571 | `FPP_CMD_VLAN_ENTRY`, `_RESET` | 802.1Q VLAN interface add/remove/reset | [x] |
| 3 | Tunnels | `module_tunnel.c` | 1,885 | `FPP_CMD_TUNNEL_ADD/DEL/UPDATE` | 6in4, 4in6, GRE tunnel offload | [x] |
| 4 | L2 Bridge | `module_rx.c` | 1,746 | `FPP_CMD_RX_L2BRIDGE_*`, `_CNG_*` | MAC learning, ARL, L2 bridge flow offload | [x] |
| 5 | Statistics | `module_stat.c` | 1,267 | `FPP_CMD_STAT_*` | Per-connection, bridge, tunnel, VLAN, IPsec counters | [x] |
| 6 | Deny rules | `ffcontrol.c` | 2,908 | `FPP_CMD_IPSEC_FRAG_CFG` | Deny-rule filtering, ff_enable/disable, IPsec frag config | [x] |
| 7 | CLI daemon | `client_daemon.c` | 1,644 | (dispatcher) | Runtime CLI command interface | [x] |
| 8 | Socket accel | `module_socket.c` | 1,886 | `FPP_CMD_IPV4/6_SOCK_*` | TCP socket-level acceleration | [x] |
| 9 | RTP/voice | `module_rtp.c`, `voicebuf.c` | 1,810 | `FPP_CMD_RTP_*`, `_VOICE_BUFFER_*` | RTP/RTCP flow monitoring, voice buffers | |
| 10 | PPPoE | `pppoe.c`, `module_relay.c` | 960 | `FPP_CMD_PPPOE_ENTRY`, `_RELAY_ENTRY` | PPPoE session management and relay | [x] |
| 11 | ICC | `module_icc.c` | 554 | `FPP_CMD_ICC_*` | Ingress congestion control | [x] |
| 12 | Profiling | `module_prf.c` | 608 | `FPP_CMD_TRC_*` | FPP debug tracing and CPU profiling | [x] |
| 13 | WiFi | `module_wifi.c` | 476 | `FPP_CMD_WIFI_VAP_*` | WiFi VAP management | |
| 14 | Pkt capture | `module_pktcap.c` | 420 | `FPP_CMD_PKTCAP_*` | Packet capture / traffic mirroring | [x] |
| 15 | NAT-PT | `module_natpt.c` | 364 | `FPP_CMD_NATPT_*` | IPv4-IPv6 translation | [x] |
| 16 | L2 bridge ctrl | `ffbridge.c` | 336 | — | Bridge port list / config (stub in Linux) | [x] |
| 17 | L2TP | `module_l2tp.c` | 334 | `FPP_CMD_L2TP_ITF_*` | L2TP tunnel interfaces | [x] |
| 18 | Exception Q | `module_expt.c` | ~200 | `FPP_CMD_EXPT_QUEUE_*` | DSCP exception queue mapping | |
| 19 | TX DSCP map | `module_tx.c` | ~200 | `FPP_CMD_DSCP_VLANPCP_*` | Egress DSCP→VLAN PCP mapping | [x] |
| 20 | MACVLAN | `module_macvlan.c` | ~200 | `FPP_CMD_MACVLAN_ENTRY` | Virtual MAC interfaces | [x] |

### Adding a new command-driven module to cmmctl

Modules that are pure FCI passthrough (no CMM-side state) follow this
pattern. For example, adding Statistics (#5):

1. **Whitelist the FPP commands** in `cmm/cmm_ctrl.c` — add the new
   `FPP_CMD_STAT_*` codes to `ctrl_whitelist[]`.

2. **Create `cmmctl/cmmctl_stat.c`** — implement a
   `cmmctl_stat_main(int argc, char **argv, int fd)` function that
   parses arguments, populates the FPP struct, and calls
   `ctrl_command()`.

3. **Declare the handler** in `cmmctl/cmmctl.h`:
   ```c
   int cmmctl_stat_main(int argc, char **argv, int fd);
   ```

4. **Register the sub-command** in `cmmctl/cmmctl.c`:
   ```c
   { "stat", cmmctl_stat_main, "Statistics" },
   ```

5. **Add the source** to `cmmctl/Makefile.cross` (`CTL_SRCS`).

6. **Rebuild**: `make -f .../cmmctl/Makefile.cross clean all`. CMM
   itself only needs rebuilding if the whitelist changed.

---

- **Tunnel module (#3)**: CDX has no mode for IP-IP (IPv4-in-IPv4) or
  GRE-over-IPv4 tunnels. Only gif(4) with IPv4 outer (6in4, mode
  `TNL_6O4`), gif(4) with IPv6 outer (4in6, mode `TNL_4O6`), and gre(4)
  with IPv6 outer (`TNL_GRE_IPV6`) are supported. `gre` interfaces with
  an IPv4 outer endpoint are detected but skipped with a log warning.

- **Statistics module (#5)**: Pure FCI passthrough — no CMM daemon state.
  All 17 `FPP_CMD_STAT_*` commands are whitelisted so CDX handles them
  directly. CLI sub-commands are implemented only for ported features
  (connection, interface, queue, VLAN, tunnel, IPsec, flow, route).
  PPPoE and Bridge stats are whitelisted but have no CLI; they become
  available automatically once those modules are ported — just add the
  CLI sub-command to `cmmctl_stat.c`.

- **Extending stats for new modules**: When a new feature module is ported
  (e.g., L2 Bridge, PPPoE), its stat commands are already whitelisted in
  `cmm_ctrl.c` and handled by CDX's `control_stat.c`. To expose the new
  stats in cmmctl: (1) add a `stat_<feature>()` function to
  `cmmctl_stat.c` following the two-phase STATUS/ENTRY iteration pattern,
  (2) add the sub-command to the dispatcher in `cmmctl_stat_main()`.
  No CMM daemon changes needed.

- **Socket acceleration module (#8)**: Command-driven socket registration
  for hardware offload of services running on the GDK itself (not
  forwarded traffic — that's handled by conntrack offload). Supports
  IPv4/IPv6, TCP/UDP, connected (5-tuple) and unconnected (3-tuple)
  modes. LANWAN type only; MSP/RTP/L2TP types available once those
  modules are ported. Route changes trigger automatic socket
  reprogramming via `cmm_socket_route_update()`. No IPsec integration
  yet (SA fields zeroed). CLI: `cmmctl socket open|close|update|show`.

- **L2 Bridge module (#4 + #16)**: Three tightly coupled components.
  (1) `auto_bridge.ko` — kernel module that hooks `bridge_forward()` via
  `bridge_l2flow_hook` in `if_bridge.c` to detect L2 flows crossing bridge
  ports. Maintains a hash table with state machine (CONFIRMED→FF/LINUX/DYING).
  Communicates with CMM via `/dev/autobridge` character device (kqueue-
  compatible ring buffer). Also hooks `bridge_rtage()` via
  `bridge_fdb_can_expire_hook` to prevent FDB expiry for offloaded MACs.
  Sysctl: `net.autobridge.*` (l3_filtering, timeout_confirmed, timeout_dying,
  max_entries, count).
  (2) `cmm_bridge.c` — combines Linux `module_rx.c` (L2 flow offload) and
  `ffbridge.c` (bridge port resolution). Reads flow events from
  `/dev/autobridge`, programs CDX via `FPP_CMD_RX_L2FLOW_ENTRY`. Scans
  bridges at startup via `getifaddrs`/`IFT_BRIDGE`, queries member ports
  via `BRDGGIFS` ioctl, resolves MAC→physical port via `BRDGRTS` ioctl for
  L3 routes through bridges. Handles CDX flow timeout (`ACTION_REMOVED`)
  via FCI event callback.
  (3) `cmmctl_bridge.c` — CLI: `cmmctl bridge enable|disable|mode|timeout|
  add|remove|show|reset`. All via FCI passthrough.
  Simplified from Linux: single hook point in `bridge_forward()` (both
  src_if and dst_if known), no SEEN state needed, 4-state machine instead
  of 5.

- **Deny rules module (#6)**: Three components. (1) FF enable/disable —
  `FPP_CMD_IPV4_FF_CONTROL` whitelisted, CDX sets global `ff_enable`.
  (2) IPsec pre-frag — `FPP_CMD_IPSEC_FRAG_CFG` whitelisted, CDX stub
  (accepted, no HW ops). (3) Deny rules — CMM-side config-file-driven
  filtering (`/usr/local/etc/cmm_deny.conf`). Rules match on proto, src/dst
  address with CIDR prefix, src/dst port, and interface name. Checked in
  `pfn_event_eligible()` before offload. No asymmetric fast-forward (Linux
  feature, not needed on GDK). To add deny-rule fields: extend
  `struct cmm_deny_rule` in `cmm_deny.h` and the parser/matcher in
  `cmm_deny.c`.

- **Packet capture module (#14)**: Full-stack implementation across CDX,
  CMM, and cmmctl. (1) `control_pktcap.c` in `cdx-5.03.1/` — CDX
  command handler that stores per-port capture state (enabled, slice
  size, BPF filter). Handles ENABLE, IFSTATUS, SLICE, FLF (with
  fragment reassembly), and QUERY commands. Previously behind
  `#ifdef CDX_TODO` — moved out and enabled. (2) CMM whitelist — four
  PKTCAP FPP commands added to `cmm_ctrl.c`. No daemon-side state
  needed (pure FCI passthrough). (3) `cmmctl_pktcap.c` — CLI with
  `status`, `slice`, `filter`, and `query` sub-commands. BPF filter
  compilation via libpcap (`pcap_compile()`), validated with ported
  `check_bpf_filter()` from Linux `module_pktcap.c`. Supports filter
  fragmentation (up to 90 BPF instructions across 3 fragments of 30
  each). Port IDs are numeric CDX port indices (0-7). Note: the CDX
  handler stores configuration state only — actual data-plane capture
  (FMan frame replication) is a separate hardware integration task.

- **Profiling module (#12)**: Pure cmmctl passthrough — no CMM daemon
  state. All 8 `FPP_CMD_TRC_*` commands (0x0f01–0x0f08) whitelisted in
  `cmm_ctrl.c`. CLI: `cmmctl prf status|trace|busycpu|dmem`. Trace
  sub-commands: `start [pmn0 [pmn1]]`, `stop`, `switch`, `show`,
  `setmask <mask>`. Busy CPU: `start [weight]`, `stop` (displays
  busy/idle cycle counts and percentage). Memory display: `dmem <addr>
  [len]` reads CDX memory via `FPP_CMD_TRC_DMEM` in 224-byte chunks.
  **CDX status**: `FC_TRC` maps to `EVENT_IPS_OUT` in
  `cdx_cmdhandler.c` but no handler is registered — commands currently
  return `ERR_UNKNOWN_COMMAND`. The CLI is ready for when CDX trace
  support is added.

- **NAT-PT module (#15)**: Pure FCI passthrough — no CMM daemon state.
  CDX `control_natpt.c` (already compiled and linked) handles OPEN
  (creates IPv6↔IPv4 CT pair, binds sockets), CLOSE (unbinds, removes
  CT entries), and QUERY (returns socket IDs, control flags, stats).
  Three `FPP_CMD_NATPT_*` commands whitelisted in `cmm_ctrl.c`. CLI:
  `cmmctl natpt open|close|query`. OPEN requires socket_a (IPv6) and
  socket_b (IPv4) to be pre-registered via `cmmctl socket open`, plus
  at least one direction flag (6to4, 4to6). QUERY displays control
  flags and 8 stat counters (v6/v4 received/transmitted/dropped/ACP).
  Stats are currently zeroed (CDX has `#ifdef CDX_TODO_STATS` stub).
  The Linux CMM daemon-side route rotation (auto-configuring socket
  input interfaces) is not implemented — sockets must be configured
  correctly before opening a NAT-PT pair.

- **ICC module (#11)**: Pure FCI passthrough — no CMM daemon state.
  **No CDX handler exists** (`control_icc.c` was never written) — all
  commands return `ERR_UNKNOWN_COMMAND`, same situation as profiling
  (#12). Event routing (`FC_ICC` → `EVENT_ICC`) and error codes are
  defined in CDX headers. Four `FPP_CMD_ICC_*` commands whitelisted in
  `cmm_ctrl.c`. CLI: `cmmctl icc reset|threshold|add|delete|query`.
  Supports 9 match types: ethertype, protocol (bitmask), DSCP
  (bitmask), IPv4/IPv6 source/dest address with CIDR, port ranges
  (sport/dport/both), and VLAN ID+priority ranges. Query uses
  iterative QUERY/QUERY_CONT protocol to enumerate all entries per
  interface (0-2). The CLI is ready for when a CDX ICC handler is
  implemented.

- **L2TP module (#17)**: Command-driven L2TP session management — unlike
  pure passthrough modules, requires CMM daemon state. Each L2TP session
  ties an interface to a UDP socket with tunnel/session IDs. FreeBSD has
  no native L2TP kernel driver, so all parameters come from cmmctl.
  (1) `cmm_l2tp.c` — daemon module. On `CMM_CTRL_CMD_L2TP_ADD`: allocates
  a UDP socket via `cmm_socket_next_id()`/`cmm_socket_fpp_open()`, resolves
  route to peer, then registers the L2TP interface in CDX via
  `FPP_CMD_L2TP_ITF_ADD` (ifname, sock_id, tunnel/session IDs, options).
  On `CMM_CTRL_CMD_L2TP_DEL`: sends `FPP_CMD_L2TP_ITF_DEL`, tears down
  the associated socket, clears interface state. Rollback on failure
  (socket deprogrammed + freed if CDX registration fails).
  (2) `cmm_socket.c` refactored — internal APIs (`cmm_socket_find`,
  `cmm_socket_next_id`, `cmm_socket_add`, `cmm_socket_remove`,
  `cmm_socket_fpp_open`, `cmm_socket_fpp_close`) exposed for cross-module
  use. Existing ctrl handlers become thin wrappers.
  (3) Interface state — `ITF_F_L2TP`/`ITF_F_FPP_L2TP` flags and L2TP
  fields (tunnel/session IDs, sock_id) in `cmm_interface`. Iterator
  `cmm_itf_foreach_l2tp()` for cleanup.
  (4) `cmmctl_l2tp.c` — CLI: `cmmctl l2tp add <ifname> <inet|inet6>
  <local-addr> <peer-addr> <local-port> <peer-port> <local-tun-id>
  <peer-tun-id> <local-ses-id> <peer-ses-id> [options [dscp [queue]]]`,
  `cmmctl l2tp del <ifname>`. Positional args, ports converted to network
  byte order. CDX `FC_L2TP` handler is registered (`CMD_INIT(l2tp)`), so
  commands should work — unlike TRC which has no handler.

- **TX DSCP map module (#19)**: Pure FCI passthrough — no CMM daemon state.
  Configures per-interface egress DSCP-to-VLAN-PCP mapping in CDX hardware.
  64 DSCP values grouped into 8 by top 3 bits (0-7), each mapped to a VLAN
  PCP value (0-7). CDX handler EXISTS (`control_tx.c`, `M_tx_cmdproc`) —
  calls down to `ExternalHashSetDscpVlanpcpMapCfg` in MURAM. Three FPP
  commands whitelisted in `cmm_ctrl.c` (`#ifdef LS1043`):
  `FPP_CMD_DSCP_VLANPCP_MAP_STATUS` (0x0506, enable/disable),
  `FPP_CMD_DSCP_VLANPCP_MAP_CFG` (0x0507, set mapping),
  `FPP_CMD_QUERY_IFACE_DSCP_VLANPCP_MAP` (0x0508, query). CLI:
  `cmmctl tx enable|disable <ifname>`, `cmmctl tx map <ifname> <dscp> <pcp>`,
  `cmmctl tx query <ifname>`. Query displays enabled/disabled status and
  a table of all 8 DSCP group→VLAN PCP mappings.

---

## Architecture: Polling vs Push-Based State Notifications

The Linux CMM receives per-connection events via netlink conntrack
(`NFCT_T_NEW/UPDATE/DESTROY`) — the kernel pushes notifications as
connections change.

### Implementation: `pf_notify.ko`

The `pf_notify` kernel module (`ASK/freebsd/pf_notify/`) hooks into PF
via dedicated `V_pfnotify_*_state_ptr` function pointers (added alongside
the existing pfsync hooks in `pfvar.h` / `pf.c`).  Events are delivered
to userspace via `/dev/pfnotify` — a kqueue-compatible character device
with a 4096-entry ring buffer.  Follows the same chardev + ring + kqueue
pattern as `auto_bridge`.

**Three event types:**
- `PFN_EVENT_INSERT` — new PF state created (from `pf_state_insert`)
- `PFN_EVENT_READY` — state became offload-ready: TCP ESTABLISHED or
  UDP bidirectional (from `pf_test` update hook, one-shot per state)
- `PFN_EVENT_DELETE` — PF state removed (from `pf_unlink_state`)

**One-shot UPDATE tracking:** A module-local `uint64_t[16384]` hash
indexed by state ID prevents per-packet READY flooding.  The UPDATE hook
checks readiness (TCP ESTABLISHED / UDP bidirectional) and the one-shot
array before queuing.  Collisions cause a harmless re-notification.

**Push-only approach:** CMM requires `pf_notify.ko` and uses push events
exclusively.  The ring buffer is 128K entries (dynamically allocated) and
READY events use a mark-after-enqueue design: if the ring is full, the
event is dropped but NOT marked as notified — the next packet for that
state re-triggers READY automatically.  A 30-second maintenance timer
retries offload for connections that failed initial offload (route/neighbor
not yet resolved) and garbage-collects stale routes.

**PF kernel changes** (~20 lines across 3 files):
- `sys/net/pfvar.h` — 3 new VNET hook typedefs + declarations
- `sys/netpfil/pf/pf_ioctl.c` — 3 VNET_DEFINE
- `sys/netpfil/pf/pf.c` — hook calls at 5 sites (1 insert, 3 update,
  1 delete), alongside existing pfsync calls

### kqueue integration: `d_kqfilter` (critical)

FreeBSD character devices **must** implement `d_kqfilter` for kqueue to
work.  `d_poll` alone is not enough — there is no fallback.
`prep_cdevsw()` in `kern/kern_conf.c` fills any unset `d_kqfilter` slot
with `no_kqfilter` (returns ENODEV).  `devfs_kqfilter_f()` calls
`dsw->d_kqfilter()` directly with no poll-based fallback path.

This means if a chardev provides only `d_poll`, `EVFILT_READ`
registration will silently fail.  When CMM registers all kqueue events
in a single `kevent()` call with `nevents=0`, the first registration
failure causes `kevent()` to return -1 — all subsequent events in the
changelist (including the reconciliation timer) are never registered.
CMM then exits immediately with "kevent register: Device not configured".

**Pattern used** (reference: `sys/dev/hid/hidraw.c`):

1. `struct filterops` with `f_isfd=1`, `f_detach`, `f_event`,
   `f_copy=knote_triv_copy`
2. `d_kqfilter` function: switch on `kn_filter`, set `kn_fop`, call
   `knlist_add(&rsel.si_note, kn, 0)`
3. `f_event` callback: set `kn_data` to readable bytes, return data
   available
4. `f_detach` callback: `knlist_remove(&rsel.si_note, kn, 0)`
5. `KNOTE_LOCKED(&rsel.si_note, 0)` in the event producer (alongside
   `selwakeup`)
6. `knlist_clear` + `knlist_destroy` in module unload

The `knlist_init_mtx(&rsel.si_note, &mtx)` in module load associates the
knlist with the module mutex — all `f_event` callbacks are called with
the mutex held.

### CMM event loop integration

CMM opens `/dev/pfnotify` at startup (`O_RDONLY | O_NONBLOCK`).  The fd
is registered in the main kqueue alongside route socket, FCI, PF_KEY,
control socket, and auto_bridge fds.  A udata tag (`(void *)4`)
distinguishes pfnotify events in the dispatch loop.

Two timers in the event loop:
- **Stats sync** (ident 5): 5 seconds (`CMM_STATS_SYNC_MS`) — syncs CDX flow counters to PF state table
- **Maintenance** (ident 6): 30 seconds (`CMM_MAINT_MS`) — retries pending offloads, route GC, stats log

On `EVFILT_READ` for pfnotify, CMM reads events in a loop and dispatches:
- `PFN_EVENT_READY` → attempt offload (same path as poll-discovered
  ESTABLISHED connections)
- `PFN_EVENT_DELETE` → deregister offloaded flow from CDX
- `PFN_EVENT_INSERT` → logged at debug level, no immediate action

**Build:** `make -C .../ASK/freebsd/pf_notify $KBUILD MACHINE=arm64 ...`
**Load:** `kldload pf_notify` (after PF, before CMM)
**Sysctls:** `net.pfnotify.{ring_size,events_total,events_dropped}`
**Verified:** 10 Gb/s sustained throughput with push-mode offload
