# Architecture Overview

Hardware flow offload stack for the Mono Gateway (NXP LS1046A / DPAA1).
Packets matching offloaded flows are forwarded entirely in FMan hardware,
bypassing the FreeBSD networking stack.

## System Diagram

```
 ┌────────────────────────────────────────────────────────────────┐
 │  USERSPACE                                                     │
 │                                                                │
 │  ┌─────────┐    ┌─────────┐    ┌──────────┐    ┌────────────┐  │
 │  │   cmm   │    │ dpa_app │    │   fand   │    │  cmmctl    │  │
 │  │         │    │         │    │          │    │            │  │
 │  │ offload │    │ PCD     │    │ fan      │    │ query/ctrl │  │
 │  │ manager │    │ setup   │    │ control  │    │ tool       │  │
 │  └────┬────┘    └────┬────┘    └──────────┘    └─────┬──────┘  │
 │       │FCI           │chardev                        │socket   │
 │ ══════╪══════════════╪═══════════════════════════════╪═══════  │
 │  KERNEL              │                               │         │
 │       │         ┌────┴────┐                          │         │
 │  ┌────┴────┐    │  fmc    │                     ┌────┴────┐    │
 │  │ fci.ko  │    │ chardev │                     │  cmm    │    │
 │  │         │    │ (fman)  │                     │ ctrl    │    │
 │  │ cmd/evt │    └────┬────┘                     │ socket  │    │
 │  │ channel │         │FM ioctl                  └─────────┘    │
 │  └────┬────┘    ┌────┴────────────────────────┐                │
 │       │         │     FreeBSD DPAA1 kernel    │                │
 │  ┌────┴────┐    │  (dtsec, QMan, BMan, FMan)  │                │
 │  │ cdx.ko  │    └────┬────────────────────────┘                │
 │  │         │         │                                         │
 │  │ flow    │    ┌────┴────┐  ┌────────────┐  ┌─────────────┐   │
 │  │ engine  │    │pf_notify│  │auto_bridge │  │   caam.ko   │   │
 │  └────┬────┘    │  .ko    │  │    .ko     │  │  (crypto)   │   │
 │       │         └────┬────┘  └─────┬──────┘  └─────────────┘   │
 │       │              │             │                           │
 │  ┌────┴──────────────┴─────────────┴──────────────────────┐    │
 │  │                  FMan Hardware                         │    │
 │  │   Parser -> KeyGen -> CC/Hash Tables --> Policer/EN.   │    │
 │  └────────────────────────────────────────────────────────┘    │
 └────────────────────────────────────────────────────────────────┘
```

## Boot Sequence

```
kernel boot
  └─► kldload cdx fci pf_notify auto_bridge
        └─► dpa_app /etc/cdx_pcd.xml /etc/cdx_cfg.xml /etc/cdx_sp.xml
              └─► service cmm start
```

## Fastpath Modules

### cdx.ko — Flow Offload Engine (kernel module)

The core datapath acceleration module. Receives conntrack and route
registrations from CMM via FCI, installs flow entries in FMan's
enhanced hash tables, and executes packet transformations (NAT,
TTL decrement, MAC rewrite) in hardware.

- **Timer wheel**: Ages out idle flows (TCP ~12h, UDP unidir ~5min)
- **Miss path**: Unmatched packets enqueue to dtsec default RX FQID (software path)
- **Notifications**: Sends `CONNTRACK_CHANGE` events back to CMM via FCI when flows expire

Source: `fastpath/cdx/` + `fastpath/vendor/cdx/`

### fci.ko — Fast Control Interface (kernel module)

IPC channel between userspace (CMM) and kernel (CDX). Provides:

- **Command path** (CMM → CDX): register/deregister routes, conntrack entries, L2 flows
- **Event path** (CDX → CMM): flow timeout notifications, TCP FIN events
- **Mechanism**: chardev with ioctl for commands, ring buffer + kqueue for async events

Source: `fastpath/fci/`

### pf_notify.ko — PF State Event Bridge (kernel module)

Hooks into the PF firewall to push state change events to userspace:

- `PFN_EVENT_INSERT` — new state created
- `PFN_EVENT_READY` — state became offload-eligible (TCP ESTABLISHED)
- `PFN_EVENT_DELETE` — state removed by PF

Exposes `/dev/pfnotify` (read-only, non-blocking). Without this module,
CMM falls back to polling the PF state table every 1s.

Source: `fastpath/pf_notify/`

### auto_bridge.ko — L2 Bridge Flow Offload (kernel module)

Captures L2 forwarding decisions from the FreeBSD bridge and
exposes them to CMM for hardware offload. Exposes `/dev/autobridge`.

Source: `fastpath/auto_bridge/`

### cmm — Connection Management Module (userspace daemon)

The orchestrator. Monitors PF state and routing tables, resolves
next-hop neighbors, and programs CDX with offload entries.

```
                 ┌──────────────┐
  /dev/pfnotify  │              │ FCI commands
  PF state poll  │     CMM      ├──────────────► cdx.ko
  route socket   │              │
  PF_KEY socket  │  event loop  │◄────────────── FCI events
  /dev/autobridge│   (kqueue)   │                (flow timeout)
  ctrl socket    │              │
                 └──────────────┘
```

**Flow lifecycle**:
1. PF creates state → pfnotify READY → CMM resolves route + neighbor
2. CMM sends route + conntrack to CDX via FCI → flow in hardware
3. Packets forwarded at line rate by FMan, bypassing stack
4. CDX timer expires or TCP FIN → FCI event → CMM clears offload flag
5. If PF state still alive → next poll re-offloads automatically

Source: `fastpath/cmm/`

### cmmctl — CMM Control Tool (userspace)

CLI tool to query CMM state (offloaded connections, routes, stats)
via a unix domain socket.

Source: `fastpath/cmmctl/`

### dpa_app — PCD Configuration Tool (userspace)

Loads FMan Parser/Classification/Distribution configuration from
XML files via the FMan chardev. Sets up the KeyGen hash schemes
and CC tree that CDX later patches with per-flow entries.

Depends on: fmlib (FMan API), fmc (XML parser/compiler)

Source: `fastpath/dpa_app/`, `fastpath/fmc/`, `fastpath/fmlib/`

## Hardware Drivers

### emc2302.ko — Fan Controller

I2C driver for EMC2302 fan controller. Exposes sysctl interface
for fan RPM reading and PWM duty cycle control.

Source: `drivers/emc2302/`

### ina2xx.ko — Power Monitor

I2C driver for INA226/INA219 current/voltage/power monitors.
Exposes sysctl interface for voltage, current, and power readings.

Source: `drivers/ina2xx/`

### lp5812.ko — RGB LED Controller

I2C driver for TI LP5812 LED controller. Drives the board's
RGB status LEDs.

Source: `drivers/lp5812/`

### sfpled.ko — SFP+ Link LEDs

GPIO-based LED driver that reflects SFP+ link state on
front-panel LEDs by polling dtsec link status.

Source: `drivers/sfp-led/`

### fand — Fan Control Daemon (userspace)

Reads temperature sensors and adjusts fan speed via emc2302
sysctl interface. Runs as a daemon.

Source: `drivers/fand/`

## Data Flow: Packet Through Hardware Offload

```
Wire ──► FMan RX Port
           │
           ▼
         Parser (extract L3/L4 headers)
           │
           ▼
         KeyGen (hash IP src/dst + L4 ports)
           │
           ▼
         CC Hash Table lookup
          ╱              ╲
       HIT              MISS
        │                  │
        ▼                  ▼
   CDX opcodes         Default RX FQID
   (NAT rewrite,       (FreeBSD stack)
    TTL dec,              │
    MAC rewrite)          ▼
        │              PF firewall
        ▼              routing
   FMan TX Port        if_output
        │                 │
        ▼                 ▼
      Wire              Wire
   (line rate)       (software path)
```

## IPC Summary

| Path | Mechanism | Purpose |
|------|-----------|---------|
| CMM → CDX | FCI ioctl | Register/deregister routes, conntrack, L2 flows |
| CDX → CMM | FCI ring + kqueue | Flow timeout, TCP FIN notifications |
| PF → CMM | /dev/pfnotify | State insert/ready/delete events |
| CMM ← PF | DIOCGETSTATESV2 ioctl | Periodic state table poll (fallback) |
| CMM ← routing | PF_ROUTE socket | Route/neighbor/interface changes |
| CMM ← IPsec | PF_KEY socket | SA add/delete events |
| CMM ← bridge | /dev/autobridge | L2 flow learning events |
| cmmctl → CMM | Unix socket | Query/control commands |
| dpa_app → FMan | /dev/fman chardev | PCD configuration (XML → hardware) |
