# cmmctl Command Reference

`cmmctl` is the CLI for the Connection Management Module (CMM). It communicates with the CMM daemon over a Unix socket (`/run/cmm.ctrl`) to query and configure CDX hardware flow offload.

## stat — Statistics

Query and control CDX hardware counters. Most stat categories must be enabled before querying (error 1100 = feature not enabled).

```sh
# Enable stat collection (must do this before querying)
cmmctl stat enable interface
cmmctl stat enable flow
cmmctl stat enable queue
cmmctl stat enable bridge
cmmctl stat enable ipsec
cmmctl stat enable vlan
cmmctl stat enable tunnel
cmmctl stat enable pppoe

# Disable stat collection
cmmctl stat disable flow

# Connection counts (offloaded IPv4/IPv6 flows)
cmmctl stat conn
cmmctl stat conn reset

# Interface packet/byte counters
cmmctl stat iface dtsec3
cmmctl stat iface dtsec4 reset

# Per-queue counters
cmmctl stat queue dtsec3 0
cmmctl stat queue dtsec4 2 reset

# VLAN counters
cmmctl stat vlan
cmmctl stat vlan reset

# Tunnel counters
cmmctl stat tunnel
cmmctl stat tunnel gif0
cmmctl stat tunnel gif0 reset

# IPsec SA counters
cmmctl stat ipsec
cmmctl stat ipsec reset

# Per-flow counters (proto: 6=TCP, 17=UDP)
cmmctl stat flow 6 10.0.0.141 192.168.1.72 443 52000
cmmctl stat flow 6 10.0.0.141 192.168.1.72 443 52000 reset

# IP reassembly stats
cmmctl stat route v4
cmmctl stat route v6
```

Features for enable/disable: `queue`, `interface`, `pppoe`, `bridge`, `ipsec`, `vlan`, `tunnel`, `flow`.

## ff — Fast-Forward Control

Enable or disable CDX hardware flow offload globally.

```sh
cmmctl ff enable
cmmctl ff disable

# IPsec pre-fragmentation (fragment before encryption)
cmmctl ff ipsec-frag enable
cmmctl ff ipsec-frag disable
```

## qm — QoS / Queue Manager

### Interface QoS

```sh
# Enable/disable/reset QoS on an interface
cmmctl qm enable dtsec3
cmmctl qm disable dtsec3
cmmctl qm reset dtsec3

# Interface-level shaper (rate in kbps, bucketsize in bytes)
cmmctl qm shaper dtsec3 on rate 100000 bucketsize 65536
cmmctl qm shaper dtsec3 off
```

### Channels and Class Queues

```sh
# Assign channel to interface (channels 1-8)
cmmctl qm channel 1 assign dtsec3

# Channel shaper
cmmctl qm channel 1 shaper on rate 50000 bucketsize 32768
cmmctl qm channel 1 shaper off

# Weighted fair queuing
cmmctl qm channel 1 wbfq chshaper on priority 3

# Class queue configuration
cmmctl qm channel 1 cq 0 qdepth 64 weight 10
cmmctl qm channel 1 cq 0 chshaper on cqshaper on rate 10000
```

### DSCP-to-Queue Mapping

```sh
# Enable/disable DSCP-based queue selection
cmmctl qm dscp-fqmap dtsec3 enable
cmmctl qm dscp-fqmap dtsec3 disable

# Map DSCP value to channel + class queue
cmmctl qm dscp-fqmap dtsec3 dscp 46 channel-id 1 classqueue 0
cmmctl qm dscp-fqmap dtsec3 dscp 0 reset
```

### Rate Limiting

```sh
# Exception path rate limit (packets/sec + burst)
cmmctl qm exptrate eth 195312 64

# Fast-forward rate (CIR/PIR in kbps)
cmmctl qm ffrate dtsec3 cir 1000000 pir 1000000
```

### Ingress Policer

```sh
cmmctl qm ingress queue 0 policer on
cmmctl qm ingress queue 0 cir 500000 pir 1000000
cmmctl qm ingress reset
```

### Show / Query

```sh
cmmctl qm show dtsec3
cmmctl qm show dtsec3 clearstats
cmmctl qm show exptrate eth
cmmctl qm show exptrate eth clear
cmmctl qm show ffrate dtsec3
cmmctl qm show ffrate dtsec3 clear
cmmctl qm show dscp-fqmap dtsec3
cmmctl qm show cq 1 0
cmmctl qm show cq 1 0 clear
cmmctl qm show ingress
cmmctl qm show ingress clear
```

## tunnel — Tunnel Offload

Register tunnel interfaces for CDX hardware offload.

```sh
cmmctl tunnel add gif0
cmmctl tunnel del gif0
cmmctl tunnel show
cmmctl tunnel show gif0
```

Supported tunnel modes: ethipoip6, 6o4, 4o6, ethipoip4, gre6.

## socket — Socket Acceleration

Accelerate specific sockets by steering matching traffic to a dedicated queue.

```sh
# Open an accelerated socket
cmmctl socket open id=1 proto=tcp daddr=10.0.0.141 dport=443
cmmctl socket open id=2 proto=udp daddr=10.0.0.141 dport=5201 saddr=192.168.1.1 sport=5201 queue=3 dscp=46

# Update socket parameters
cmmctl socket update id=2 queue=4 dscp=0

# Close
cmmctl socket close id=1
cmmctl socket close id=2

# Show accelerated socket stats
cmmctl socket show
```

## bridge — L2 Bridge Offload

Hardware-accelerated L2 bridging via CDX flow entries.

```sh
# Enable/disable bridge offload on an interface
cmmctl bridge enable bridge0
cmmctl bridge disable bridge0

# Set bridge mode
cmmctl bridge mode auto
cmmctl bridge mode manual

# Set flow timeout (seconds, 1-65535)
cmmctl bridge timeout 300

# Add a static L2 flow entry
cmmctl bridge add srcmac=00:1a:2b:3c:4d:5e dstmac=00:5e:4d:3c:2b:1a input=dtsec3 output=dtsec4
cmmctl bridge add srcmac=00:1a:2b:3c:4d:5e dstmac=00:5e:4d:3c:2b:1a input=dtsec3 output=dtsec4 ethertype=0x0800 prio=7

# Remove a flow entry
cmmctl bridge remove srcmac=00:1a:2b:3c:4d:5e dstmac=00:5e:4d:3c:2b:1a input=dtsec3

# Show bridge state
cmmctl bridge show flows
cmmctl bridge show status

# Reset all bridge flows
cmmctl bridge reset
```

## pktcap — Packet Capture

CDX hardware packet capture (ports 0-7).

```sh
# Enable/disable capture on a port
cmmctl pktcap status 0 enable
cmmctl pktcap status 0 disable

# Set capture slice size (40-1518 bytes)
cmmctl pktcap slice 0 128

# Set BPF filter expression
cmmctl pktcap filter 0 "host 10.0.0.141 and tcp port 443"
cmmctl pktcap filter 0 reset

# Query capture status
cmmctl pktcap query
```

## prf — FPP Trace / Profiling

Low-level CDX fast-path processor diagnostics.

```sh
# Query trace state
cmmctl prf status

# Trace control
cmmctl prf trace start
cmmctl prf trace start 0x01 0x02    # with performance monitor counters
cmmctl prf trace stop               # stop + display buffer
cmmctl prf trace switch             # switch buffers + display current
cmmctl prf trace show               # display current buffer
cmmctl prf trace setmask 0xff       # set module trace mask

# CPU busy/idle measurement
cmmctl prf busycpu start
cmmctl prf busycpu start 50         # with weight parameter
cmmctl prf busycpu stop

# Read CDX memory (hex dump)
cmmctl prf dmem 0x80000000
cmmctl prf dmem 0x80000000 64
```

## natpt — NAT-PT Translation

NAT Protocol Translation between IPv4 and IPv6. Requires sockets registered via `cmmctl socket open` first.

```sh
cmmctl natpt open 1 2 6to4
cmmctl natpt open 1 2 4to6
cmmctl natpt query 1 2
cmmctl natpt close 1 2
```

Arguments are socket IDs (from `cmmctl socket open`).

## icc — Ingress Congestion Control

Classify and police ingress traffic to prevent buffer exhaustion.

```sh
# Reset ICC state
cmmctl icc reset

# Set buffer thresholds (BMU1/BMU2, 0-1024)
cmmctl icc threshold 512 256

# Add classification rules (interface index 0-2)
cmmctl icc add 0 ethertype 0x0800
cmmctl icc add 0 protocol 6 17
cmmctl icc add 0 dscp 46 48
cmmctl icc add 0 saddr 10.0.0.0 24
cmmctl icc add 0 daddr 192.168.1.0 24
cmmctl icc add 0 saddr6 fd00:: 64
cmmctl icc add 0 daddr6 2001:db8:: 48
cmmctl icc add 0 port 1024-65535 80-443
cmmctl icc add 0 sport 1024-65535
cmmctl icc add 0 dport 80-443
cmmctl icc add 0 vlan 100-200 0-7

# Delete rules (same syntax as add)
cmmctl icc delete 0 protocol 6

# Query rules
cmmctl icc query
cmmctl icc query 0
```

## l2tp — L2TP Tunnel Interfaces

Register L2TP tunnels for CDX offload.

```sh
# Add L2TP tunnel
# Args: <ifname> <inet|inet6> <local_addr> <peer_addr>
#        <local_port> <peer_port> <local_tun_id> <peer_tun_id>
#        <local_ses_id> <peer_ses_id> [options [dscp [queue]]]
cmmctl l2tp add l2tp0 inet 10.0.0.94 10.0.0.141 1701 1701 1 2 1 2
cmmctl l2tp add l2tp1 inet6 fd00::1 fd00::2 1701 1701 3 4 3 4 0 46 2

# Delete
cmmctl l2tp del l2tp0
```

## macvlan — Virtual MAC Interfaces

Register virtual MAC (macvlan) interfaces for CDX lookup.

```sh
# Add/remove macvlan mapping
cmmctl macvlan add macvlan0 dtsec3 02:00:00:00:00:01
cmmctl macvlan del macvlan0 dtsec3 02:00:00:00:00:01

# Query all entries
cmmctl macvlan query

# Reset all entries
cmmctl macvlan reset
```

## tx — TX DSCP to VLAN PCP Mapping

Map outgoing DSCP values to 802.1Q VLAN priority code points.

```sh
# Enable/disable on an interface
cmmctl tx enable dtsec3
cmmctl tx disable dtsec3

# Map DSCP group to PCP (group 0=DSCP 0-7, 1=DSCP 8-15, ..., 7=DSCP 56-63)
cmmctl tx map dtsec3 5 5    # DSCP 40-47 → PCP 5 (EF/voice)
cmmctl tx map dtsec3 0 0    # DSCP 0-7 → PCP 0 (best effort)

# Query current mapping
cmmctl tx query dtsec3
```

## mc4 — IPv4 Multicast Offload

Program CDX hardware multicast replication for IPv4 groups.

```sh
# Add multicast group (dst, src, input interface, output interface)
cmmctl mc4 add 239.1.1.1 10.0.0.1 dtsec3 dtsec4

# Remove a listener
cmmctl mc4 remove 239.1.1.1 10.0.0.1 dtsec4

# Query all groups
cmmctl mc4 query

# Reset all groups
cmmctl mc4 reset
```

## mc6 — IPv6 Multicast Offload

Program CDX hardware multicast replication for IPv6 groups.

```sh
# Add multicast group
cmmctl mc6 add ff38::1 2001:db8::1 dtsec3 dtsec4

# Remove a listener
cmmctl mc6 remove ff38::1 2001:db8::1 dtsec4

# Query all groups
cmmctl mc6 query

# Reset all groups
cmmctl mc6 reset
```
