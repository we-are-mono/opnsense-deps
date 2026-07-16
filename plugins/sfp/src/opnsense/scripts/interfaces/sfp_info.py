#!/usr/local/bin/python3

"""
SFP/SFP+ module information reader for the Mono Gateway.

Reads the raw module EEPROM (SFF-8472 A0h + A2h pages) exported by the dtsec
driver via `dev.dtsec.<unit>.sfp_eeprom` (a hex string) and decodes it into a
flat {label: value} dict for the interface details popup.
"""

import json
import math
import re
import struct
import subprocess
import sys


HEX_RE = re.compile(r'^[0-9a-fA-F]*$')

CONNECTORS = {
    0x00: "Unknown",
    0x01: "SC",
    0x07: "LC",
    0x0B: "Optical pigtail",
    0x0C: "MPO 1x12",
    0x21: "Copper pigtail",
    0x22: "RJ45",
    0x23: "No separable connector",
}

_ALARM_112 = [
    (0x80, "Temp high"), (0x40, "Temp low"),
    (0x20, "Vcc high"), (0x10, "Vcc low"),
    (0x08, "TX bias high"), (0x04, "TX bias low"),
    (0x02, "TX power high"), (0x01, "TX power low"),
]
_ALARM_113 = [
    (0x80, "RX power high"), (0x40, "RX power low"),
]


def _ascii(b):
    return bytes(b).decode("ascii", "replace").strip()


def _u16(b, off):
    return (b[off] << 8) | b[off + 1]


def _s16(b, off):
    v = _u16(b, off)
    return v - 0x10000 if (v & 0x8000) else v


def _f32(b, off):
    return struct.unpack(">f", bytes(b[off:off + 4]))[0]


def _slope(b, off):
    return b[off] + b[off + 1] / 256.0


def _dbm(mw):
    if mw <= 0:
        return "-inf"
    return "%.2f dBm" % (10.0 * math.log10(mw))


def media_type(a0):
    """Best-effort media/compliance string from connector + compliance codes."""
    conn = a0[2]
    # Copper RJ45 modules embed a PHY and report their real link type over MDIO,
    # not in the SFF optical/cable compliance bytes — which they routinely set
    # spuriously (e.g. FS SFP-10G-T sets the passive-DAC bit, Ubiquiti
    # UACC-CM-RJ45-MG sets the 10GBASE-SR bit). Classify these by the declared
    # max signaling rate (byte 12, units of 100 Mbps) instead; the PHY
    # negotiates the actual mode (2.5G/5G/...) and the kernel logs it separately.
    if conn == 0x22:               # RJ45
        rate = a0[12] * 100        # Mbps; module's maximum rate
        if rate >= 10000:
            return "10GBASE-T"
        if rate >= 5000:
            return "5GBASE-T"
        if rate >= 2500:
            return "2.5GBASE-T"
        if rate >= 1000:
            return "1000BASE-T"
        if rate >= 100:
            return "100BASE-TX"
        return "10GBASE-T"         # rate undeclared: default to the cage's max
    codes = []
    eth10g = a0[3]
    if eth10g & 0x10:
        codes.append("10GBASE-SR")
    if eth10g & 0x20:
        codes.append("10GBASE-LR")
    if eth10g & 0x40:
        codes.append("10GBASE-LRM")
    if eth10g & 0x80:
        codes.append("10GBASE-ER")
    eth1g = a0[6]
    if eth1g & 0x01:
        codes.append("1000BASE-SX")
    if eth1g & 0x02:
        codes.append("1000BASE-LX")
    if eth1g & 0x08:
        codes.append("1000BASE-T")
    cable = a0[8]  # SFP+ cable technology
    if cable & 0x04:
        codes.append("10GBASE-CR (passive)")
    if cable & 0x08:
        codes.append("10GBASE-CR (active)")
    return ", ".join(codes) if codes else "Unknown"


def decode_alarms(a2):
    active = []
    for bit, label in _ALARM_112:
        if a2[112] & bit:
            active.append(label)
    for bit, label in _ALARM_113:
        if a2[113] & bit:
            active.append(label)
    return ", ".join(active) if active else "none"


def decode_ddm(a0, a2):
    """Return DDM (diagnostics) fields if implemented, else {}."""
    dmt = a0[92]
    if not (dmt & 0x40):           # bit6: DDM implemented
        return {}
    external = bool(dmt & 0x10)    # bit4: externally calibrated

    t_raw = _s16(a2, 96)
    v_raw = _u16(a2, 98)
    bias_raw = _u16(a2, 100)
    txp_raw = _u16(a2, 102)
    rxp_raw = _u16(a2, 104)

    if external:
        t_cnt = _slope(a2, 84) * t_raw + _s16(a2, 86)
        v_cnt = _slope(a2, 88) * v_raw + _s16(a2, 90)
        bias_cnt = _slope(a2, 76) * bias_raw + _s16(a2, 78)
        txp_cnt = _slope(a2, 80) * txp_raw + _s16(a2, 82)
        c4 = _f32(a2, 56); c3 = _f32(a2, 60); c2 = _f32(a2, 64)
        c1 = _f32(a2, 68); c0 = _f32(a2, 72)
        rxp_cnt = (c4 * rxp_raw ** 4 + c3 * rxp_raw ** 3 +
                   c2 * rxp_raw ** 2 + c1 * rxp_raw + c0)
    else:
        t_cnt, v_cnt, bias_cnt, txp_cnt, rxp_cnt = \
            t_raw, v_raw, bias_raw, txp_raw, rxp_raw

    temp_c = t_cnt / 256.0
    vcc_v = v_cnt * 0.0001          # LSB 100 uV
    bias_ma = bias_cnt * 0.002      # LSB 2 uA
    txp_mw = txp_cnt * 0.0001       # LSB 0.1 uW
    rxp_mw = rxp_cnt * 0.0001       # LSB 0.1 uW

    return {
        "Temperature": "%.1f °C" % temp_c,
        "Supply Voltage": "%.2f V" % vcc_v,
        "TX Bias": "%.2f mA" % bias_ma,
        "TX Power": _dbm(txp_mw),
        "RX Power": _dbm(rxp_mw),
        "Alarms": decode_alarms(a2),
    }


def decode(a0, a2):
    """Decode A0h+A2h byte arrays into a flat ordered {label: value} dict."""
    if len(a0) < 96 or a0[0] == 0x00:
        return {}
    info = {}
    info["Type"] = media_type(a0)
    info["Connector"] = CONNECTORS.get(a0[2], "0x%02x" % a0[2])
    info["Vendor"] = _ascii(a0[20:36])
    info["OUI"] = "%02x:%02x:%02x" % (a0[37], a0[38], a0[39])
    info["Part Number"] = _ascii(a0[40:56])
    info["Revision"] = _ascii(a0[56:60])
    info["Serial Number"] = _ascii(a0[68:84])
    info["Date Code"] = _ascii(a0[84:92])
    bitrate = a0[12]
    if bitrate:
        info["Nominal Bitrate"] = "%d Mbps" % (bitrate * 100)
    wl = _u16(a0, 60)
    if a0[2] in (0x01, 0x07, 0x0B, 0x0C) and wl:  # optical connectors only
        info["Wavelength"] = "%d nm" % wl
    info.update(decode_ddm(a0, a2))
    return {k: v for k, v in info.items() if v not in ("", None)}


def _hex_to_bytes(s):
    s = (s or "").strip()
    if not s or not HEX_RE.match(s):
        return None
    try:
        return bytearray.fromhex(s)
    except ValueError:
        return None


def read_eeprom(ifname):
    """Return (a0, a2) bytearrays for the interface, or None if unavailable."""
    m = re.fullmatch(r"dtsec(\d+)", ifname or "")
    if not m:
        return None
    oid = "dev.dtsec.%s.sfp_eeprom" % m.group(1)
    try:
        out = subprocess.run(
            ["/sbin/sysctl", "-nq", oid],
            capture_output=True, text=True
        ).stdout.strip()
    except OSError:
        return None
    raw = _hex_to_bytes(out)
    if raw is None or len(raw) < 512:
        return None
    return raw[:256], raw[256:512]


def read_phy_modes(ifname):
    """Supported copper PHY rates (e.g. "1G, 2.5G, 5G, 10G"), or "" if N/A.

    Sourced from the dtsec driver, which reads the module PHY's MDIO ability
    registers — the SFF EEPROM cannot enumerate negotiable rates. Empty for
    fiber/DAC modules and 10G-only copper without multigig support.
    """
    m = re.fullmatch(r"dtsec(\d+)", ifname or "")
    if not m:
        return ""
    oid = "dev.dtsec.%s.sfp_phy_modes" % m.group(1)
    try:
        return subprocess.run(
            ["/sbin/sysctl", "-nq", oid],
            capture_output=True, text=True
        ).stdout.strip()
    except OSError:
        return ""


def info_for(ifname):
    pages = read_eeprom(ifname)
    if pages is None:
        return {}
    info = decode(pages[0], pages[1])
    if info:
        modes = read_phy_modes(ifname)
        if modes:
            info["Supported Rates"] = modes
    return info


if __name__ == "__main__":
    ifname = sys.argv[1] if len(sys.argv) > 1 else ""
    print(json.dumps(info_for(ifname)))
