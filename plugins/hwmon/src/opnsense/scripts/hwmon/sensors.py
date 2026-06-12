#!/usr/local/bin/python3

"""
Hardware sensor reader for Mono Gateway dashboard widget.
Discovers and reads INA2xx power monitors and EMC2302 fan controllers
via sysctl.
"""

import json
import subprocess
import sys


def sysctl_tree(prefix):
    """Read all sysctls under prefix, return dict of name->value."""
    sp = subprocess.run(
        ['/sbin/sysctl', '-i', prefix],
        capture_output=True, text=True
    )
    result = {}
    for line in sp.stdout.splitlines():
        parts = line.split(': ', 1)
        if len(parts) == 2:
            result[parts[0].strip()] = parts[1].strip()
    return result


def parse_power(raw):
    """Parse dev.ina2xx.* into power sensor list."""
    # Group by device instance
    instances = {}
    for key, val in raw.items():
        # dev.ina2xx.0.bus_voltage -> instance=0, field=bus_voltage
        parts = key.split('.')
        if len(parts) < 4 or parts[0] != 'dev' or parts[1] != 'ina2xx':
            continue
        try:
            idx = int(parts[2])
        except ValueError:
            continue
        field = '.'.join(parts[3:])
        instances.setdefault(idx, {})[field] = val

    sensors = []
    for idx in sorted(instances):
        fields = instances[idx]
        label = fields.get('label', f'ina2xx.{idx}')
        try:
            voltage = int(fields.get('bus_voltage', 0))
            current = int(fields.get('current', 0))
            power = int(fields.get('power', 0))
        except ValueError:
            continue
        sensors.append({
            'label': label,
            'voltage': voltage,
            'current': current,
            'power': power,
        })
    return sensors


def parse_fans(raw):
    """Parse dev.emc2302.* into fan list."""
    # Group by controller then fan
    controllers = {}
    for key, val in raw.items():
        parts = key.split('.')
        if len(parts) < 5 or parts[0] != 'dev' or parts[1] != 'emc2302':
            continue
        try:
            ctrl = int(parts[2])
        except ValueError:
            continue
        fan_field = '.'.join(parts[3:])
        # e.g. fan0.rpm, fan1.pwm
        controllers.setdefault(ctrl, {})[fan_field] = val

    fans = []
    for ctrl in sorted(controllers):
        fields = controllers[ctrl]
        # Discover fan channels
        fan_ids = set()
        for k in fields:
            if k.startswith('fan') and '.' in k:
                fan_ids.add(k.split('.')[0])
        for fan_id in sorted(fan_ids):
            try:
                rpm = int(fields.get(f'{fan_id}.rpm', 0))
                pwm_raw = int(fields.get(f'{fan_id}.pwm', 0))
                fault = int(fields.get(f'{fan_id}.fault', 0))
            except ValueError:
                continue
            pwm_pct = round(pwm_raw * 100 / 255)
            # Skip fans with 0 RPM (stalled or not connected)
            if rpm == 0:
                continue
            # The board has a single SoC fan on fan0; give it a friendly name.
            label = 'SoC Fan' if fan_id == 'fan0' else fan_id
            fans.append({
                'label': label,
                'rpm': rpm,
                'pwm': pwm_pct,
                'fault': fault != 0,
            })
    return fans


if __name__ == '__main__':
    power_raw = sysctl_tree('dev.ina2xx')
    fan_raw = sysctl_tree('dev.emc2302')

    result = {
        'power': parse_power(power_raw),
        'fans': parse_fans(fan_raw),
    }

    print(json.dumps(result))
