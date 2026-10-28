#!/usr/bin/env python3
import json
import sys

try:
    data = json.load(sys.stdin)
except json.JSONDecodeError as error:
    print(f"Invalid simctl JSON: {error}", file=sys.stderr)
    sys.exit(1)

candidates = []
for runtime, devices in data.get("devices", {}).items():
    if "iOS" not in runtime:
        continue
    for device in devices:
        if device.get("isAvailable") and device.get("name", "").startswith("iPhone"):
            candidates.append(device)

if not candidates:
    print("No available iPhone simulator was found", file=sys.stderr)
    sys.exit(1)

candidates.sort(key=lambda device: (
    device.get("name") != "iPhone 17 Pro",
    device.get("name", ""),
    device.get("udid", ""),
))
print(candidates[0]["udid"])
