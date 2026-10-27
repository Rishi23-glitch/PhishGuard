"""
snort_integration.py

Connects PhishGuard to Snort. Snort writes one line per alert to its
"fast" alert log whenever live traffic matches a rule. This module
tails that log and parses each alert into structured JSON for the
/network-alerts endpoint.

Run the Flask backend from INSIDE the same WSL session Snort runs in
so this can read Snort's log at its native Linux path. Start Snort
with:
    sudo snort -A fast -k none -c /etc/snort/snort.conf -i eth0 -l /var/log/snort

(-k none is needed on WSL2: the virtual NIC produces packets with bad
checksums, and Snort silently skips rule matching on them.)
"""

import os
import re

SNORT_ALERT_LOG = os.environ.get("SNORT_ALERT_LOG", "/var/log/snort/alert")

# SIDs of PhishGuard's own custom rules (flagged in the UI)
CUSTOM_SIDS = {"1000001", "1000050"}

# The [Classification: ...] block is OPTIONAL: Snort only writes it when a
# rule has a classtype. Rules without one look like:
#   10/26-00:11:17.078994  [**] [1:1000050:1] ICMP test [**] [Priority: 0] {ICMP} 1.2.3.4 -> 5.6.7.8
ALERT_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"
    r"(?P<msg>.+?)\s+\[\*\*\]\s+"
    r"(?:\[Classification:\s*(?P<classification>[^\]]+)\]\s+)?"
    r"\[Priority:\s*(?P<priority>\d+)\]\s+"
    r"\{(?P<proto>\w+)\}\s+(?P<src>\S+)\s+->\s+(?P<dst>\S+)"
)

DEMO_ALERTS = [
    {
        "timestamp": "--/--  --:--:--", "sid": "1000001",
        "message": "Possible plaintext credential submission over HTTP (custom rule)",
        "classification": "Attempted Information Leak", "priority": "2",
        "protocol": "TCP", "source": "demo", "destination": "demo", "is_custom_rule": True,
    }
]


def _parse_line(line: str):
    match = ALERT_PATTERN.match(line.strip())
    if not match:
        return None
    d = match.groupdict()
    return {
        "timestamp": d["timestamp"], "sid": d["sid"], "message": d["msg"],
        "classification": (d["classification"] or "Unclassified").strip(),
        "priority": d["priority"],
        "protocol": d["proto"], "source": d["src"], "destination": d["dst"],
        "is_custom_rule": d["sid"] in CUSTOM_SIDS,
    }


def get_recent_alerts(limit: int = 20):
    if not os.path.exists(SNORT_ALERT_LOG):
        return {"source": "demo", "alerts": DEMO_ALERTS}
    try:
        with open(SNORT_ALERT_LOG, "r", errors="ignore") as f:
            lines = f.readlines()
    except PermissionError:
        return {"source": "error", "alerts": [], "error": "Permission denied reading Snort log."}

    alerts = [p for p in (_parse_line(l) for l in lines) if p]
    alerts.reverse()
    return {"source": "live", "alerts": alerts[:limit]}