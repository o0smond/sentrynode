#By: Oliver Osmond
#Created on: 2026-1-1
#Updated on: 2026-11-19
#Description: This file deals in comparing sentrynode scans to
# find what changed on the network between them. Scans can come
# from saved files (single or series) or straight from memory.
# DIFFERENCES SEARCHED FOR:
# 1. ip/host changes:
#   - New host ips
#   - "Missing" or now disconnected host ips
# 2. port changes:
#   -New open ports
#   -Now closed ports
# 3. fingerprint/service changes:
#   -Change of service
#   -Change of banner
# Only changes are kept, so an empty section means nothing changed.

import json

#This function reads a sentrynode JSON file back into a dict.
# Files without the "sentrynode" tag at the top are rejected so
# we never try to diff some random JSON file.
def load(path: str) -> dict:
    with open(path, "r") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            data = None
    if not isinstance(data, dict) or "sentrynode" not in data:
        raise ValueError(f"{path} is not a sentrynode file")
    return data

#This function compares the results of two scans and returns the
# differences as a dict. See above for what this function looks for.
def diff(old_results: dict, new_results: dict) -> dict:
    old_hosts = set(old_results.keys())    #Taking hosts from old dict and new dict as we don't want their values here
    new_hosts = set(new_results.keys())

    changes = {        #Defining structure
        "hosts": {
            "added": [],
            "removed": []
        },
        "ports": {},
        "fingerprints": {
            "service_change": {},
            "banner_change": {}
        }
    }

    #host diff
    changes["hosts"]["added"] = sorted(new_hosts - old_hosts) #By subtracting old hosts from new hosts we get the added hosts
    changes["hosts"]["removed"] = sorted(old_hosts - new_hosts) #Vice versa

    #port diff
    common_hosts = old_hosts & new_hosts #We don't want to analyse ports on hosts that have been removed.
    for host in sorted(common_hosts):
        old_ports = set(old_results[host].keys())
        new_ports = set(new_results[host].keys())

        added_ports = new_ports - old_ports
        removed_ports = old_ports - new_ports

        if added_ports or removed_ports:    #Skipping hosts where no ports changed
            changes["ports"][host] = {
                "added": sorted(added_ports),
                "removed": sorted(removed_ports)
            }

    #Fingerprint diff
    for host in sorted(common_hosts):
        old_ports = old_results[host]
        new_ports = new_results[host]
        common_ports = old_ports.keys() & new_ports.keys()

        for port in sorted(common_ports):
            old_p = old_ports[port] or {}   #Fingerprint is None if fingerprinting failed
            new_p = new_ports[port] or {}

            if old_p.get("service") != new_p.get("service"):
                changes["fingerprints"]["service_change"].setdefault(host, {})[port] = {
                    "old_service": old_p.get("service"),
                    "new_service": new_p.get("service")
                }

            if old_p.get("response") != new_p.get("response"):
                changes["fingerprints"]["banner_change"].setdefault(host, {})[port] = {
                    "old_banner": old_p.get("response"),
                    "new_banner": new_p.get("response")
                }

    return changes

#This function takes a list of scans (oldest first) and diffs each
# scan against the one before it (1->2, 2->3, ...) so you can see
# when each change happened. Returns a tagged diff dict.
def diff_scans(scans: list[dict]) -> dict:
    diffs = []
    for i in range(1, len(scans)):
        old_scan = scans[i - 1]
        new_scan = scans[i]
        diffs.append({
            "from": old_scan["time"],
            "to": new_scan["time"],
            "changes": diff(old_scan["results"], new_scan["results"])
        })
    return {"sentrynode": "diff", "diffs": diffs}

#Quick self-check, run with: python -m scanner.diff
if __name__ == "__main__":
    old = {"time": "t1", "results": {
        "10.0.0.1": {21: None, 22: {"service": "ssh", "response": ["SSH-2.0-old"]}, 80: None},
        "10.0.0.2": {22: {"service": "ssh", "response": []}},
    }}
    new = {"time": "t2", "results": {
        "10.0.0.1": {22: {"service": "ssh", "response": ["SSH-2.0-new"]}, 80: {"service": "http", "response": []}},
        "10.0.0.3": {443: {"service": "https", "response": []}},
    }}
    same = {"time": "t3", "results": new["results"]}

    out = diff_scans([old, new, same])
    first = out["diffs"][0]["changes"]
    assert out["sentrynode"] == "diff" and len(out["diffs"]) == 2
    assert first["hosts"] == {"added": ["10.0.0.3"], "removed": ["10.0.0.2"]}
    assert first["ports"] == {"10.0.0.1": {"added": [], "removed": [21]}}
    assert first["fingerprints"]["banner_change"]["10.0.0.1"][22]["new_banner"] == ["SSH-2.0-new"]
    assert first["fingerprints"]["service_change"]["10.0.0.1"][80]["new_service"] == "http"   #None fingerprint handled
    assert out["diffs"][1]["changes"] == {"hosts": {"added": [], "removed": []}, "ports": {},
                                          "fingerprints": {"service_change": {}, "banner_change": {}}}
    print("diff self-check passed")
