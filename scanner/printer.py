#By: Oliver Osmond
#Created on: 2026-11-19
#Description: This file prints sentrynode scans, series and diffs as
# an easy to read, colored report in the terminal instead of raw JSON.
# Colors: ips are yellow, ports are green, values are red. In diffs,
# green means something appeared and red means something went away.

import os, sys
YELLOW = "\033[33m"
RED = "\033[31m"
GREEN = "\033[32m"
BOLD = "\033[1m"
RESET = "\033[0m"

#No colors when output goes to a file/pipe or the user set NO_COLOR,
# so saved output doesn't fill up with escape codes.
if not sys.stdout.isatty() or "NO_COLOR" in os.environ:
    YELLOW = RED = GREEN = BOLD = RESET = ""
elif os.name == "nt":
    os.system("")   #Turns on ANSI color support in older Windows consoles

#This function wraps text in a color and resets it after.
def paint(text, color: str) -> str:
    return f"{color}{text}{RESET}"

#This function prints any sentrynode dict (scan, series or diff)
# by passing it to the right print function.
def print_report(data: dict):
    if data["sentrynode"] == "scan":
        print_scan(data)
    elif data["sentrynode"] == "series":
        print_series(data)
    elif data["sentrynode"] == "diff":
        print_diff(data)
    else:
        print(f"Unknown sentrynode file type: {data['sentrynode']}")

#This function prints one scan: a header line, then each host with
# its open ports and what was found on each port.
def print_scan(scan: dict):
    results = scan["results"]
    print(f"\n{BOLD}Scan {scan['time']}{RESET}   subnet {scan['subnet']}   mode {scan.get('mode', 'light')}")
    print(f"{len(results)} host(s) found")

    for host in results:
        print(f"\n{paint(host, YELLOW + BOLD)}")
        ports = results[host]
        if len(ports) == 0:
            print("  no open ports")

        for port in sorted(ports, key=int):    #Ports are ints in memory but strings after loading from JSON
            print(f"  port {paint(port, GREEN)}")
            data = ports[port]
            if data == None:
                print(f"    {paint('fingerprint failed', RED)}")
                continue

            print(f"    service:   {paint(data.get('service'), RED)}")
            if "certainty" in data:    #fingerprint_http doesn't set certainty
                print(f"    certainty: {paint(data['certainty'], RED)}")

            label = "    response:  "
            for line in data.get("response", []):
                if line.strip() == "":   #Skipping the blank lines at the end of HTTP responses
                    continue
                print(f"{label}{paint(line, RED)}")
                label = "               "    #Only the first response line gets the label

#This function prints a series: a header, then every scan in it.
def print_series(series: dict):
    print(f"\n{BOLD}Series: {len(series['scans'])} scans, every {series['interval']:g}s{RESET}")
    for scan in series["scans"]:
        print_scan(scan)

#This function prints a diff: one block per step (scan 1 -> 2, ...),
# with one line per change.
def print_diff(d: dict):
    for step in d["diffs"]:
        changes = step["changes"]
        print(f"\n{BOLD}Changes {step['from']} -> {step['to']}{RESET}")
        count = 0    #Counting changes so we can say "no changes" if there are none

        for host in changes["hosts"]["added"]:
            print(f"  {paint('new host', GREEN)}   {paint(host, YELLOW)}")
            count += 1
        for host in changes["hosts"]["removed"]:
            print(f"  {paint('gone host', RED)}  {paint(host, YELLOW)}")
            count += 1

        ports = changes["ports"]
        for host in ports:
            for port in ports[host]["added"]:
                print(f"  {paint(host, YELLOW)}   port {paint(port, GREEN)} {paint('opened', GREEN)}")
                count += 1
            for port in ports[host]["removed"]:
                print(f"  {paint(host, YELLOW)}   port {paint(port, GREEN)} {paint('closed', RED)}")
                count += 1

        services = changes["fingerprints"]["service_change"]
        for host in services:
            for port in services[host]:
                old = services[host][port]["old_service"]
                new = services[host][port]["new_service"]
                print(f"  {paint(host, YELLOW)}   port {paint(port, GREEN)} service: {paint(old, RED)} -> {paint(new, GREEN)}")
                count += 1

        banners = changes["fingerprints"]["banner_change"]
        for host in banners:
            for port in banners[host]:
                print(f"  {paint(host, YELLOW)}   port {paint(port, GREEN)} banner changed")
                for line in banners[host][port]["old_banner"] or []:
                    if line.strip() != "":
                        print(f"      old: {paint(line, RED)}")
                for line in banners[host][port]["new_banner"] or []:
                    if line.strip() != "":
                        print(f"      new: {paint(line, GREEN)}")
                count += 1

        if count == 0:
            print("  no changes")

#Quick visual check, run with: python -m scanner.printer
if __name__ == "__main__":
    print_report({"sentrynode": "scan", "time": "t1", "subnet": "10.0.0.0/24", "mode": "full", "results": {
        "10.0.0.1": {
            22: {"service": "ssh", "certainty": "banner", "response": ["SSH-2.0-OpenSSH_9.6"]},
            80: {"service": "http", "response": ["HTTP/1.1 200 OK", "Server: nginx", "", ""]},
            8080: None,
        },
        "10.0.0.2": {},
    }})
    print_report({"sentrynode": "diff", "diffs": [
        {"from": "t1", "to": "t2", "changes": {
            "hosts": {"added": ["10.0.0.3"], "removed": ["10.0.0.2"]},
            "ports": {"10.0.0.1": {"added": [8080], "removed": [21]}},
            "fingerprints": {
                "service_change": {"10.0.0.1": {80: {"old_service": None, "new_service": "http"}}},
                "banner_change": {"10.0.0.1": {22: {"old_banner": ["SSH-2.0-old"], "new_banner": ["SSH-2.0-new"]}}},
            }}},
        {"from": "t2", "to": "t3", "changes": {
            "hosts": {"added": [], "removed": []}, "ports": {},
            "fingerprints": {"service_change": {}, "banner_change": {}}}},
    ]})
