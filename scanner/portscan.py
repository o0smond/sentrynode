#By: Oliver Osmond
#Created on: 2025-12-29
#Description: This file works to scan a network's host IP's for open ports.
#By default, in main.py, it will scan for common ports first to avoid
#overworking the system and detection on the host's side (intrusion
# detection systems or rate limiters). Full scans
#will only be conducted upon user request.

from scanner import discovery, config
from concurrent.futures import ThreadPoolExecutor, as_completed

#This function scans all common ports on a list of active hosts
# on a network pulled from discovery.py's discover_hosts function.
#If you would like to add a port to scan, please add it to
#config.py's COMMON_PORTS list.
def scan_common_ports(hosts: list[str]) -> dict[str, list[int]]:
    open_ports = {host: [] for host in hosts}

    with ThreadPoolExecutor(max_workers=config.MAX_THREADS) as executor:
        futures = {
            executor.submit(discovery.tcp_probe, host, port): (host, port)
            for host in hosts
            for port in config.COMMON_PORTS
        }

        for future in as_completed(futures):
            host, port = futures[future]
            if future.result():
                open_ports[host].append(port)
    return open_ports

#This function scans all ports on a host ip.
#Please note that this is extremely computationally expensive
#and should only be used in special cases where the common
#port scan is not enough.
def scan_all_ports(host: str) -> list[int]:
    open_ports = []
    with ThreadPoolExecutor(max_workers=config.MAX_THREADS) as executor:
        futures = {
            executor.submit(discovery.tcp_probe, host, port): port
            for port in range(1, 65536)
        }

        for future in as_completed(futures):
            port = futures[future]
            if future.result():
                open_ports.append(port)
    return sorted(open_ports)