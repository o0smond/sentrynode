#By: Oliver Osmond
#Created on: 2025-12-29
#Description: This file handles the discovery of active IP adresses on a network

import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from scanner import config

#This lower level function takes an ip address and
#optionally a port and attempts connection to it.
#If successful, returns true, otherwise false.
def tcp_probe(ip: str, port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(config.SOCKET_TIMEOUT)
            sock.connect((ip, port))
            return True
    except Exception:
        return False

#This is an extention of tcp_probe that simply attempts
#connection to a very small set of common ports to ensure
#that the host is alive.
def is_host_alive(ip: str) -> bool:
    return any(tcp_probe(ip, port) for port in config.DISCOVERY_PORTS)

#This funciton's purpose is to scan a network for ip adresses
#that are alive/have active ports.
def discover_hosts(subnet: str) -> list[str]:
    hosts = []
    network = ipaddress.ip_network(subnet, strict=False)
    
    print(f"\nScanning {network} for hosts...")
    with ThreadPoolExecutor(max_workers=config.MAX_THREADS) as executor:    #Using a thread pool to speed up the scan
        futures = {executor.submit(is_host_alive, str(ip)): str(ip) for ip in network.hosts()}
        
        for future in as_completed(futures):
            ip = futures[future]
            if future.result():
                hosts.append(ip)
                
    print(f"Discovered {len(hosts)} hosts.")
    return sorted(hosts)