#By: Oliver Osmond
#Created on: 2025-12-29
#Updated on: 2026-11-19
#Description: This file handles the discovery of active IP adresses on a network

import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from scanner import config

#This function finds the subnet of the network this machine is on,
# using the ip of the interface our internet traffic goes out of.
# Raises OSError if there is no network connection.
def local_subnet() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("8.8.8.8", 80))   #UDP connect sends no packets, it just picks the outgoing interface
        ip = sock.getsockname()[0]
    #shortcut: assumes a /24 (home network size), use -s for bigger or smaller networks
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))

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