import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from scanner import config

def tcp_probe(ip: str, port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(config.SOCKET_TIMEOUT)
            sock.connect((ip, port))
            return True
    except Exception:
        return False
    
def is_host_alive(ip: str) -> bool:
    return any(tcp_probe(ip, port) for port in config.DISCOVERY_PORTS)

def discover_hosts(subnet: str) -> list[str]:
    hosts = []
    network = ipaddress.ip_network(subnet, strict=False)
    
    print(f"Scanning {network} for hosts...")
    with ThreadPoolExecutor(max_workers=config.MAX_THREADS) as executor:
        futures = {executor.submit(is_host_alive, str(ip)): str(ip) for ip in network.hosts()}
        
        for future in as_completed(futures):
            ip = futures[future]
            if future.result():
                hosts.append(ip)
                
    print(f"Discovered {len(hosts)} hosts.")
    return sorted(hosts)