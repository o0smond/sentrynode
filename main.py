#By: Oliver Osmond
#Created on: 2025-12-29
#Description: This file acts the main "controller" for the program, connecting
# all the files together.

from scanner import portscan, discovery, fingerprint, config, output
def start_scan():
    #scan hosts
    hosts = discovery.discover_hosts(config.TARGET_SUBNET)
    
    #scan host ports
    hostports = portscan.scan_common_ports(hosts)
    
    #print results and do optional full scan of some hosts.
    print("\nactive hosts:")
    for host in hosts:
        print(f"{host}")
    while True:
        allscan_address = input("\nWould you like to conduct a full scan of a host? if so, please enter the ip address (or enter 'c' to cancel): ").lower().strip()
        if allscan_address in hosts:
            while True:
                response = input("This scan is very resource heavy. Are you sure you want to continue? (y/n)").lower().strip()
                if response == "y":
                    print(f"Scanning {allscan_address} for open ports...")
                    allscan_ports = portscan.scan_all_ports(allscan_address)
                    hostports[allscan_address] = allscan_ports
                    print(f"Open ports on {allscan_address}: {allscan_ports}")
                    break
                elif response == "n":
                    break
                else:
                    print("Invalid input. Please type either 'y' or 'n'.")
        elif allscan_address == "c":
            break
        else:
            print("Invalid ip address. Please try again.")
    
    #Get banners and rewrite hostports to be a double nested dictionary.
    # The final output will be stored in net_dict.
    net_dict = {}
    http_ports = {80,8080,443}
    
    for host, ports in hostports.items():
        net_dict[host] = {}
        
        for port in ports:
            if port in http_ports:
                data = fingerprint.fingerprint_http(host, port)
            else:
                banner = fingerprint.grab_banner(host, port)
                data = {
                    "service": "TBD",
                    "response": banner
                }
            net_dict[host][port] = data
    output.save_to_json(net_dict)
    
        

print("Welcome to SentryNode!")
print("Scan will be conducted with these settings:")
print(f"Target subnet: {config.TARGET_SUBNET}")
print(f"Discovery ports: {config.DISCOVERY_PORTS}")
print(f"Common ports: {config.COMMON_PORTS}")
print(f"Max threads: {config.MAX_THREADS}")
print(f"Socket timeout: {config.SOCKET_TIMEOUT}")
print(f"Output directory: {config.OUTPUT_DIR}")
while True:
    proceed = input("Are these your prefered settings? (y/n): ").lower().strip()
    if proceed == "y":
        start_scan()
        break
    elif proceed == "n":
        print("Please update your settings in /scanner/config.py.")
        break
    else:
        print("Invalid input. Please type either 'y' or 'n'.")
