#By: Oliver Osmond
#Created on: 2025-12-29
#Description: This file acts the main "controller" for the program, connecting
# all the files together.

import os, sys
from scanner import portscan, discovery, fingerprint, config, output, diff

#Function for if the user wants to run a scan
def scan_mode():
    #Ensuring settings are correct
    print("\nScan will be conducted with these settings:")
    print(f"Target subnet: {config.TARGET_SUBNET}")
    print(f"Discovery ports: {config.DISCOVERY_PORTS}")
    print(f"Common ports: {config.COMMON_PORTS}")
    print(f"Max threads: {config.MAX_THREADS}")
    print(f"Socket timeout: {config.SOCKET_TIMEOUT}")
    print(f"Output directory: {config.OUTPUT_DIR_SCAN}")
    while True:
        proceed = input("Are these your prefered settings? (y/n):").lower().strip()
        if proceed == "y":
            break
        elif proceed == "n":
            print("Please update your settings in /scanner/config.py.")
            sys.exit(0)
        else:
            print("Invalid input. Please type either 'y' or 'n'.")
            
    #scan hosts
    hosts = discovery.discover_hosts(config.TARGET_SUBNET)
    
    #scan host ports
    hostports = portscan.scan_common_ports(hosts)
    
    #print results and do optional full scan of some hosts, as full scans
    # are very resource heavy and can cause some rate limiting or other
    # conecquences.
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
    
    #fingerprinting each open port on each active host
    net_dict = {}
    
    for host in hostports:  #Initializing the nested dict
        net_dict[host] = {}
    
    for host in hostports:
        for port in hostports[host]:
            data = fingerprint.fingerprint_http(host, port)
            if data == None:
                data = fingerprint.fingerprint_general(host, port)
            if data == None:
                print("An error occured while fingerprinting")
            net_dict[host][port] = data
            
    #Saving results to JSON
    output.save_to_json(net_dict, config.OUTPUT_DIR_SCAN)
    print(f"Results saved to JSON in {config.OUTPUT_DIR_SCAN}")
    
#Function for if the user wants to run an analysis
def diff_mode():
    print("Welcome to analysis mode. Please enter the names of two files to analyse. Files MUST be in the scan output directory. Enter 'c' to cancel.")
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))   #Determining current directory
    while True:
        name1 = input("\nFile 1 (older file):")
        if name1.lower().strip() == "c":
            break
        if not name1.endswith(".json"):
            print("missing .json or invalid file format")
        else:
            dir1 = os.path.join(BASE_DIR, config.OUTPUT_DIR_SCAN, name1)    #Determining path from current directory to file
            if not os.path.exists(dir1):
                print("File is either not in scan output directory or does not exist")
            else:
                break
        
    while True:
        name2 = input("\nFile 2 (newer file):")
        if name1.lower().strip() == "c":
            break
        if not name2.endswith(".json"):
            print("missing .json or invalid file format")
        else:
            dir2 = os.path.join(BASE_DIR, config.OUTPUT_DIR_SCAN, name2)
            if not os.path.exists(dir2):
                print("File is either not in scan output directory or does not exist")
            else:
                break
    
    if name1.lower().strip() == "c" or name2.lower().strip() == "c":
        print("Analysis cancelled.")
    else:
        #run analysis
        out = diff.diff(dir1, dir2)
        #save results
        output.save_to_json(out, config.OUTPUT_DIR_DIFF)
        print(f"Results saved to JSON in {config.OUTPUT_DIR_DIFF}")
    
#Startup mode selection
print("\n   ███████╗ ███████╗ ███╗   ██╗ ████████╗ ██████╗ ██╗   ██╗\n   ██╔════╝ ██╔════╝ ████╗  ██║ ╚══██╔══╝ ██╔══██╗╚██╗ ██╔╝\n   ███████╗ █████╗   ██╔██╗ ██║    ██║    ██████╔╝ ╚████╔╝ \n   ╚════██║ ██╔══╝   ██║╚██╗██║    ██║    ██╔══██╗  ╚██╔╝  \n   ███████║ ███████╗ ██║ ╚████║    ██║    ██║  ██║   ██║   \n   ╚══════╝ ╚══════╝ ╚═╝  ╚═══╝    ╚═╝    ╚═╝  ╚═╝   ╚═╝   \n\n                      SENTRYNODE\n           network scanning & change detection\n\n")
while True:
    mode = input("Please enter mode: scan or analysis or 'q' to quit (s/a):").lower().strip()
    if mode == "s":
        scan_mode()
        break
    elif mode == "a":
        diff_mode()
        break
    elif mode == "q":
        print("Goodbye!")
        break
    else:
        print("Invalid input. Please type either 's' or 'a'.")


