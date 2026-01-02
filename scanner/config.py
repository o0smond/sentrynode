#By: Oliver Osmond
#Created on: 2025-12-29
#Description: This file acts as a config file containing information for the other files in this program.

#Scope
TARGET_SUBNET = "192.168.10.0/24" #Base is set to my homelab's subnet

#Discovery
DISCOVERY_PORTS = [22, 80, 443] #Super common ports to scan quickly

#Port scanning. Add extra port to be scanned here:
COMMON_PORTS = [
    21,22,23,25,
    53,80,110,
    143,443,445,
    3306, 8080
]

#Performance settings
SOCKET_TIMEOUT = 0.5 #Timeout in seconds if a connection cannot be established
MAX_THREADS = 100 #Number of threads ThreadPoolExecutor will use

#Output
OUTPUT_DIR_SCAN = "scans" #Prefered name for SCAN output directory
OUTPUT_DIR_DIFF = "analysis" #Prefered name for analysis output directory
