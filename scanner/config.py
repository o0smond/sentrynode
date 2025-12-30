#By: Oliver Osmond
#Created on: 2025-12-29
#Description: This file acts as a config file containing information for the other files in this program.

#Scope
TARGET_SUBNET = "192.168.10.50/24" #Base is set to scan the LAN's server

#Discovery
DISCOVERY_PORTS = [22, 80, 443]

#Port scanning
COMMON_PORTS = [
    21,22,23,25,
    53,80,110,
    143,443,445,
    3306, 8080
]

#Performance settings
SOCKET_TIMEOUT = 0.5
MAX_THREADS = 100

#Output
OUTPUT_DIR = "scans"
