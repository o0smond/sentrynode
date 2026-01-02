#By: Oliver Osmond
#Created on: 2026-1-1
#Description: This file deals in analyzing two scan JSONs in the scans folder to
# provide greater utility to the user. Additionally provides the function
# to view any saved files.
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
# All this will be saved to a JSON
# in your specified diff directory 
# (default = diff).

import json
import os
from datetime import datetime
from scanner import config

#This function reads a given JSON file exported by output.py back
# to a usable dict for further analysis.
def readfile(path: str) -> dict:
    with open(path, "r") as f:
        results = json.load(f)
    return results

#This function compares two scan JSONs and returns the differences
# as a dict, that gets saved later as another JSON. See above for
# what this function looks for.
def diff(old_dir: str, new_dir: str) -> dict:
    old_dict = readfile(old_dir)
    new_dict = readfile(new_dir)
    old_hosts = set(old_dict.keys())    #Taking hosts from old dict and new dict as we don't want their values here
    new_hosts = set(new_dict.keys())
    
    diff = {        #Defining structure
        "hosts": {
            "added": [],
            "removed": []
        },
        "ports": {},
        "fingerprints": {
            "service_change":{},
            "banner_change":{}
        }
    }
    
    #host diff
    diff["hosts"]["added"] = sorted(new_hosts - old_hosts) #By subrtacting new hosts from old hosts we get the added hosts
    diff["hosts"]["removed"] = sorted(old_hosts - new_hosts) #Vice versa
    
    #port diff
    common_hosts = old_hosts & new_hosts #We don't want to analyse ports on hosts that have been removed.
    for host in common_hosts:
        old_ports = set(old_dict[host].keys())
        new_ports = set(new_dict[host].keys())
        
        added_ports = new_ports - old_ports
        removed_ports = old_ports - new_ports
        
        diff["ports"][host] = {
            "added": sorted(added_ports),
            "removed": sorted(removed_ports)
        }

    #Fingerprint diff
    diff["fingerprints"]["service_change"] = {}
    diff["fingerprints"]["banner_change"] = {}
    for host in common_hosts:
        old_ports = old_dict[host]
        new_ports = new_dict[host]
        common_ports = old_ports.keys() & new_ports.keys()
        
        for port in common_ports:
            old_p = old_ports[port]
            new_p = new_ports[port]
            
            
            if old_p["service"] != new_p["service"]:
                diff["fingerprints"]["service_change"].setdefault(host, {})[port] = {
                    "old_service": old_p["service"],
                    "new_service": new_p["service"]
                }
            else:
                diff["fingerprints"]["service_change"].setdefault(host, {})[port] = {
                    "no_changes":"no_changes"
                }
                
            if old_p["response"] != new_p["response"]:
                diff["fingerprints"]["banner_change"].setdefault(host, {})[port] = {
                    "old_banner": old_p["response"],
                    "new_banner": new_p["response"]
                }
            else:
                diff["fingerprints"]["banner_change"].setdefault(host, {})[port] = {
                    "no_changes":"no_changes"
                }
    
    return diff