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
#   -changed services/banner
#   -loss/addition of banner
# All this will be saved to a JSON
# in your specified diff directory 
# (default = diff).

import json
import os
from datetime import datetime
from scanner import config

def readfile(dir: str) -> dict:
    with open(dict, "r") as f:
        results = json.load(f)
    return results

def diff(old_dir: str, new_dir: str) -> dict:
    old_dict = readfile(old_dir)
    new_dict = readfile(new_dir)