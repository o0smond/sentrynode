#By: Oliver Osmond
#Created on: 2025-12-29
#Updated on: 2026-11-19
#Description: This file saves the outputted dictionary from main.py
# into a json file.

import json
import os
from datetime import datetime

#This function takes a dict and dumps it into a json file.
# If a path is given it saves there, otherwise it saves to a
# timestamp-named file in the specified directory.
def save_to_json(results: dict, dir: str, path: str | None = None):
    if path == None:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
        path = os.path.join(dir, f"{timestamp}.json")

    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)   #dirname is "" for a bare filename like me.json
    with open(path, "w") as f:
        json.dump(results, f, indent=4)

    print(f"Results saved to {path}")
    return path
