#By: Oliver Osmond
#Created on: 2025-12-29
#Description: This file saves the outputted dictionary from main.py 
# into a json file.

import json
import os
from datetime import datetime

#This function takes a dict and dumps it
# into a json file in the specified directory.
def save_to_json(results: dict, dir: str):
    os.makedirs(dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
    filename = f"{timestamp}.json"
    path = os.path.join(dir, filename)
    
    with open(path, "w") as f:
        json.dump(results, f, indent=4)
    
    print(f"Results saved to {path}")
    return path