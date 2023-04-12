# -*- coding: utf-8 -*-
"""
Created on Sun Apr  9 14:36:55 2023

@author: Tristan
"""

#File to SHA256-Hash (Virustotal)
import hashlib
import requests
import os

# Your API Key
api_key = ""

def virustotal(hash, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{hash}"
    headers = {
        "accept": "application/json",
        "x-apikey": f"{api_key}"
    }
    response = requests.get(url, headers=headers)
    json_response = response.json()
    print("Results from Virustotal:")
    try:
        print(json_response['data']['attributes']['last_analysis_stats'], end="\n\n")
    except:
        print(response.json(), end="\n\n")

while True:
    path = input("Drop file or insert link (Warning HASH will be uploaded to Virustotal): \n")
    
    if path[0] == "'" or path[0] == '"':
        path = path[1:len(path)-1] # Remove quotes
    
    try:
        with open(path, "rb") as f:
            bytes = f.read() # Read bytes
            hash = hashlib.sha256(bytes).hexdigest() # Hash function
            print(f"Output from {os.path.basename(f.name)} (SHA256):\n{hash}\n")
            virustotal(hash, api_key)
                        
    except:
        print("Error with file or link...\n")
