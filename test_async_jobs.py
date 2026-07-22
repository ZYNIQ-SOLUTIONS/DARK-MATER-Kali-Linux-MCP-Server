import requests
import time
import sys
import json
import os

BASE_URL = "http://localhost:5000"

def get_headers():
    creds_file = "/etc/mcp-kali/credentials.json"
    with open(creds_file, "r") as f:
        data = json.load(f)
        # Get the first api_key from the credentials dict
        first_key = list(data.keys())[0]
        api_key = data[first_key].get("api_key")
        
    return {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

def test_async_job():
    headers = get_headers()
    print("1. Submitting async job for net.scan_basic...")
    payload = {
        "name": "net.scan_basic",
        "arguments": {
            "target": "127.0.0.1",
            "ports": "80",
            "fast": True
        }
    }
    
    response = requests.post(f"{BASE_URL}/tools/jobs", json=payload, headers=headers)
    if response.status_code != 202:
        print(f"FAILED: Expected 202 Accepted, got {response.status_code}")
        print(response.text)
        sys.exit(1)
        
    data = response.json()
    job_id = data.get("job_id")
    print(f"SUCCESS: Job submitted with ID: {job_id}")
    
    print("\n2. Polling job status...")
    max_retries = 30
    for i in range(max_retries):
        resp = requests.get(f"{BASE_URL}/tools/jobs/{job_id}", headers=headers)
        if resp.status_code != 200:
            print(f"FAILED: Expected 200 OK from poll, got {resp.status_code}")
            print(resp.text)
            sys.exit(1)
            
        job_data = resp.json()
        status = job_data.get("status")
        print(f"Poll {i+1}: Status = {status}")
        
        if status in ["completed", "failed"]:
            print(f"\nSUCCESS: Job finished with status: {status}")
            print(f"Result RC: {job_data.get('result', {}).get('rc')}")
            sys.exit(0)
            
        time.sleep(2)
        
    print("FAILED: Job timed out during polling.")
    sys.exit(1)

if __name__ == "__main__":
    test_async_job()
