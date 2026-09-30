#!/usr/bin/env python3
import sys
import subprocess
import requests
import json

OLLAMA_URL = "http://127.0.0.1:11434"
MODEL_NAME = "deepseek-r1:8b"

BANNER = """
================================================================
  _   _        _ __        __eae                

 | \ | | ___ _| |\ \      / /__  __ _ _   _____ 
 |  \| |/ _ \_   _\ \ /\ / / _ \/ _` | | | / _ \\
 | |\  |  __/ | |  \ V  V /  __/ (_| | |_| |  __/
 |_| \_|\___| |_|   \_/\_/ \___|\__,_|\__,_|\___| v7.0
================================================================
 [*] Tactical Reconnaissance & Intelligent Attack Path Engine
================================================================
"""

def print_banner():
    print(BANNER)

def run_nmap(target_ip):
    print(f"[➔] Initiating reconnaissance scan against: {target_ip}")
    try:
        result = subprocess.run(
            ["nmap", "-sV", "-sC", "-T4", target_ip],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[🗙] Critical: Nmap engine failed to execute: {e}")
        sys.exit(1)

def ask_local_ai(scan_data):
    print(f"[➔] Processing data through tactical intelligence pipeline...")
    
    # Optimerad prompt för att agera som en direkt, strategisk hacking-assistent
    prompt = (
        "You are an elite Red Team operator and tactical hacking assistant. Analyze the provided Nmap scan results.\n"
        "Your output must be ultra-dense, strategic, and highly actionable. No fluff, no introductory chatter, no mechanical filler.\n\n"
        "Structure your response exactly like this:\n\n"
        "## 🎯 TARGET LANDSCAPE\n"
        "- [Port/Service/Version] -> Short, brutal assessment of what this exposure means.\n\n"
        "## ⚡ STRATEGIC ATTACK PATHS\n"
        "- [Path Name]: Short explanation of the exploit vector, logical flaw, or CVE. Explain the exact objective of targeting this.\n\n"
        "## 🛠️ TACTICAL EXECUTION (NEXT COMMANDS)\n"
        "Provide exact, ready-to-paste terminal commands for further enumeration or direct exploitation. "
        "Each command must be preceded by a single-sentence tactical explanation of what it validates.\n\n"
        f"Nmap Scan Results:\n{scan_data}"
    )
    
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False
    }
    
    try:
        response = requests.post(f"{OLLAMA_URL}/api/generate", json=payload, timeout=None)
        response.raise_for_status()
        response_json = response.json()
        return response_json.get("response", "No analysis payload returned from the AI core.")
    except requests.exceptions.RequestException as e:
        print(f"[🗙] Critical: Connection to AI engine core failed: {e}")
        sys.exit(1)

def main():
    print_banner()
    
    if len(sys.argv) < 2:
        print("[🗙] Usage error. Correct format: python3 pwn_recon.py <TARGET_IP>")
        sys.exit(1)
        
    target_ip = sys.argv[1]
    
    scan_output = run_nmap(target_ip)
    print("[✓] Reconnaissance acquisition complete.")
    print("-" * 64)
    
    ai_analysis = ask_local_ai(scan_output)
    
    print("\n" + "=" * 64)
    print("                     TACTICAL THREAT REPORT                     ")
    print("=" * 64)
    print(ai_analysis.strip())
    print("=" * 64 + "\n")

if __name__ == "__main__":
    main()
