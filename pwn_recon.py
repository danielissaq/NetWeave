#!/usr/bin/env python3
import sys
import subprocess
import requests
import json

OLLAMA_URL = "http://127.0.0"
MODEL_NAME = "deepseek-r1:8b"

def run_nmap(target_ip):
    print(f"[*] Initiating Nmap scan against target: {target_ip}")
    try:
        result = subprocess.run(
            ["nmap", "-sV", "-sC", "-T4", target_ip],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[-] Nmap scan execution failed: {e}")
        sys.exit(1)

def ask_local_ai(scan_data):
    print(f"[*] Forwarding scan data to local AI model ({MODEL_NAME}) for automated analysis...")
    
    prompt = (
        "Analyze the following Nmap scan results. Identify open ports, active services, "
        "potential vulnerabilities, and suggest specific tactical next steps for exploitation:\n\n"
        f"{scan_data}"
    )
    
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False
    }
    
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=None)
        response.raise_for_status()
        response_json = response.json()
        return response_json.get("response", "No analysis returned from the local AI engine.")
    except requests.exceptions.RequestException as e:
        print(f"[-] Error communicating with local AI endpoint: {e}")
        sys.exit(1)

def main():
    if len(sys.argv) < 2:
        print("[-] Usage error. Correct format: python3 pwn_recon.py <TARGET_IP>")
        sys.exit(1)
        
    target_ip = sys.argv[1]
    
    scan_output = run_nmap(target_ip)
    print("[+] Nmap scan completed successfully.")
    
    ai_analysis = ask_local_ai(scan_output)
    print("\n================================================================================")
    print("                           SYSTEM AUTOMATION ANALYSIS                           ")
    print("================================================================================")
    print(ai_analysis)
    print("================================================================================")

if __name__ == "__main__":
    main()
