#!/usr/bin/env python3
import sys
import os
import re
import requests
import json
import subprocess
import ipaddress
import argparse
from datetime import datetime
from pathlib import Path

# Configuration
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_TAGS_URL = "http://localhost:11434/api/tags"
DEFAULT_TIMEOUT = 300

# Common wordlist paths (searched in order)
WORDLIST_PATHS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt", 
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
    "./wordlists/common.txt",
    "./common.txt"
]

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_banner():
    print(f"""
    {Colors.OKCYAN}███╗   ██╗███████╗████████╗██╗    ██╗███████╗ █████╗ ██╗   ██╗███████╗{Colors.ENDC}
    {Colors.OKCYAN}████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔════╝██╔══██╗██║   ██║██╔════╝{Colors.ENDC}
    {Colors.OKCYAN}██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║█████╗  ███████║██║   ██║█████╗  {Colors.ENDC}
    {Colors.OKCYAN}██║╚██╗██║██╔══╝     ██║   ██║███╗██║██╔══╝  ██╔══██║╚██╗ ██╔╝██╔══╝  {Colors.ENDC}
    {Colors.OKCYAN}██║ ╚████║███████╗   ██║   ╚███╔███╔╝███████╗██║  ██║ ╚████╔╝ ███████╗{Colors.ENDC}
    {Colors.OKCYAN}╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝{Colors.ENDC}
    {Colors.OKGREEN}>>> NetWeave v7.1 - CTF Recon & Attack Framework <<<{Colors.ENDC}
    """)

def validate_ip(ip_str):
    """Validate IP and warn if not private."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback:
            return str(ip), True
        if not ip.is_private:
            print(f"{Colors.WARNING}[!] WARNING: {ip} is not a private IP!{Colors.ENDC}")
            response = input(f"{Colors.WARNING}    Only continue if authorized. [y/N]: {Colors.ENDC}")
            if response.lower() not in ['y', 'yes']:
                return None, False
        return str(ip), True
    except ValueError:
        print(f"{Colors.FAIL}[-] Invalid IP address: {ip_str}{Colors.ENDC}")
        return None, False

def check_ollama():
    """Verify Ollama is running."""
    try:
        r = requests.get(OLLAMA_TAGS_URL, timeout=5)
        return r.status_code == 200
    except:
        print(f"{Colors.FAIL}[-] Ollama not running. Start with: ollama serve{Colors.ENDC}")
        return False

def get_model(preferred=None):
    """Get best available model."""
    try:
        r = requests.get(OLLAMA_TAGS_URL, timeout=5)
        if r.status_code != 200:
            return "deepseek-r1:8b"
        
        models = [m["name"] for m in r.json().get("models", [])]
        if not models:
            print(f"{Colors.FAIL}[-] No models found. Run: ollama pull deepseek-r1:8b{Colors.ENDC}")
            return None
        
        if preferred and preferred in models:
            return preferred
            
        # Priority order
        for pattern in ["deepseek-r1:8b", "deepseek-r1", "qwen2.5", "llama3.2", "mistral"]:
            for m in models:
                if pattern in m.lower():
                    return m
        return models[0]
    except Exception as e:
        print(f"{Colors.FAIL}[-] Error getting models: {e}{Colors.ENDC}")
        return "deepseek-r1:8b"

def run_command(cmd, desc, timeout=DEFAULT_TIMEOUT):
    """Execute command with proper error handling."""
    print(f"{Colors.OKBLUE}[*] {desc}...{Colors.ENDC}")
    
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout
        )
        
        if result.returncode == 0:
            print(f"{Colors.OKGREEN}[+] {desc} complete{Colors.ENDC}")
        else:
            # Many security tools return non-zero but still have useful output
            print(f"{Colors.WARNING}[!] {desc} finished (code {result.returncode}){Colors.ENDC}")
        
        return result.stdout
        
    except subprocess.TimeoutExpired:
        print(f"{Colors.FAIL}[-] {desc} timed out{Colors.ENDC}")
        return ""
    except FileNotFoundError:
        print(f"{Colors.FAIL}[-] {cmd[0]} not found. Install it first.{Colors.ENDC}")
        return ""
    except Exception as e:
        print(f"{Colors.FAIL}[-] {desc} failed: {e}{Colors.ENDC}")
        return ""

def find_wordlist():
    """Find first available wordlist."""
    for path in WORDLIST_PATHS:
        if os.path.isfile(path):
            return path
    return None

def clean_ai_output(text):
    """Remove DeepSeek thinking tags and markdown."""
    # Remove <think> blocks (DeepSeek R1 specific)
    text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL)
    # Remove markdown code blocks
    text = re.sub(r'```[\w]*\n?', '', text)
    text = re.sub(r'```', '', text)
    return text.strip()

def extract_commands(text):
    """Extract commands using multiple strategies."""
    commands = []
    
    # Strategy 1: [CMD] tags (your format)
    pattern1 = r'\[CMD\]\s*(.*?)\s*\[CMD\]'
    matches = re.findall(pattern1, text, re.DOTALL)
    for m in matches:
        cmd = ' '.join(m.split())  # normalize whitespace
        if len(cmd) > 3:
            commands.append(cmd)
    
    # Strategy 2: Code blocks with security tools
    if not commands:
        pattern2 = r'(?:^|\n)\s*(?:curl|wget|nmap|nikto|gobuster|dirb|wfuzz|hydra|nuclei|msfconsole|searchsploit|python|ruby)\s+[^\n`]+'
        matches = re.findall(pattern2, text, re.IGNORECASE | re.MULTILINE)
        for m in matches:
            cmd = m.strip().strip('`').strip()
            if len(cmd) > 5:
                commands.append(cmd)
    
    # Deduplicate while preserving order
    seen = set()
    unique = []
    for c in commands:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    
    return unique

def sanitize_ps(cmd):
    """Sanitize for PowerShell (escape single quotes)."""
    # Escape single quotes for PowerShell
    return cmd.replace("'", "''")

def generate_script(commands, ip, dry_run=False):
    """Generate PowerShell script."""
    if not commands:
        print(f"{Colors.FAIL}[-] No commands to generate{Colors.ENDC}")
        return None
    
    filename = f"fire_payloads_{ip.replace('.', '_')}.ps1"
    
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write("# NetWeave CTF Attack Script\n")
            f.write(f"# Target: {ip}\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n")
            f.write("#" + "="*50 + "\n\n")
            
            f.write("$ErrorActionPreference = 'Continue'\n")
            f.write("$ProgressPreference = 'SilentlyContinue'\n\n")
            
            for i, cmd in enumerate(commands, 1):
                safe = sanitize_ps(cmd)
                
                f.write(f"Write-Host '[{i}/{len(commands)}] {safe[:60]}' -ForegroundColor Cyan\n")
                
                if dry_run:
                    f.write(f"Write-Host 'DRY RUN: {safe}' -ForegroundColor Yellow\n")
                else:
                    f.write(f"try {{ Invoke-Expression '{safe}' -ErrorAction Stop }} catch {{ Write-Host 'Failed: $_' -ForegroundColor Red }}\n")
                
                f.write("Write-Host ''\n")
            
            f.write("Write-Host '[+] Complete' -ForegroundColor Green\n")
        
        print(f"{Colors.OKGREEN}[+] Script: {os.path.abspath(filename)}{Colors.ENDC}")
        return filename
        
    except Exception as e:
        print(f"{Colors.FAIL}[-] Script error: {e}{Colors.ENDC}")
        return None

def query_ai(scan_data, model, ip):
    """Send to Ollama and get response."""
    
    # Optimized prompt for DeepSeek R1
    prompt = f"""You are a CTF penetration testing assistant. Analyze this scan data and provide 3 specific attack commands.

TARGET IP: {ip}

SCAN DATA:
{scan_data}

Provide exactly 3 commands in this format:
[CMD] command here [CMD]

Focus on: 1) Service verification 2) Enumeration 3) Exploitation"""

    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.3,
            "num_predict": 800  # Reduced for faster response
        }
    }
    
    try:
        print(f"{Colors.OKBLUE}[*] AI analyzing with {model}...{Colors.ENDC}")
        r = requests.post(OLLAMA_URL, json=payload, timeout=90)
        
        if r.status_code == 200:
            raw = r.json().get('response', '')
            cleaned = clean_ai_output(raw)
            
            print(f"\n{Colors.OKCYAN}{'='*50}{Colors.ENDC}")
            print(cleaned)
            print(f"{Colors.OKCYAN}{'='*50}{Colors.ENDC}\n")
            
            return cleaned
        else:
            print(f"{Colors.FAIL}[-] AI error: HTTP {r.status_code}{Colors.ENDC}")
            return None
            
    except requests.Timeout:
        print(f"{Colors.FAIL}[-] AI request timed out{Colors.ENDC}")
        return None
    except Exception as e:
        print(f"{Colors.FAIL}[-] AI error: {e}{Colors.ENDC}")
        return None

def main():
    parser = argparse.ArgumentParser(description='NetWeave CTF Framework')
    parser.add_argument('-t', '--target', help='Target IP')
    parser.add_argument('-m', '--model', help='Ollama model')
    parser.add_argument('--dry-run', action='store_true', help='Preview only')
    parser.add_argument('-w', '--wordlist', help='Custom wordlist')
    args = parser.parse_args()
    
    print_banner()
    
    # Pre-flight checks
    if not check_ollama():
        sys.exit(1)
    
    model = get_model(args.model)
    if not model:
        sys.exit(1)
    print(f"{Colors.OKGREEN}[*] Model: {model}{Colors.ENDC}")
    
    # Get target
    ip = args.target or input(f"{Colors.OKBLUE}[?] Target IP: {Colors.ENDC}").strip()
    ip, valid = validate_ip(ip)
    if not valid:
        sys.exit(1)
    
    # Reconnaissance
    scan_data = f"Target: {ip}\nTime: {datetime.now().isoformat()}\n\n"
    
    # Nmap
    nmap_out = run_command(["nmap", "-sV", "-sC", "-Pn", ip], "Nmap scan", timeout=180)
    scan_data += "=== NMAP ===\n" + nmap_out + "\n"
    
    # Find web ports
    web_ports = []
    for p in [80, 443, 8080, 8443, 3000, 8000, 8081]:
        if f"{p}/tcp" in nmap_out and "open" in nmap_out.split(f"{p}/tcp")[1].split("\n")[0]:
            web_ports.append(p)
    
    wordlist = args.wordlist or find_wordlist()
    
    # Web scanning
    for port in web_ports:
        proto = "https" if port in [443, 8443] else "http"
        url = f"{proto}://{ip}:{port}" if port not in [80, 443] else f"{proto}://{ip}"
        
        print(f"{Colors.OKBLUE}[*] Port {port} web service detected{Colors.ENDC}")
        
        if wordlist:
            gob_out = run_command(
                ["gobuster", "dir", "-u", url, "-w", wordlist, "-q", "-t", "30", "-k"],
                f"Gobuster ({port})", 
                timeout=180
            )
            scan_data += f"=== GOBUSTER {port} ===\n" + gob_out + "\n"
        else:
            print(f"{Colors.WARNING}[!] No wordlist found{Colors.ENDC}")
        
        nikto_out = run_command(
            ["nikto", "-h", url, "-maxtime", "60", "-C", "all"],
            f"Nikto ({port})",
            timeout=120
        )
        scan_data += f"=== NIKTO {port} ===\n" + nikto_out + "\n"
    
    # AI Analysis
    ai_text = query_ai(scan_data, model, ip)
    if not ai_text:
        print(f"{Colors.FAIL}[-] Analysis failed{Colors.ENDC}")
        sys.exit(1)
    
    commands = extract_commands(ai_text)
    
    if not commands:
        print(f"{Colors.WARNING}[!] No commands extracted. Manual review needed.{Colors.ENDC}")
        sys.exit(0)
    
    print(f"{Colors.OKGREEN}[+] Extracted {len(commands)} commands:{Colors.ENDC}")
    for i, c in enumerate(commands, 1):
        print(f"    {i}. {c[:70]}{'...' if len(c) > 70 else ''}")
    
    # Generate payload
    script = generate_script(commands, ip, args.dry_run)
    if script:
        print(f"\n{Colors.OKGREEN}[+] Ready: pwsh ./{script}{Colors.ENDC}")
        if not args.dry_run:
            print(f"{Colors.WARNING}[!] Review before executing!{Colors.ENDC}")

if __name__ == "__main__":
    main()
