#!/usr/bin/env python3
"""
NetWeave v8.0 - The CTF Reconnaissance & Attack Path Correlation Framework
Surgically perfected for zero-failure operation.
"""
import sys
import os
import re
import json
import time
import socket
import argparse
import ipaddress
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuration
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_TAGS_URL = "http://localhost:11434/api/tags"
SESSION_FILE = ".netweave_session.json"

# The Council of Wizards - Ranked by reliability for CTFs
COUNCIL = {
    "qwen2.5-coder:7b": {"role": "Battle Mage", "weight": 3, "timeout": 60, "desc": "Fast command generation"},
    "llama3.2": {"role": "Scout", "weight": 2, "timeout": 30, "desc": "Rapid fallback"},
    "mistral": {"role": "Duelist", "weight": 2, "timeout": 45, "desc": "Balanced performance"},
    "deepseek-r1:8b": {"role": "Archivist", "weight": 3, "timeout": 180, "desc": "Deep reasoning (slow)"},
}

# Built-in attack patterns for when AI fails
ATTACK_PATTERNS = {
    "http": {
        "tools": ["gobuster", "nikto", "curl", "wfuzz"],
        "paths": ["/admin", "/login", "/api", "/backup", "/.env", "/robots.txt"],
        "extensions": ["php", "txt", "bak", "old", "zip"]
    },
    "ssh": {
        "tools": ["hydra", "ssh-audit", "nc"],
        "users": ["root", "admin", "user", "test"],
        "checks": ["version", "key-auth", "banner"]
    },
    "ftp": {
        "tools": ["hydra", "ftp", "lftp"],
        "anon": True
    },
    "smb": {
        "tools": ["enum4linux", "smbclient", "smbmap", "nmap"],
        "shares": ["IPC$", "C$", "ADMIN$", "public"]
    }
}

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

@dataclass
class Service:
    port: int
    protocol: str
    state: str
    name: str
    version: str
    cpe: str
    scripts: List[str]

@dataclass  
class Host:
    ip: str
    hostname: str
    os: str
    services: List[Service]
    open_ports: List[int]

class NetWeave:
    def __init__(self):
        self.session = {}
        self.target = None
        self.host = None
        
    def banner(self):
        print(f"""
    {Colors.OKCYAN}███╗   ██╗███████╗████████╗██╗    ██╗███████╗ █████╗ ██╗   ██╗███████╗{Colors.ENDC}
    {Colors.OKCYAN}████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔════╝██╔══██╗██║   ██║██╔════╝{Colors.ENDC}
    {Colors.OKCYAN}██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║█████╗  ███████║██║   ██║█████╗  {Colors.ENDC}
    {Colors.OKCYAN}██║╚██╗██║██╔══╝     ██║   ██║███╗██║██╔══╝  ██╔══██║╚██╗ ██╔╝██╔══╝  {Colors.ENDC}
    {Colors.OKCYAN}██║ ╚████║███████╗   ██║   ╚███╔███╔╝███████╗██║  ██║ ╚████╔╝ ███████╗{Colors.ENDC}
    {Colors.OKCYAN}╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝{Colors.ENDC}
    {Colors.OKGREEN}>>> NetWeave v8.0 - Council of Wizards Edition <<<{Colors.ENDC}
        """)
    
    def validate_target(self, ip_str: str) -> Optional[str]:
        """Validate target with safety checks."""
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.is_loopback:
                return str(ip)
            if not ip.is_private:
                print(f"{Colors.WARNING}[!] WARNING: {ip} is PUBLIC!{Colors.ENDC}")
                resp = input(f"{Colors.WARNING}    Continue only if authorized [y/N]: {Colors.ENDC}")
                if resp.lower() not in ['y', 'yes']:
                    return None
            return str(ip)
        except ValueError:
            print(f"{Colors.FAIL}[-] Invalid IP: {ip_str}{Colors.ENDC}")
            return None
    
    def check_ollama(self) -> bool:
        """Verify Ollama is responsive."""
        try:
            r = requests.get(OLLAMA_TAGS_URL, timeout=5)
            if r.status_code == 200:
                models = [m["name"] for m in r.json().get("models", [])]
                if models:
                    return True
                else:
                    print(f"{Colors.FAIL}[-] No models found. Run: ollama pull qwen2.5-coder:7b{Colors.ENDC}")
                    return False
            return False
        except Exception as e:
            print(f"{Colors.FAIL}[-] Ollama not running: {e}{Colors.ENDC}")
            print(f"{Colors.FAIL}    Start with: ollama serve{Colors.ENDC}")
            return False
    
    def run_tool(self, cmd: List[str], desc: str, timeout: int = 300) -> Tuple[str, bool]:
        """Execute tool with comprehensive error handling."""
        print(f"{Colors.OKBLUE}[*] {desc}...{Colors.ENDC}")
        
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout
            )
            
            success = result.returncode == 0 or len(result.stdout) > 100  # Some tools return non-zero but have output
            status = Colors.OKGREEN if success else Colors.WARNING
            print(f"{status}[+] {desc} complete ({len(result.stdout)} bytes){Colors.ENDC}")
            return result.stdout, success
            
        except subprocess.TimeoutExpired:
            print(f"{Colors.FAIL}[-] {desc} timed out{Colors.ENDC}")
            return "", False
        except FileNotFoundError:
            print(f"{Colors.FAIL}[-] {cmd[0]} not installed{Colors.ENDC}")
            return "", False
        except Exception as e:
            print(f"{Colors.FAIL}[-] {desc} failed: {e}{Colors.ENDC}")
            return "", False
    
    def nmap_scan(self, target: str) -> Host:
        """Perform structured nmap scan and parse XML."""
        xml_file = f"nmap_{target.replace('.', '_')}.xml"
        
        # Run nmap with XML output
        cmd = ["nmap", "-sV", "-sC", "-Pn", "-oX", xml_file, target]
        output, success = self.run_tool(cmd, "Nmap service scan", 300)
        
        if not success or not os.path.exists(xml_file):
            print(f"{Colors.WARNING}[!] Falling back to basic TCP scan{Colors.ENDC}")
            return self._fallback_scan(target)
        
        # Parse XML
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            host = Host(
                ip=target,
                hostname="",
                os="",
                services=[],
                open_ports=[]
            )
            
            for host_elem in root.findall('host'):
                for addr in host_elem.findall('address'):
                    if addr.get('addrtype') == 'ipv4':
                        host.ip = addr.get('addr')
                
                hostnames = host_elem.find('hostnames')
                if hostnames is not None:
                    for name in hostnames.findall('hostname'):
                        host.hostname = name.get('name', '')
                
                ports = host_elem.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        if port.get('state') == 'open':
                            port_num = int(port.get('portid'))
                            host.open_ports.append(port_num)
                            
                            service = Service(
                                port=port_num,
                                protocol=port.get('protocol', 'tcp'),
                                state='open',
                                name='unknown',
                                version='',
                                cpe='',
                                scripts=[]
                            )
                            
                            svc = port.find('service')
                            if svc is not None:
                                service.name = svc.get('name', 'unknown')
                                service.version = svc.get('version', '')
                                service.cpe = svc.get('cpe', '')
                            
                            for script in port.findall('script'):
                                service.scripts.append(f"{script.get('id')}: {script.get('output', '')[:100]}")
                            
                            host.services.append(service)
            
            return host
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] XML parse failed: {e}, using fallback{Colors.ENDC}")
            return self._fallback_scan(target)
    
    def _fallback_scan(self, target: str) -> Host:
        """Basic TCP connect scan when nmap fails."""
        print(f"{Colors.OKBLUE}[*] Running fallback port scan...{Colors.ENDC}")
        open_ports = []
        common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                    print(f"{Colors.OKGREEN}    Port {port}/tcp open{Colors.ENDC}")
                sock.close()
            except:
                pass
        
        services = []
        for port in open_ports:
            name = {21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns', 80: 'http', 
                   110: 'pop3', 139: 'netbios', 143: 'imap', 443: 'https', 445: 'smb',
                   3306: 'mysql', 3389: 'rdp', 5432: 'postgresql', 5900: 'vnc', 
                   8080: 'http-proxy', 8443: 'https-alt'}.get(port, 'unknown')
            services.append(Service(port=port, protocol='tcp', state='open', name=name, 
                                   version='', cpe='', scripts=[]))
        
        return Host(ip=target, hostname='', os='', services=services, open_ports=open_ports)
    
    def web_scan(self, host: Host) -> Dict:
        """Scan web services with multiple tools."""
        results = {}
        
        web_services = [s for s in host.services if s.name in ['http', 'https', 'http-proxy']]
        
        for svc in web_services:
            port = svc.port
            proto = 'https' if svc.name == 'https' or port in [443, 8443] else 'http'
            url = f"{proto}://{host.ip}:{port}" if port not in [80, 443] else f"{proto}://{host.ip}"
            
            print(f"{Colors.OKBLUE}[*] Scanning web service on port {port}{Colors.ENDC}")
            
            # Gobuster
            wordlists = [
                "/usr/share/wordlists/dirb/common.txt",
                "/usr/share/seclists/Discovery/Web-Content/common.txt",
                "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
            ]
            wordlist = next((w for w in wordlists if os.path.exists(w)), None)
            
            if wordlist:
                cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-q", "-t", "50", "-k"]
                out, _ = self.run_tool(cmd, f"Gobuster {port}", 180)
                results[f"gobuster_{port}"] = out
            
            # Nikto
            cmd = ["nikto", "-h", url, "-maxtime", "120", "-C", "all"]
            out, _ = self.run_tool(cmd, f"Nikto {port}", 150)
            results[f"nikto_{port}"] = out
        
        return results
    
    def summon_wizard(self, model: str, scan_summary: str, timeout: int) -> Optional[Dict]:
        """Query single AI model."""
        try:
            import requests
        except ImportError:
            return None
        
        prompt = f"""You are a CTF penetration testing expert. Analyze this scan and provide ONE best attack command.

SCAN:
{scan_summary}

Respond ONLY with:
VULN: [brief vulnerability name]
[CMD] [exact command to run] [CMD]
CONFIDENCE: [High/Medium/Low]"""

        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.3, "num_predict": 512}
        }
        
        try:
            start = time.time()
            r = requests.post(OLLAMA_URL, json=payload, timeout=timeout)
            elapsed = time.time() - start
            
            if r.status_code == 200:
                text = r.json().get('response', '')
                
                # Extract command
                cmd_match = re.search(r'\[CMD\]\s*(.*?)\s*\[CMD\]', text, re.DOTALL)
                cmd = cmd_match.group(1).strip() if cmd_match else None
                
                # Extract confidence
                conf_match = re.search(r'CONFIDENCE:\s*(High|Medium|Low)', text, re.I)
                conf = conf_match.group(1).lower() if conf_match else "medium"
                
                # Extract vuln
                vuln_match = re.search(r'VULN:\s*(.+?)(?:\n|$)', text, re.I)
                vuln = vuln_match.group(1).strip() if vuln_match else "Unknown"
                
                if cmd and len(cmd) > 5:
                    return {
                        "model": model,
                        "command": cmd,
                        "vuln": vuln,
                        "confidence": conf,
                        "time": elapsed,
                        "raw": text
                    }
        except Exception as e:
            pass
        
        return None
    
    def council_deliberation(self, host: Host, web_results: Dict) -> Tuple[str, List[str]]:
        """The Council of Wizards convenes to decide the attack path."""
        print(f"\n{Colors.HEADER}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}  ★ THE COUNCIL OF WIZARDS CONVENES ★{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}\n")
        
        # Prepare scan summary
        summary = f"Target: {host.ip}\n"
        summary += f"Open Ports: {', '.join(map(str, host.open_ports))}\n\n"
        
        for svc in host.services:
            summary += f"Port {svc.port}/{svc.protocol}: {svc.name}"
            if svc.version:
                summary += f" ({svc.version})"
            summary += "\n"
        
        # Summarize web results
        for key, val in web_results.items():
            if val and len(val) > 50:
                lines = val.strip().split('\n')[:10]  # First 10 lines
                summary += f"\n{key}:\n" + '\n'.join(lines) + "\n"
        
        # Summon all wizards in parallel
        available_models = []
        try:
            r = requests.get(OLLAMA_TAGS_URL, timeout=5)
            if r.status_code == 200:
                available_models = [m["name"] for m in r.json().get("models", [])]
        except:
            pass
        
        # Filter to council members that are available
        wizards_to_summon = {k: v for k, v in COUNCIL.items() if k in available_models}
        
        if not wizards_to_summon:
            print(f"{Colors.WARNING}[!] No council models available, using built-in patterns{Colors.ENDC}")
            return self._pattern_based_attacks(host)
        
        print(f"{Colors.OKBLUE}[*] Summoning {len(wizards_to_summon)} wizards...{Colors.ENDC}\n")
        
        responses = []
        with ThreadPoolExecutor(max_workers=len(wizards_to_summon)) as executor:
            future_to_model = {
                executor.submit(self.summon_wizard, model, summary, info["timeout"]): (model, info)
                for model, info in wizards_to_summon.items()
            }
            
            for future in as_completed(future_to_model):
                model, info = future_to_model[future]
                try:
                    result = future.result()
                    if result:
                        result["role"] = info["role"]
                        result["weight"] = info["weight"]
                        responses.append(result)
                        print(f"{Colors.OKGREEN}  ✓ {info['role']} ({model}): {result['vuln']} [{result['confidence']}]{Colors.ENDC}")
                    else:
                        print(f"{Colors.WARNING}  ⚠ {model}: No response{Colors.ENDC}")
                except Exception as e:
                    print(f"{Colors.FAIL}  ✗ {model}: Failed{Colors.ENDC}")
        
        if not responses:
            print(f"{Colors.WARNING}[!] Council failed, using pattern matching{Colors.ENDC}")
            return self._pattern_based_attacks(host)
        
        # Vote on commands
        command_votes = {}
        for r in responses:
            cmd = r["command"]
            norm_cmd = re.sub(r'\s+', ' ', cmd.lower().strip())
            tool = norm_cmd.split()[0] if norm_cmd else "unknown"
            
            key = f"{tool}:{hash(norm_cmd) % 10000}"  # Group similar commands
            
            if key not in command_votes:
                command_votes[key] = {
                    "command": cmd,
                    "votes": 0,
                    "weight": 0,
                    "vulns": [],
                    "supporters": []
                }
            
            weight = r["weight"] * {"high": 3, "medium": 2, "low": 1}.get(r["confidence"], 1)
            command_votes[key]["votes"] += 1
            command_votes[key]["weight"] += weight
            command_votes[key]["vulns"].append(r["vuln"])
            command_votes[key]["supporters"].append(r["role"])
        
        # Sort by weight (votes × confidence)
        sorted_commands = sorted(command_votes.values(), key=lambda x: x["weight"], reverse=True)
        
        # Display results
        print(f"\n{Colors.HEADER}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}  DELIBERATION RESULTS{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}\n")
        
        for i, opt in enumerate(sorted_commands[:3], 1):
            medal = "🥇" if i == 1 else "🥈" if i == 2 else "🥉"
            color = Colors.OKGREEN if i == 1 else Colors.WARNING if i == 2 else Colors.OKBLUE
            
            print(f"{color}  {medal} Rank {i}: {opt['vulns'][0]}{Colors.ENDC}")
            print(f"      Command: {opt['command'][:70]}{'...' if len(opt['command']) > 70 else ''}")
            print(f"      Supported by: {', '.join(set(opt['supporters']))} (weight: {opt['weight']})")
            print()
        
        primary = sorted_commands[0]["command"] if sorted_commands else "nmap -sC -sV " + host.ip
        alternatives = [c["command"] for c in sorted_commands[1:3]] if len(sorted_commands) > 1 else []
        
        print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}  ★ PRIMARY ATTACK VECTOR SELECTED ★{Colors.ENDC}")
        print(f"{Colors.OKGREEN}  {primary}{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}\n")
        
        return primary, alternatives
    
    def _pattern_based_attacks(self, host: Host) -> Tuple[str, List[str]]:
        """Fallback when AI fails - use built-in patterns."""
        print(f"{Colors.OKBLUE}[*] Using built-in attack patterns{Colors.ENDC}")
        
        commands = []
        
        for svc in host.services:
            patterns = ATTACK_PATTERNS.get(svc.name, {})
            if patterns:
                tool = patterns["tools"][0] if patterns.get("tools") else "nmap"
                
                if svc.name == "http":
                    cmd = f"gobuster dir -u http://{host.ip}:{svc.port}/ -w /usr/share/wordlists/dirb/common.txt -t 50"
                elif svc.name == "ssh":
                    cmd = f"hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://{host.ip}"
                elif svc.name == "ftp":
                    cmd = f"hydra -l anonymous -p anonymous ftp://{host.ip}"
                elif svc.name == "smb":
                    cmd = f"enum4linux -a {host.ip}"
                else:
                    cmd = f"nmap -sC -sV -p {svc.port} {host.ip}"
                
                commands.append((cmd, svc.name))
        
        if not commands:
            commands = [(f"nmap -sC -sV -p- {host.ip}", "full_scan")]
        
        primary = commands[0][0]
        alternatives = [c[0] for c in commands[1:3]]
        
        print(f"{Colors.OKGREEN}[+] Pattern-based primary: {primary}{Colors.ENDC}")
        
        return primary, alternatives
    
    def generate_payloads(self, primary: str, alternatives: List[str], target: str, dry_run: bool):
        """Generate execution scripts in multiple formats."""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"netweave_{target.replace('.', '_')}_{timestamp}"
        
        scripts = []
        
        # PowerShell
        ps_file = f"{base_name}.ps1"
        with open(ps_file, "w") as f:
            f.write(f"# NetWeave Execution Payload\n")
            f.write(f"# Target: {target}\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n\n")
            
            f.write("$ErrorActionPreference = 'Continue'\n\n")
            
            cmds = [primary] + alternatives
            for i, cmd in enumerate(cmds, 1):
                safe = cmd.replace("'", "''")
                f.write(f"Write-Host '[{i}/{len(cmds)}] {safe}' -ForegroundColor Cyan\n")
                if dry_run:
                    f.write(f"Write-Host 'DRY RUN' -ForegroundColor Yellow\n")
                else:
                    f.write(f"Invoke-Expression '{safe}'\n")
                f.write("Write-Host ''\n")
            
            f.write("Write-Host '[+] Complete' -ForegroundColor Green\n")
        
        scripts.append(ps_file)
        print(f"{Colors.OKGREEN}[+] PowerShell: ./{ps_file}{Colors.ENDC}")
        
        # Bash
        sh_file = f"{base_name}.sh"
        with open(sh_file, "w") as f:
            f.write("#!/bin/bash\n")
            f.write(f"# NetWeave Execution Payload\n")
            f.write(f"# Target: {target}\n\n")
            
            cmds = [primary] + alternatives
            for i, cmd in enumerate(cmds, 1):
                f.write(f"echo '[{i}/{len(cmds)}] {cmd}'\n")
                f.write(f"{cmd}\n")
                f.write("echo ''\n")
            
            f.write("echo '[+] Complete'\n")
        
        os.chmod(sh_file, 0o755)
        scripts.append(sh_file)
        print(f"{Colors.OKGREEN}[+] Bash: ./{sh_file}{Colors.ENDC}")
        
        # Python
        py_file = f"{base_name}_exec.py"
        with open(py_file, "w") as f:
            f.write("#!/usr/bin/env python3\n")
            f.write(f"# NetWeave Execution Payload\n")
            f.write(f"# Target: {target}\n\n")
            f.write("import subprocess\n\n")
            
            cmds = [primary] + alternatives
            for i, cmd in enumerate(cmds, 1):
                f.write(f"print('[{i}/{len(cmds)}] {cmd}')\n")
                f.write(f"subprocess.run({repr(cmd.split())}, capture_output=False)\n")
                f.write("print()\n")
            
            f.write("print('[+] Complete')\n")
        
        os.chmod(py_file, 0o755)
        scripts.append(py_file)
        print(f"{Colors.OKGREEN}[+] Python: ./{py_file}{Colors.ENDC}")
        
        # JSON summary
        json_file = f"{base_name}.json"
        with open(json_file, "w") as f:
            json.dump({
                "target": target,
                "timestamp": datetime.now().isoformat(),
                "primary_attack": primary,
                "alternatives": alternatives,
                "scripts": scripts
            }, f, indent=2)
        
        print(f"{Colors.OKGREEN}[+] Summary: ./{json_file}{Colors.ENDC}")
        
        return scripts
    
    def save_session(self):
        """Save current session for resume."""
        with open(SESSION_FILE, "w") as f:
            json.dump(asdict(self.host) if self.host else {}, f)
    
    def run(self, args):
        """Main execution flow."""
        self.banner()
        
        # Validate target
        target = args.target or input(f"{Colors.OKBLUE}[?] Target IP: {Colors.ENDC}").strip()
        target = self.validate_target(target)
        if not target:
            sys.exit(1)
        
        self.target = target
        
        # Check Ollama (optional - we have fallbacks)
        ollama_ready = self.check_ollama()
        
        # Reconnaissance
        print(f"\n{Colors.HEADER}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}  PHASE 1: RECONNAISSANCE{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}\n")
        
        host = self.nmap_scan(target)
        self.host = host
        
        print(f"\n{Colors.OKGREEN}[+] Discovered {len(host.services)} services:{Colors.ENDC}")
        for svc in host.services:
            ver = f" ({svc.version})" if svc.version else ""
            print(f"    • Port {svc.port}/{svc.protocol}: {svc.name}{ver}")
        
        # Web scanning
        web_results = self.web_scan(host)
        
        # AI Analysis (Council of Wizards)
        print(f"\n{Colors.HEADER}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}  PHASE 2: COUNCIL DELIBERATION{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}\n")
        
        if ollama_ready:
            primary, alternatives = self.council_deliberation(host, web_results)
        else:
            primary, alternatives = self._pattern_based_attacks(host)
        
        # Payload Generation
        print(f"\n{Colors.HEADER}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}  PHASE 3: PAYLOAD GENERATION{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}\n")
        
        scripts = self.generate_payloads(primary, alternatives, target, args.dry_run)
        
        # Summary
        print(f"\n{Colors.HEADER}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}  ★ NETWEAVE COMPLETE ★{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}\n")
        
        print(f"{Colors.OKCYAN}Next steps:{Colors.ENDC}")
        print(f"  1. Review: cat {scripts[-1].replace('.py', '.json')}")
        print(f"  2. Execute: ./{scripts[0]}")
        print(f"  3. Listener: nc -lvnp 4444")
        print()

def main():
    parser = argparse.ArgumentParser(description='NetWeave v8.0 - Council of Wizards Edition')
    parser.add_argument('-t', '--target', help='Target IP address')
    parser.add_argument('--dry-run', action='store_true', help='Generate scripts without execution')
    parser.add_argument('--resume', action='store_true', help='Resume previous session')
    args = parser.parse_args()
    
    nw = NetWeave()
    nw.run(args)

if __name__ == "__main__":
    main()