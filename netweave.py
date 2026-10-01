#!/usr/bin/env python3
"""
NetWeave v9.2 - Cyan Engine
OS-Aware Reconnaissance & Attack Path Correlation
Zero-cloud, local Ollama inference only
"""

import asyncio
import argparse
import ipaddress
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Any, Tuple

try:
    import aiohttp
    ASYNC_HTTP = True
except ImportError:
    ASYNC_HTTP = False
    print("[!] pip install aiohttp")

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

class Config:
    OLLAMA_URL = "http://localhost:11434/api/generate"
    OLLAMA_TAGS_URL = "http://localhost:11434/api/tags"
    AI_TIMEOUT = 20
    MAX_RETRIES = 1
    CONCURRENT_SCANS = 50
    TOP_CTF_PORTS = [21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 
                     443, 445, 464, 993, 995, 2049, 3306, 3389, 5432, 5985, 8080, 8443]
    
    COUNCIL = {
        "qwen2.5-coder:7b": {"role": "Battle Mage", "weight": 3},
        "llama3.2": {"role": "Scout", "weight": 2},
        "mistral": {"role": "Duelist", "weight": 2},
    }

class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    ENDC = '\033[0m'

@dataclass
class Service:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    name: str = "unknown"
    version: str = ""
    banner: str = ""
    cpe: str = ""

@dataclass
class Host:
    ip: str
    hostname: str = ""
    os: str = "Unknown"
    os_accuracy: int = 0
    services: List[Service] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)

class NetWeave:
    def __init__(self):
        self.console = Console() if RICH_AVAILABLE else None
        self.target: Optional[str] = None
        self.host: Optional[Host] = None
        self.session: Optional[aiohttp.ClientSession] = None
        
    def banner(self):
        banner = """
    ███╗   ██╗███████╗████████╗██╗    ██╗███████╗ █████╗ ██╗   ██╗███████╗
    ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔════╝██╔══██╗██║   ██║██╔════╝
    ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║█████╗  ███████║██║   ██║█████╗  
    ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██╔══╝  ██╔══██║╚██╗ ██╔╝██╔══╝  
    ██║ ╚████║███████╗   ██║   ╚███╔███╔╝███████╗██║  ██║ ╚████╔╝ ███████╗
    ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝
        """
        if self.console:
            self.console.print(Panel(Text(banner, style="bold cyan"), 
                                   subtitle="[cyan]v9.2 Cyan Engine - OS-Aware Council[/cyan]", 
                                   border_style="cyan"))
        else:
            print(f"{Colors.CYAN}{banner}{Colors.ENDC}")
            print(f"{Colors.CYAN}>>> NetWeave v9.2 - Cyan Engine <<<{Colors.ENDC}\n")
    
    def status(self, msg: str, level: str = "info"):
        indicators = {
            "info": ("[*]", Colors.BLUE),
            "success": ("[+]", Colors.GREEN),
            "warning": ("[!]", Colors.YELLOW),
            "error": ("[-]", Colors.RED),
            "scan": ("[~]", Colors.CYAN),
            "os": ("[OS]", Colors.CYAN)
        }
        ind, color = indicators.get(level, ("[*]", Colors.BLUE))
        if RICH_AVAILABLE:
            style = {"info": "blue", "success": "green", "warning": "yellow", 
                    "error": "red", "scan": "cyan", "os": "magenta"}.get(level, "white")
            self.console.print(f"[{style}]{ind} {msg}[/{style}]")
        else:
            print(f"{color}{ind} {msg}{Colors.ENDC}")
    
    def validate_target(self, ip_str: str) -> Optional[str]:
        try:
            ip = ipaddress.ip_address(ip_str)
            if not ip.is_private:
                self.status(f"WARNING: {ip} is PUBLIC", "warning")
                if input("Continue only if authorized [y/N]: ").lower() not in ['y', 'yes']:
                    return None
            return str(ip)
        except ValueError:
            self.status(f"Invalid IP: {ip_str}", "error")
            return None
    
    def detect_os_heuristic(self, host: Host) -> str:
        win_services = {'smb', 'microsoft-ds', 'msrpc', 'winrm', 'ms-wbt-server'}
        linux_services = {'ssh', 'nfs', 'rpcbind', 'postgresql', 'mysql'}
        
        win_score = sum(1 for s in host.services if s.name in win_services)
        linux_score = sum(1 for s in host.services if s.name in linux_services)
        
        if 3389 in host.open_ports or 5985 in host.open_ports or 445 in host.open_ports:
            win_score += 2
        if 2049 in host.open_ports or 22 in host.open_ports:
            linux_score += 2
        
        for svc in host.services:
            banner = (svc.version + svc.banner).lower()
            if any(w in banner for w in ['windows', 'microsoft', 'iis', 'win32']):
                win_score += 3
            if any(l in banner for l in ['ubuntu', 'debian', 'centos', 'red hat', 'linux']):
                linux_score += 3
        
        if win_score > linux_score:
            return "Windows"
        elif linux_score > win_score:
            return "Linux"
        return "Unknown"
    
    async def nmap_scan(self, target: str) -> Host:
        xml_file = f"/tmp/netweave_{target.replace('.', '_')}.xml"
        if os.path.exists(xml_file):
            os.remove(xml_file)
        
        cmd = ["nmap", "-sV", "-O", "--osscan-guess", "-Pn", "--open",
               "-oX", xml_file, "--top-ports", "1000", "--max-retries", "1",
               "--host-timeout", "3m", "-T4", target]
        
        self.status("Running OS-Aware Nmap...", "scan")
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE
            )
            try:
                await asyncio.wait_for(proc.communicate(), timeout=180)
            except asyncio.TimeoutError:
                proc.kill()
                return await self.fallback_scan(target)
        except FileNotFoundError:
            return await self.fallback_scan(target)
        
        host = Host(ip=target)
        
        if not os.path.exists(xml_file):
            return await self.fallback_scan(target)
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for host_elem in root.findall('host'):
                os_elem = host_elem.find('os')
                if os_elem is not None:
                    osmatch = os_elem.find('osmatch')
                    if osmatch is not None:
                        host.os = osmatch.get('name', 'Unknown')
                        host.os_accuracy = int(osmatch.get('accuracy', 0))
                        self.status(f"OS Detected: {host.os}", "os")
                
                ports_elem = host_elem.find('ports')
                if ports_elem is not None:
                    for port_elem in ports_elem.findall('port'):
                        state = port_elem.find('state')
                        if state is not None and state.get('state') == 'open':
                            port_num = int(port_elem.get('portid'))
                            host.open_ports.append(port_num)
                            
                            service = Service(port=port_num)
                            svc_elem = port_elem.find('service')
                            if svc_elem is not None:
                                service.name = svc_elem.get('name', 'unknown')
                                product = svc_elem.get('product', '')
                                version = svc_elem.get('version', '')
                                service.version = f"{product} {version}".strip()
                                service.banner = svc_elem.get('extrainfo', '')
                                
                                if host.os == "Unknown":
                                    banner = (service.version + service.banner).lower()
                                    if any(w in banner for w in ['windows', 'microsoft']):
                                        host.os = "Windows"
                                    elif any(l in banner for l in ['ubuntu', 'debian', 'linux']):
                                        host.os = "Linux"
                            
                            host.services.append(service)
            
            if host.os == "Unknown":
                host.os = self.detect_os_heuristic(host)
                
        except Exception as e:
            self.status(f"Parse error: {e}", "error")
            host = await self.fallback_scan(target)
        finally:
            try:
                os.remove(xml_file)
            except:
                pass
        
        self.status(f"Found {len(host.services)} services | OS: {host.os}", "success")
        return host
    
    async def fallback_scan(self, target: str) -> Host:
        self.status("Using fallback TCP probe...", "scan")
        host = Host(ip=target)
        
        semaphore = asyncio.Semaphore(Config.CONCURRENT_SCANS)
        
        async def probe(port: int) -> Optional[int]:
            async with semaphore:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(target, port), timeout=1.5
                    )
                    writer.close()
                    await writer.wait_closed()
                    return port
                except:
                    return None
        
        tasks = [probe(p) for p in Config.TOP_CTF_PORTS]
        results = await asyncio.gather(*tasks)
        host.open_ports = sorted([p for p in results if p is not None])
        
        service_map = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 88: 'kerberos', 110: 'pop3', 111: 'rpcbind',
            135: 'msrpc', 139: 'netbios', 143: 'imap', 443: 'https',
            445: 'smb', 464: 'kpasswd', 993: 'imaps', 995: 'pop3s',
            2049: 'nfs', 3306: 'mysql', 3389: 'rdp', 5432: 'postgresql',
            5985: 'winrm', 8080: 'http-proxy', 8443: 'https-alt'
        }
        
        for port in host.open_ports:
            host.services.append(Service(port=port, name=service_map.get(port, 'unknown')))
        
        host.os = self.detect_os_heuristic(host)
        self.status(f"Fallback: {len(host.open_ports)} ports | OS: {host.os}", "success")
        return host
    
    async def query_ollama(self, model: str, prompt: str) -> Optional[str]:
        if not ASYNC_HTTP:
            return None
        
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.1, "num_predict": 100}
        }
        
        try:
            timeout = aiohttp.ClientTimeout(total=Config.AI_TIMEOUT)
            async with self.session.post(Config.OLLAMA_URL, json=payload, timeout=timeout) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get('response', '')
        except:
            pass
        return None
    
    async def council_deliberation(self, host: Host) -> Dict[str, Any]:
        self.status("Council convening...", "info")
        
        services_str = ", ".join([f"{s.port}:{s.name}" for s in host.services[:5]])
        prompt = f"Target {host.ip} OS:{host.os} Services:{services_str}. Respond ONLY with: [CMD]command to run[CMD]"
        
        try:
            async with self.session.get(Config.OLLAMA_TAGS_URL, timeout=5) as resp:
                if resp.status != 200:
                    raise Exception("Ollama unreachable")
                data = await resp.json()
                available = [m["name"] for m in data.get("models", [])]
        except:
            self.status("Ollama unreachable, using patterns", "warning")
            return self._pattern_fallback(host)
        
        wizards = {k: v for k, v in Config.COUNCIL.items() if k in available}
        if not wizards:
            return self._pattern_fallback(host)
        
        votes = {}
        for model, info in wizards.items():
            response = await self.query_ollama(model, prompt)
            if response:
                match = re.search(r'\[CMD\]\s*(.*?)\s*(?:\[CMD\]|$)', response, re.DOTALL)
                if match:
                    cmd = match.group(1).strip()
                    self.status(f"  {info['role']}: {cmd[:40]}...", "success")
                    key = hash(cmd) % 10000
                    if key not in votes:
                        votes[key] = {"cmd": cmd, "weight": 0}
                    votes[key]["weight"] += info["weight"]
        
        if not votes:
            return self._pattern_fallback(host)
        
        winner = max(votes.values(), key=lambda x: x["weight"])
        return {"primary": winner["cmd"], "alternatives": [], "source": "Council"}
    
    def _pattern_fallback(self, host: Host) -> Dict[str, Any]:
        primary = None
        
        if host.os == "Windows":
            if any(s.port == 445 for s in host.services):
                primary = f"enum4linux -a {host.ip}"
            elif any(s.port == 5985 for s in host.services):
                primary = f"evil-winrm -i {host.ip} -u administrator"
        else:
            if any(s.name == 'http' for s in host.services):
                primary = f"gobuster dir -u http://{host.ip}/ -w /usr/share/wordlists/dirb/common.txt -t 50"
            elif any(s.name == 'ssh' for s in host.services):
                primary = f"hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://{host.ip}"
            elif any(s.name == 'ftp' for s in host.services):
                primary = f"hydra -l anonymous -p anonymous ftp://{host.ip}"
        
        if not primary:
            primary = f"nmap -sC -sV -p- {host.ip}"
        
        self.status(f"Pattern: {primary[:50]}...", "success")
        return {"primary": primary, "alternatives": [], "source": "Pattern"}
    
    def save_contract(self, plan: Dict, host: Host):
        contract = {
            "target": host.ip,
            "timestamp": datetime.now().isoformat(),
            "operating_system": host.os,
            "os_confidence": host.os_accuracy,
            "ports": [{"port": s.port, "service": s.name, "version": s.version, 
                      "notes": s.banner[:50] if s.banner else ""} for s in host.services],
            "recommended_vector": {
                "vector_name": plan["primary"].split()[0],
                "target_port": host.services[0].port if host.services else 0,
                "vulnerability_type": "Enumeration",
                "technical_summary": plan["primary"]
            },
            "commands": {
                "primary": plan["primary"],
                "alternatives": plan["alternatives"],
                "source": plan.get("source", "Unknown")
            },
            "metadata": {"tool": "NetWeave", "version": "9.2"}
        }
        
        filename = f"netweave_{host.ip.replace('.', '_')}.json"
        with open(filename, 'w') as f:
            json.dump(contract, f, indent=2)
        
        self.status(f"Contract: {filename}", "success")
        return filename
    
    async def run(self, target: str):
        self.banner()
        
        validated = self.validate_target(target)
        if not validated:
            sys.exit(1)
        self.target = validated
        
        self.status(f"Target: {self.target}", "info")
        
        if ASYNC_HTTP:
            self.session = aiohttp.ClientSession()
        
        try:
            self.status("Phase 1: Reconnaissance", "info")
            self.host = await self.nmap_scan(self.target)
            
            if not self.host.services:
                self.status("No services found", "error")
                return
            
            self.status("Phase 2: Council Deliberation", "info")
            plan = await self.council_deliberation(self.host)
            
            self.status("Phase 3: Contract Generation", "info")
            self.save_contract(plan, self.host)
            
            self.status("Pipeline ready for Sectumsempra", "success")
            
        finally:
            if self.session:
                await self.session.close()

def main():
    parser = argparse.ArgumentParser(description='NetWeave v9.2 - Cyan Engine')
    parser.add_argument('target', help='Target IP address')
    parser.add_argument('--no-ai', action='store_true', help='Skip AI, use patterns only')
    args = parser.parse_args()
    
    if args.no_ai:
        Config.COUNCIL = {}
    
    try:
        asyncio.run(NetWeave().run(args.target))
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Cancelled{Colors.ENDC}")
        sys.exit(0)

if __name__ == "__main__":
    main()
