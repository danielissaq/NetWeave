#!/usr/bin/env python3
"""
NetWeave v9.1 - Cyan Engine (Bulletproof Edition)
OS-Aware Reconnaissance with Stable Local AI
"""

import asyncio
import argparse
import ipaddress
import json
import os
import re
import socket
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Dict, Optional, Any
import subprocess

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
    AI_TIMEOUT = 30  # Reduced from 90 - aggressive for CTF speed
    MAX_RETRIES = 2
    CONCURRENT_SCANS = 50
    TOP_CTF_PORTS = [21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 443, 445, 464, 993, 995, 3306, 3389, 5985, 8080, 8443]
    
    COUNCIL = {
        "qwen2.5-coder:7b": {"role": "Battle Mage", "weight": 3},
        "deepseek-r1:8b": {"role": "Archivist", "weight": 2},  # Reduced weight - too slow
        "llama3.2": {"role": "Scout", "weight": 2},
    }

@dataclass
class Service:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    name: str = "unknown"
    version: str = ""
    banner: str = ""
    cpe: str = ""
    scripts: Dict[str, str] = field(default_factory=dict)

@dataclass
class Host:
    ip: str
    hostname: str = ""
    os: str = "Unknown"
    os_accuracy: int = 0  # Confidence score
    ttl: Optional[int] = None  # For heuristic detection
    services: List[Service] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)

class NetWeave:
    def __init__(self):
        self.console = Console() if RICH_AVAILABLE else None
        self.target: Optional[str] = None
        self.host: Optional[Host] = None
        self.session: Optional[aiohttp.ClientSession] = None
        
    def banner(self):
        banner_text = """
    ███╗   ██╗███████╗████████╗██╗    ██╗███████╗ █████╗ ██╗   ██╗███████╗
    ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔════╝██╔══██╗██║   ██║██╔════╝
    ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║█████╗  ███████║██║   ██║█████╗  
    ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██╔══╝  ██╔══██║╚██╗ ██╔╝██╔══╝  
    ██║ ╚████║███████╗   ██║   ╚███╔███╔╝███████╗██║  ██║ ╚████╔╝ ███████╗
    ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝
        """
        if self.console:
            self.console.print(Panel(Text(banner_text, style="bold cyan"), 
                                   subtitle="[cyan]v9.1 Cyan Engine - OS-Aware Council[/cyan]", 
                                   border_style="cyan"))
        else:
            print(f"\033[96m{banner_text}\033[0m")
            print("\033[96m>>> NetWeave v9.1 - Bulletproof Council <<<\033[0m\n")
    
    def status(self, message: str, level: str = "info"):
        indicators = {
            "info": ("[*]", "\033[94m"),
            "success": ("[+]", "\033[92m"),
            "warning": ("[!]", "\033[93m"),
            "error": ("[-]", "\033[91m"),
            "scan": ("[~]", "\033[96m"),
            "os_detect": ("[OS]", "\033[95m")
        }
        ind, color = indicators.get(level, ("[*]", "\033[94m"))
        
        if self.console:
            style = {"info": "blue", "success": "green", "warning": "yellow", 
                    "error": "red", "scan": "cyan", "os_detect": "magenta"}.get(level, "white")
            self.console.print(f"[{style}]{ind} {message}[/{style}]")
        else:
            print(f"{color}{ind} {message}\033[0m")
    
    def validate_target(self, ip_str: str) -> Optional[str]:
        try:
            ip = ipaddress.ip_address(ip_str)
            if not ip.is_private:
                self.status(f"WARNING: {ip} is PUBLIC!", "warning")
                if input("Continue only if authorized [y/N]: ").lower() not in ['y', 'yes']:
                    return None
            return str(ip)
        except ValueError:
            self.status(f"Invalid IP: {ip_str}", "error")
            return None
    
    def detect_os_heuristic(self, host: Host) -> str:
        """Multi-factor OS detection when Nmap fails"""
        # Factor 1: Service-based fingerprinting
        win_services = {'smb', 'microsoft-ds', 'msrpc', 'winrm', 'rdp', 'mssql'}
        linux_services = {'ssh', 'nfs', 'rpcbind', 'x11', 'postgresql'}
        
        win_score = sum(1 for s in host.services if s.name in win_services)
        linux_score = sum(1 for s in host.services if s.name in linux_services)
        
        # Factor 2: Port behavior
        if 3389 in host.open_ports or 5985 in host.open_ports:
            win_score += 2
        if 2049 in host.open_ports or 111 in host.open_ports:
            linux_score += 2
            
        # Factor 3: Banner analysis
        for svc in host.services:
            banner_lower = (svc.banner + svc.version).lower()
            if any(x in banner_lower for x in ['windows', 'win32', 'microsoft', 'iis']):
                win_score += 3
            if any(x in banner_lower for x in ['ubuntu', 'debian', 'centos', 'red hat', 'linux']):
                linux_score += 3
        
        if win_score > linux_score:
            return "Windows"
        elif linux_score > win_score:
            return "Linux"
        return "Unknown"
    
    async def nmap_scan(self, target: str) -> Host:
        xml_file = f"/tmp/netweave_{target.replace('.', '_')}_{os.getpid()}.xml"
        if os.path.exists(xml_file):
            os.remove(xml_file)
        
        # Aggressive OS detection added
        cmd = [
            "nmap", "-sV", "-sC", "-O", "--osscan-guess", "-Pn", "--open",
            "-oX", xml_file, "--top-ports", "1000",
            "--max-retries", "1", "--host-timeout", "3m",
            "-T5", target
        ]
        
        self.status("Running OS-Aware Nmap Scan...", "scan")
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE
            )
            try:
                await asyncio.wait_for(proc.communicate(), timeout=180)
            except asyncio.TimeoutError:
                proc.kill()
                self.status("Nmap timed out, using fallback", "warning")
                return await self.fallback_scan(target)
        except FileNotFoundError:
            return await self.fallback_scan(target)
        
        host = Host(ip=target)
        
        if not os.path.exists(xml_file) or os.path.getsize(xml_file) < 100:
            return await self.fallback_scan(target)
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for host_elem in root.findall('host'):
                # OS Detection - Priority 1
                os_elem = host_elem.find('os')
                if os_elem is not None:
                    osmatch = os_elem.find('osmatch')
                    if osmatch is not None:
                        host.os = osmatch.get('name', 'Unknown')
                        host.os_accuracy = int(osmatch.get('accuracy', 0))
                        self.status(f"Nmap OS Detected: {host.os} ({host.os_accuracy}%)", "os_detect")
                
                # Port parsing
                ports_elem = host_elem.find('ports')
                if ports_elem is not None:
                    for port_elem in ports_elem.findall('port'):
                        state_elem = port_elem.find('state')
                        if state_elem is not None and state_elem.get('state') == 'open':
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
                                
                                # Extract OS hints from service banners
                                if not host.os or host.os == "Unknown":
                                    banner = (service.version + service.banner).lower()
                                    if any(w in banner for w in ['windows', 'microsoft', 'iis', 'win32']):
                                        host.os = "Windows"
                                    elif any(l in banner for l in ['ubuntu', 'debian', 'centos', 'redhat', 'linux']):
                                        host.os = "Linux"
                            
                            host.services.append(service)
            
            # Heuristic fallback if Nmap OS detection failed
            if not host.os or host.os == "Unknown":
                host.os = self.detect_os_heuristic(host)
                if host.os != "Unknown":
                    self.status(f"Heuristic OS Detected: {host.os} (service-based)", "os_detect")
                    
        except Exception as e:
            self.status(f"Parse error: {e}", "error")
            host = await self.fallback_scan(target)
        finally:
            try:
                os.remove(xml_file)
            except:
                pass
        
        self.status(f"Scan complete: {len(host.services)} services | OS: {host.os}", "success")
        return host
    
    async def fallback_scan(self, target: str) -> Host:
        self.status("Running async TCP probe...", "scan")
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
            3306: 'mysql', 3389: 'rdp', 5985: 'winrm', 8080: 'http-proxy'
        }
        
        for port in host.open_ports:
            host.services.append(Service(port=port, name=service_map.get(port, 'unknown')))
        
        # OS detection on fallback
        host.os = self.detect_os_heuristic(host)
        self.status(f"Fallback found {len(host.open_ports)} ports | OS: {host.os}", "success")
        return host
    
    async def query_ollama_stable(self, model: str, prompt: str) -> Optional[Dict]:
        """Bulletproof Ollama querying with retries"""
        if not ASYNC_HTTP:
            return None
            
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_predict": 150,  # Reduced for speed
                "stop": ["\n\n", "Human:", "Assistant:"]
            }
        }
        
        for attempt in range(Config.MAX_RETRIES):
            try:
                timeout = aiohttp.ClientTimeout(total=Config.AI_TIMEOUT)
                async with self.session.post(
                    Config.OLLAMA_URL, json=payload, timeout=timeout
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        text = data.get('response', '')
                        
                        # Extract command with regex
                        cmd_match = re.search(r'\[CMD\]\s*(.*?)\s*(?:\[CMD\]|$)', text, re.DOTALL)
                        if cmd_match:
                            return {
                                "model": model,
                                "command": cmd_match.group(1).strip(),
                                "raw": text[:100]
                            }
                        return None
            except asyncio.TimeoutError:
                self.status(f"  {model}: Timeout (attempt {attempt+1})", "warning")
                await asyncio.sleep(0.5)
            except Exception as e:
                self.status(f"  {model}: Error {str(e)[:30]}", "error")
                break
        
        return None
    
    async def council_deliberation(self, host: Host) -> Dict[str, Any]:
        self.status("Council of Wizards convening...", "info")
        
        # Build concise prompt
        svc_summary = "\n".join([
            f"{s.port}:{s.name}:{s.version}" 
            for s in host.services[:5]  # Limit context
        ])
        
        prompt = f"""CTF target {host.ip} OS:{host.os}
Services: {svc_summary}
Suggest ONE command. Format: [CMD]command[CMD]
Example: [CMD]nc -lvnp 4444[CMD]"""
        
        # Check available models
        available = []
        try:
            async with self.session.get(Config.OLLAMA_TAGS_URL, timeout=5) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    available = [m["name"] for m in data.get("models", [])]
        except:
            pass
        
        wizards = {k: v for k, v in Config.COUNCIL.items() if k in available}
        
        if not wizards:
            self.status("No wizards available, using OS-aware patterns", "warning")
            return self._pattern_based_attacks(host)
        
        # Query wizards concurrently with gather (cleaner than ThreadPool)
        tasks = [
            self.query_ollama_stable(model, prompt) 
            for model in wizards.keys()
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        votes = {}
        for (model_name, model_info), result in zip(wizards.items(), results):
            if isinstance(result, Exception) or result is None:
                self.status(f"  ✗ {model_info['role']}: Failed", "error")
                continue
            
            cmd = result["command"]
            self.status(f"  ✓ {model_info['role']}: {cmd[:40]}...", "success")
            
            # Weight by role
            weight = model_info["weight"]
            key = hash(cmd) % 10000
            if key not in votes:
                votes[key] = {"cmd": cmd, "weight": 0, "supporters": []}
            votes[key]["weight"] += weight
            votes[key]["supporters"].append(model_info["role"])
        
        if not votes:
            return self._pattern_based_attacks(host)
        
        winner = max(votes.values(), key=lambda x: x["weight"])
        self.status(f"Primary vector: {winner['cmd'][:50]}...", "success")
        
        return {
            "primary": winner["cmd"],
            "alternatives": [v["cmd"] for v in votes.values() if v["cmd"] != winner["cmd"]][:2],
            "supporters": winner["supporters"]
        }
    
    def _pattern_based_attacks(self, host: Host) -> Dict[str, Any]:
        """OS-aware pattern matching"""
        primary = None
        alternatives = []
        
        # OS-specific logic
        if host.os == "Windows":
            if 445 in [s.port for s in host.services]:
                primary = f"enum4linux -a {host.ip}"
                alternatives.append(f"smbclient -L //{host.ip} -N")
            elif 5985 in [s.port for s in host.services]:
                primary = f"evil-winrm -i {host.ip} -u administrator"
            elif 3389 in [s.port for s in host.services]:
                primary = f"rdesktop {host.ip}"
        else:  # Linux or Unknown
            if any(s.name == 'http' for s in host.services):
                primary = f"gobuster dir -u http://{host.ip}/ -w /usr/share/wordlists/dirb/common.txt -t 50"
            elif any(s.name == 'ssh' for s in host.services):
                primary = f"hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://{host.ip}"
            elif any(s.name == 'ftp' for s in host.services):
                primary = f"hydra -l anonymous -p anonymous ftp://{host.ip}"
        
        if not primary:
            primary = f"nmap -sC -sV -p- {host.ip}"
        
        return {
            "primary": primary,
            "alternatives": alternatives,
            "supporters": ["PatternFallback"]
        }
    
    def save_contract(self, attack_plan: Dict, host: Host):
        """Serialize to Sectumsempra-compatible JSON"""
        contract = {
            "target": host.ip,
            "timestamp": datetime.now().isoformat(),
            "operating_system": host.os,
            "os_confidence": host.os_accuracy,
            "ports": [
                {
                    "port": s.port,
                    "service": s.name,
                    "version": s.version,
                    "notes": s.banner[:50] if s.banner else ""
                }
                for s in host.services
            ],
            "recommended_vector": {
                "vector_name": attack_plan["primary"].split()[0],
                "target_port": host.services[0].port if host.services else 0,
                "vulnerability_type": "Enumeration",
                "technical_summary": attack_plan["primary"]
            },
            "commands": {
                "primary": attack_plan["primary"],
                "alternatives": attack_plan["alternatives"],
                "council": attack_plan.get("supporters", [])
            },
            "metadata": {
                "tool": "NetWeave",
                "version": "9.1",
                "council_size": len(attack_plan.get("supporters", []))
            }
        }
        
        filename = f"netweave_{host.ip.replace('.', '_')}.json"
        with open(filename, 'w') as f:
            json.dump(contract, f, indent=2)
        
        self.status(f"Contract serialized: {filename}", "success")
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
            # Phase 1: Recon with OS detection
            self.status("Phase 1: OS-Aware Reconnaissance", "info")
            self.host = await self.nmap_scan(self.target)
            
            if not self.host.services:
                self.status("No services found", "error")
                return
            
            # Phase 2: Council
            self.status("Phase 2: Council Deliberation", "info")
            plan = await self.council_deliberation(self.host)
            
            # Phase 3: Contract
            self.status("Phase 3: Contract Generation", "info")
            self.save_contract(plan, self.host)
            
            self.status("Pipeline ready for Sectumsempra", "success")
            
        finally:
            if self.session:
                await self.session.close()

def main():
    parser = argparse.ArgumentParser(description='NetWeave v9.1 - OS-Aware Council')
    parser.add_argument('target', help='Target IP')
    parser.add_argument('--no-ai', action='store_true', help='Skip Council')
    args = parser.parse_args()
    
    if args.no_ai:
        Config.COUNCIL = {}
    
    try:
        asyncio.run(NetWeave().run(args.target))
    except KeyboardInterrupt:
        print("\n[!] Cancelled")
        sys.exit(0)

if __name__ == "__main__":
    main()
