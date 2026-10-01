#!/usr/bin/env python3
"""
NetWeave v9.0 - Cyan Engine (Council of Wizards Edition)
High-Performance Offline CTF Reconnaissance & Attack Path Correlation
Optimized for HTB/THM Air-Gapped Environments
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
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import aiohttp
    ASYNC_HTTP = True
except ImportError:
    ASYNC_HTTP = False

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Configuration
class Config:
    OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
    OLLAMA_TAGS_URL = os.getenv("OLLAMA_TAGS_URL", "http://localhost:11434/api/tags")
    AI_TIMEOUT = int(os.getenv("AI_TIMEOUT", "90"))
    CONCURRENT_SCANS = 50
    TOP_CTF_PORTS = [21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 443, 445, 464, 993, 995, 3306, 3389, 5985, 8080, 8443]
    
    COUNCIL = {
        "qwen2.5-coder:7b": {"role": "Battle Mage", "weight": 3},
        "deepseek-r1:8b": {"role": "Archivist", "weight": 3},
        "llama3.2": {"role": "Scout", "weight": 2},
        "mistral": {"role": "Duelist", "weight": 2},
    }

class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    ENDC = '\033[0m'
    
    @classmethod
    def cyan(cls, text: str) -> str:
        return f"{cls.CYAN}{text}{cls.ENDC}"
    
    @classmethod
    def green(cls, text: str) -> str:
        return f"{cls.GREEN}{text}{cls.ENDC}"
    
    @classmethod
    def yellow(cls, text: str) -> str:
        return f"{cls.YELLOW}{text}{cls.ENDC}"

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
            self.console.print(Panel(
                Text(banner_text, style="bold cyan"),
                subtitle="[cyan]v9.0 Cyan Engine - Council of Wizards[/cyan]",
                border_style="cyan"
            ))
        else:
            print(Colors.cyan(banner_text))
            print(Colors.cyan(">>> NetWeave v9.0 - Cyan Engine - Council of Wizards <<<\n"))
    
    def status(self, message: str, level: str = "info"):
        indicators = {
            "info": ("[*]", Colors.BLUE),
            "success": ("[+]", Colors.GREEN),
            "warning": ("[!]", Colors.YELLOW),
            "error": ("[-]", Colors.RED),
            "scan": ("[~]", Colors.CYAN)
        }
        indicator, color = indicators.get(level, ("[*]", Colors.BLUE))
        
        if self.console:
            style = {"info": "blue", "success": "green", "warning": "yellow", "error": "red", "scan": "cyan"}.get(level, "white")
            self.console.print(f"[{style}]{indicator} {message}[/{style}]")
        else:
            print(f"{color}{indicator} {message}{Colors.ENDC}")
    
    def validate_target(self, ip_str: str) -> Optional[str]:
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.is_loopback:
                self.status("Loopback address detected", "warning")
                return str(ip)
            if not ip.is_private:
                self.status(f"WARNING: {ip} is a PUBLIC IP!", "warning")
                if input("Continue only if authorized [y/N]: ").lower() not in ['y', 'yes']:
                    return None
            return str(ip)
        except ValueError:
            self.status(f"Invalid IP address: {ip_str}", "error")
            return None
    
    async def check_ollama(self) -> bool:
        if not ASYNC_HTTP:
            return False
        try:
            async with self.session.get(Config.OLLAMA_TAGS_URL, timeout=5) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    models = [m["name"] for m in data.get("models", [])]
                    if models:
                        self.status(f"Council ready with {len(models)} wizards", "success")
                        return True
                    else:
                        self.status("No local models found. Run: ollama pull qwen2.5-coder:7b", "warning")
                        return False
                return False
        except Exception as e:
            self.status(f"Ollama not responding: {e}", "warning")
            return False
    
    async def nmap_scan(self, target: str) -> Host:
        xml_file = f"/tmp/netweave_{target.replace('.', '_')}_{os.getpid()}.xml"
        
        if os.path.exists(xml_file):
            os.remove(xml_file)
        
        cmd = [
            "nmap", "-sV", "-sC", "-Pn", "--open", 
            "-oX", xml_file, "--top-ports", "1000",
            "--max-retries", "2", "--host-timeout", "5m",
            "-T4", target
        ]
        
        self.status("Running Nmap Connect Scan...", "scan")
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                _, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            except asyncio.TimeoutError:
                proc.kill()
                self.status("Nmap timed out, using fallback", "warning")
                return await self.fallback_socket_scan(target)
                
        except FileNotFoundError:
            self.status("Nmap not found, using fallback scanner", "warning")
            return await self.fallback_socket_scan(target)
        except Exception as e:
            self.status(f"Nmap failed: {e}", "error")
            return await self.fallback_socket_scan(target)
        
        host = Host(ip=target)
        
        if not os.path.exists(xml_file) or os.path.getsize(xml_file) < 100:
            return await self.fallback_socket_scan(target)
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for host_elem in root.findall('host'):
                hostnames = host_elem.find('hostnames')
                if hostnames is not None:
                    for name in hostnames.findall('hostname'):
                        if name.get('name'):
                            host.hostname = name.get('name')
                            break
                
                os_elem = host_elem.find('os')
                if os_elem is not None:
                    osmatch = os_elem.find('osmatch')
                    if osmatch is not None:
                        host.os = osmatch.get('name', 'Unknown')[:50]
                
                ports_elem = host_elem.find('ports')
                if ports_elem is not None:
                    for port_elem in ports_elem.findall('port'):
                        state_elem = port_elem.find('state')
                        if state_elem is not None and state_elem.get('state') == 'open':
                            port_num = int(port_elem.get('portid'))
                            host.open_ports.append(port_num)
                            
                            service = Service(port=port_num)
                            service.protocol = port_elem.get('protocol', 'tcp')
                            
                            svc_elem = port_elem.find('service')
                            if svc_elem is not None:
                                service.name = svc_elem.get('name', 'unknown')
                                product = svc_elem.get('product', '')
                                version = svc_elem.get('version', '')
                                service.version = f"{product} {version}".strip()
                                service.cpe = svc_elem.get('cpe', '')
                            
                            for script in port_elem.findall('script'):
                                script_id = script.get('id')
                                output = script.get('output', '')
                                if script_id and output:
                                    service.scripts[script_id] = output[:500]
                            
                            host.services.append(service)
            
            if not host.services:
                fallback = await self.fallback_socket_scan(target)
                if fallback.open_ports:
                    return fallback
                    
        except Exception as e:
            self.status(f"XML parse error: {e}", "error")
            return await self.fallback_socket_scan(target)
        finally:
            try:
                os.remove(xml_file)
            except:
                pass
        
        self.status(f"Nmap complete: {len(host.services)} services", "success")
        return host
    
    async def fallback_socket_scan(self, target: str) -> Host:
        self.status("Initiating fallback TCP probe...", "scan")
        
        host = Host(ip=target)
        open_ports = []
        
        semaphore = asyncio.Semaphore(Config.CONCURRENT_SCANS)
        
        async def probe_port(port: int) -> Optional[int]:
            async with semaphore:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(target, port),
                        timeout=2.0
                    )
                    writer.close()
                    await writer.wait_closed()
                    return port
                except:
                    return None
        
        tasks = [probe_port(p) for p in Config.TOP_CTF_PORTS]
        results = await asyncio.gather(*tasks)
        open_ports = sorted([p for p in results if p is not None])
        
        if not open_ports:
            self.status("No open ports found", "warning")
            return host
        
        self.status(f"Fallback found {len(open_ports)} ports: {open_ports}", "success")
        host.open_ports = open_ports
        
        service_map = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 88: 'kerberos', 110: 'pop3', 111: 'rpcbind',
            135: 'msrpc', 139: 'netbios', 143: 'imap', 443: 'https',
            445: 'smb', 464: 'kpasswd', 993: 'imaps', 995: 'pop3s',
            3306: 'mysql', 3389: 'rdp', 5985: 'winrm', 8080: 'http-proxy', 8443: 'https-alt'
        }
        
        for port in open_ports:
            svc = Service(port=port, name=service_map.get(port, 'unknown'), state='open')
            host.services.append(svc)
        
        return host
    
    async def summon_wizard(self, model: str, scan_summary: str) -> Optional[Dict]:
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
            "options": {"temperature": 0.3, "num_predict": 256}
        }
        
        try:
            async with self.session.post(
                Config.OLLAMA_URL,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=Config.AI_TIMEOUT)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    text = data.get('response', '')
                    
                    cmd_match = re.search(r'\[CMD\]\s*(.*?)\s*\[CMD\]', text, re.DOTALL)
                    cmd = cmd_match.group(1).strip() if cmd_match else None
                    
                    conf_match = re.search(r'CONFIDENCE:\s*(High|Medium|Low)', text, re.I)
                    conf = conf_match.group(1).lower() if conf_match else "medium"
                    
                    vuln_match = re.search(r'VULN:\s*(.+?)(?:\n|$)', text, re.I)
                    vuln = vuln_match.group(1).strip() if vuln_match else "Unknown"
                    
                    if cmd and len(cmd) > 5:
                        return {
                            "model": model,
                            "command": cmd,
                            "vuln": vuln,
                            "confidence": conf,
                            "raw": text[:200]
                        }
        except asyncio.TimeoutError:
            self.status(f"  ⚠ {model}: Timed out", "warning")
        except Exception as e:
            self.status(f"  ⚠ {model}: Failed", "warning")
        
        return None
    
    async def council_deliberation(self, host: Host) -> Tuple[str, List[str]]:
        self.status("The Council of Wizards convenes...", "info")
        
        summary = f"Target: {host.ip}\nOpen Ports: {', '.join(map(str, host.open_ports))}\n\n"
        for svc in host.services:
            summary += f"Port {svc.port}/{svc.protocol}: {svc.name} {svc.version}\n"
            if svc.scripts:
                summary += f"  Scripts: {list(svc.scripts.keys())[:3]}\n"
        
        available_models = []
        try:
            async with self.session.get(Config.OLLAMA_TAGS_URL, timeout=5) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    available_models = [m["name"] for m in data.get("models", [])]
        except:
            pass
        
        wizards = {k: v for k, v in Config.COUNCIL.items() if k in available_models}
        
        if not wizards:
            self.status("No wizards available, using pattern fallback", "warning")
            return self._pattern_based_attacks(host)
        
        self.status(f"Summoning {len(wizards)} wizards...", "scan")
        
        responses = []
        with ThreadPoolExecutor(max_workers=len(wizards)) as executor:
            future_to_model = {
                executor.submit(asyncio.run, self.summon_wizard(model, summary)): (model, info)
                for model, info in wizards.items()
            }
            
            for future in as_completed(future_to_model):
                model, info = future_to_model[future]
                try:
                    result = future.result()
                    if result:
                        result["role"] = info["role"]
                        result["weight"] = info["weight"]
                        responses.append(result)
                        self.status(f"  ✓ {info['role']}: {result['vuln']} [{result['confidence']}]", "success")
                    else:
                        self.status(f"  ⚠ {info['role']}: No response", "warning")
                except:
                    self.status(f"  ✗ {info['role']}: Failed", "error")
        
        if not responses:
            return self._pattern_based_attacks(host)
        
        command_votes = {}
        for r in responses:
            cmd = r["command"]
            norm_cmd = re.sub(r'\s+', ' ', cmd.lower().strip())
            tool = norm_cmd.split()[0] if norm_cmd else "unknown"
            key = f"{tool}:{hash(norm_cmd) % 10000}"
            
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
        
        sorted_cmds = sorted(command_votes.values(), key=lambda x: x["weight"], reverse=True)
        
        self.status("Deliberation Results:", "info")
        for i, opt in enumerate(sorted_cmds[:3], 1):
            medal = ["🥇", "🥈", "🥉"][i-1]
            self.status(f"{medal} Rank {i}: {opt['vulns'][0]} (weight: {opt['weight']})", "success")
            self.status(f"    Command: {opt['command'][:60]}...", "info")
        
        primary = sorted_cmds[0]["command"] if sorted_cmds else f"nmap -sC -sV {host.ip}"
        alternatives = [c["command"] for c in sorted_cmds[1:3]] if len(sorted_cmds) > 1 else []
        
        self.status(f"Primary vector selected", "success")
        return primary, alternatives
    
    def _pattern_based_attacks(self, host: Host) -> Tuple[str, List[str]]:
        self.status("Using built-in attack patterns", "info")
        commands = []
        
        for svc in host.services:
            if svc.name == "http":
                commands.append(f"gobuster dir -u http://{host.ip}:{svc.port}/ -w /usr/share/wordlists/dirb/common.txt -t 50")
            elif svc.name == "https":
                commands.append(f"gobuster dir -u https://{host.ip}:{svc.port}/ -w /usr/share/wordlists/dirb/common.txt -t 50 -k")
            elif svc.name == "ssh":
                commands.append(f"hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://{host.ip}")
            elif svc.name == "ftp":
                commands.append(f"hydra -l anonymous -p anonymous ftp://{host.ip}")
            elif svc.name == "smb":
                commands.append(f"enum4linux -a {host.ip}")
        
        if not commands:
            commands = [f"nmap -sC -sV -p- {host.ip}"]
        
        return commands[0], commands[1:3]
    
    def generate_output(self, primary: str, alternatives: List[str], target: str):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = f"netweave_{target.replace('.', '_')}"
        
        data = {
            "target": target,
            "timestamp": timestamp,
            "operating_system": self.host.os if self.host else "Unknown",
            "ports": [
                {"port": s.port, "service": s.name, "version": s.version, 
                 "notes": f"Scripts: {list(s.scripts.keys())}" if s.scripts else ""}
                for s in (self.host.services if self.host else [])
            ],
            "recommended_vector": {
                "vector_name": primary.split()[0] if primary else "unknown",
                "target_port": self.host.services[0].port if (self.host and self.host.services) else 0,
                "vulnerability_type": "Enumeration",
                "technical_summary": f"Primary: {primary}. Alternatives: {len(alternatives)}"
            },
            "commands": {
                "primary": primary,
                "alternatives": alternatives
            }
        }
        
        filename = f"{base}.json"
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        self.status(f"Contract serialized: {filename}", "success")
        
        # Also generate bash script for immediate use
        sh_file = f"{base}.sh"
        with open(sh_file, 'w') as f:
            f.write(f"#!/bin/bash\n# NetWeave Execution Payload\n# Target: {target}\n\n")
            f.write(f"echo '[*] Executing primary vector...'\n")
            f.write(f"{primary}\n")
            for alt in alternatives:
                f.write(f"\necho '[*] Alternative: {alt}'\n")
                f.write(f"{alt}\n")
            f.write("echo '[+] Complete'\n")
        os.chmod(sh_file, 0o755)
        self.status(f"Script generated: {sh_file}", "success")
        
        return filename, sh_file
    
    async def run(self, target: str):
        self.banner()
        
        validated = self.validate_target(target)
        if not validated:
            sys.exit(1)
        self.target = validated
        
        self.status(f"Target acquired: {self.target}", "info")
        
        if ASYNC_HTTP:
            self.session = aiohttp.ClientSession()
        
        try:
            ollama_ready = await self.check_ollama()
            
            self.status("Phase 1: Network Reconnaissance", "info")
            self.host = await self.nmap_scan(self.target)
            
            if not self.host.services:
                self.status("No services discovered", "warning")
                return
            
            web_count = len([s for s in self.host.services if s.name in ['http', 'https']])
            self.status(f"Web Targets Isolated: {web_count}", "info")
            
            self.status("Phase 2: Council Deliberation", "info")
            if ollama_ready:
                primary, alternatives = await self.council_deliberation(self.host)
            else:
                primary, alternatives = self._pattern_based_attacks(self.host)
            
            self.status("Phase 3: Data Packaging", "info")
            await asyncio.to_thread(self.generate_output, primary, alternatives, self.target)
            
            self.status("Reconnaissance complete - data ready for Sectumsempra", "success")
            
        finally:
            if self.session:
                await self.session.close()

def main():
    parser = argparse.ArgumentParser(description='NetWeave v9.0 - Cyan Engine - Council of Wizards')
    parser.add_argument('target', help='Target IP address')
    parser.add_argument('--no-ai', action='store_true', help='Skip AI, use pattern matching only')
    args = parser.parse_args()
    
    if args.no_ai:
        Config.COUNCIL = {}
    
    try:
        asyncio.run(NetWeave().run(args.target))
    except KeyboardInterrupt:
        print(f"\n{Colors.yellow('[!] Cancelled')}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.red(f'[-] Fatal: {e}')}")
        sys.exit(1)

if __name__ == "__main__":
    main()
