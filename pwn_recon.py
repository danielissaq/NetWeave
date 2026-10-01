#!/usr/bin/env python3
"""
NetWeave v9.0 - Cyan Engine
CTF Reconnaissance & Attack Path Correlation
Optimized for HTB/THM Speedrun 
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
from pathlib import Path
from typing import List, Dict, Optional, Any, Tuple

# Optional imports with graceful degradation
try:
    import aiohttp
    ASYNC_HTTP = True
except ImportError:
    ASYNC_HTTP = False
    print("[!] aiohttp not installed. Install with: pip install aiohttp")

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Configuration
class Config:
    """Environment and runtime configuration"""
    VENICE_API_URL = os.getenv("VENICE_API_URL", "https://api.venice.ai/api/v1/chat/completions")
    VENICE_API_KEY = os.getenv("VENICE_API_KEY", "")
    AI_MODEL = os.getenv("VENICE_MODEL", "default")
    AI_TIMEOUT = int(os.getenv("AI_TIMEOUT", "45"))
    CONCURRENT_SCANS = 50
    TOP_CTF_PORTS = [21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 443, 445, 464, 993, 995, 3306, 3389, 5985]

class Colors:
    """ANSI color codes for terminal output"""
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
    
    @classmethod
    def red(cls, text: str) -> str:
        return f"{cls.RED}{text}{cls.ENDC}"

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
        """Display ASCII banner with cyan styling"""
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
                subtitle="[cyan]v9.0 Cyan Engine - HTB/THM Speedrun Suite[/cyan]",
                border_style="cyan"
            ))
        else:
            print(Colors.cyan(banner_text))
            print(Colors.cyan(">>> NetWeave v9.0 - Cyan Engine - HTB/THM Speedrun Suite <<<\n"))
    
    def status(self, message: str, level: str = "info"):
        """Print status message with appropriate styling"""
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
        """Validate target IP with safety checks"""
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
    
    async def nmap_scan(self, target: str) -> Host:
        """Execute Nmap scan with XML output parsing"""
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
                if proc.returncode != 0 and stderr:
                    self.status(f"Nmap stderr: {stderr.decode().strip()}", "warning")
            except asyncio.TimeoutError:
                proc.kill()
                self.status("Nmap scan timed out, using fallback", "warning")
                return await self.fallback_socket_scan(target)
                
        except FileNotFoundError:
            self.status("Nmap not found in PATH, using fallback scanner", "warning")
            return await self.fallback_socket_scan(target)
        except Exception as e:
            self.status(f"Nmap execution failed: {e}", "error")
            return await self.fallback_socket_scan(target)
        
        host = Host(ip=target)
        
        if not os.path.exists(xml_file) or os.path.getsize(xml_file) < 100:
            self.status("Nmap XML output missing or empty, using fallback", "warning")
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
                                service.banner = svc_elem.get('extrainfo', '')
                            
                            for script in port_elem.findall('script'):
                                script_id = script.get('id')
                                output = script.get('output', '')
                                if script_id and output:
                                    service.scripts[script_id] = output[:500]
                            
                            host.services.append(service)
            
            if not host.services:
                self.status("Nmap found no open ports, validating with fallback", "warning")
                fallback = await self.fallback_socket_scan(target)
                if fallback.open_ports:
                    return fallback
                    
        except ET.ParseError as e:
            self.status(f"XML parsing error: {e}", "error")
            return await self.fallback_socket_scan(target)
        except Exception as e:
            self.status(f"Unexpected error parsing Nmap results: {e}", "error")
            return await self.fallback_socket_scan(target)
        finally:
            try:
                os.remove(xml_file)
            except:
                pass
        
        self.status(f"Nmap scan complete: {len(host.services)} services identified", "success")
        return host
    
    async def fallback_socket_scan(self, target: str) -> Host:
        """Fallback raw socket scanner for top 20 CTF ports"""
        self.status("Initiating fallback TCP socket probe...", "scan")
        
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
            self.status("No open ports detected on fallback scan", "warning")
            return host
        
        self.status(f"Fallback scan found {len(open_ports)} open ports: {open_ports}", "success")
        host.open_ports = open_ports
        
        service_map = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 88: 'kerberos', 110: 'pop3', 111: 'rpcbind',
            135: 'msrpc', 139: 'netbios', 143: 'imap', 443: 'https',
            445: 'smb', 464: 'kpasswd', 993: 'imaps', 995: 'pop3s',
            3306: 'mysql', 3389: 'rdp', 5985: 'winrm'
        }
        
        for port in open_ports:
            svc = Service(
                port=port,
                name=service_map.get(port, 'unknown'),
                state='open'
            )
            host.services.append(svc)
        
        return host
    
    async def query_venice_ai(self, host: Host) -> Dict[str, Any]:
        """Query Venice AI for attack path analysis"""
        if not ASYNC_HTTP or not Config.VENICE_API_KEY:
            self.status("AI analysis skipped - no API access", "warning")
            return self._generate_local_analysis(host)
        
        services_text = "\n".join([
            f"Port {s.port}/{s.protocol}: {s.name} {s.version}"
            for s in host.services
        ])
        
        prompt = f"""Analyze this CTF target and respond ONLY with valid JSON.

Target: {host.ip}
Operating System: {host.os or "Unknown"}
Open Services:
{services_text}

Respond with exactly this JSON structure:
{{
  "target": "{host.ip}",
  "operating_system": "Linux|Windows|Unknown",
  "ports": [
    {{"port": 80, "service": "http", "version": "Apache 2.4.41", "notes": "Potential exploit vector"}}
  ],
  "recommended_vector": {{
    "vector_name": "string",
    "target_port": 80,
    "vulnerability_type": "string",
    "technical_summary": "string"
  }}
}}

Do not include any markdown formatting, explanations, or text outside the JSON object."""

        headers = {
            "Authorization": f"Bearer {Config.VENICE_API_KEY}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": Config.AI_MODEL,
            "messages": [
                {"role": "system", "content": "You are a CTF penetration testing expert. Output only valid JSON."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.2,
            "max_tokens": 800
        }
        
        self.status("Transmitting telemetry to Venice AI...", "scan")
        
        try:
            async with self.session.post(
                Config.VENICE_API_URL,
                headers=headers,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=Config.AI_TIMEOUT)
            ) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    self.status(f"API error {resp.status}: {text[:100]}", "error")
                    return self._generate_local_analysis(host)
                
                data = await resp.json()
                content = data['choices'][0]['message']['content']
                
                json_match = re.search(r'\{.*\}', content, re.DOTALL)
                if json_match:
                    try:
                        result = json.loads(json_match.group(0))
                        self.status("AI analysis received and parsed", "success")
                        return result
                    except json.JSONDecodeError as e:
                        self.status(f"JSON parse error: {e}", "error")
                        return self._generate_local_analysis(host)
                else:
                    self.status("No JSON found in AI response", "warning")
                    return self._generate_local_analysis(host)
                    
        except asyncio.TimeoutError:
            self.status("AI analysis timed out", "warning")
            return self._generate_local_analysis(host)
        except Exception as e:
            self.status(f"AI query failed: {e}", "error")
            return self._generate_local_analysis(host)
    
    def _generate_local_analysis(self, host: Host) -> Dict[str, Any]:
        """Generate analysis locally when AI is unavailable"""
        self.status("Generating local attack pattern analysis...", "info")
        
        ports_data = []
        recommended_port = None
        recommended_service = None
        
        for svc in host.services:
            port_info = {
                "port": svc.port,
                "service": svc.name,
                "version": svc.version,
                "notes": ""
            }
            
            if svc.name == 'http' and not recommended_port:
                port_info["notes"] = "Web application - check for default pages, directory traversal"
                recommended_port = svc.port
                recommended_service = 'http'
            elif svc.name == 'smb' and not recommended_port:
                port_info["notes"] = "SMB service - check for null sessions, anonymous shares"
                recommended_port = svc.port
                recommended_service = 'smb'
            elif svc.name == 'ssh' and not recommended_port:
                port_info["notes"] = "SSH service - check for weak credentials, outdated versions"
                recommended_port = svc.port
                recommended_service = 'ssh'
            elif svc.name == 'ftp' and not recommended_port:
                port_info["notes"] = "FTP service - check for anonymous access"
                recommended_port = svc.port
                recommended_service = 'ftp'
            
            ports_data.append(port_info)
        
        if not recommended_port and host.open_ports:
            recommended_port = host.open_ports[0]
            recommended_service = host.services[0].name if host.services else "unknown"
        
        os_guess = "Unknown"
        if any(s.name in ['smb', 'winrm', 'rdp', 'msrpc'] for s in host.services):
            os_guess = "Windows"
        elif any(s.name in ['ssh', 'nfs', 'rpcbind'] for s in host.services):
            os_guess = "Linux"
        
        return {
            "target": host.ip,
            "operating_system": os_guess,
            "ports": ports_data,
            "recommended_vector": {
                "vector_name": f"{recommended_service.upper()}_Initial_Access" if recommended_service else "Unknown",
                "target_port": recommended_port or 0,
                "vulnerability_type": "Configuration/Enumeration",
                "technical_summary": f"Initial foothold via {recommended_service} service enumeration and credential testing" if recommended_service else "Manual enumeration required"
            }
        }
    
    async def save_results(self, data: Dict[str, Any]):
        """Save structured JSON to disk"""
        filename = f"netweave_{self.target.replace('.', '_')}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
            self.status(f"Attack vector data serialized: {filename}", "success")
            
            if self.console:
                self.console.print(f"\n[bold cyan]Target:[/bold cyan] {data['target']}")
                self.console.print(f"[bold cyan]OS:[/bold cyan] {data['operating_system']}")
                self.console.print(f"[bold cyan]Primary Vector:[/bold cyan] {data['recommended_vector']['vector_name']} on port {data['recommended_vector']['target_port']}")
            else:
                print(f"\n{Colors.cyan('Target:')} {data['target']}")
                print(f"{Colors.cyan('OS:')} {data['operating_system']}")
                print(f"{Colors.cyan('Primary Vector:')} {data['recommended_vector']['vector_name']} on port {data['recommended_vector']['target_port']}")
                
        except Exception as e:
            self.status(f"Failed to save results: {e}", "error")
            print(json.dumps(data, indent=2))
    
    async def run(self, target: str):
        """Main execution pipeline"""
        self.banner()
        
        validated = self.validate_target(target)
        if not validated:
            sys.exit(1)
        self.target = validated
        
        self.status(f"Target acquired: {self.target}", "info")
        
        if ASYNC_HTTP:
            self.session = aiohttp.ClientSession()
        
        try:
            self.status("Phase 1: Network Reconnaissance", "info")
            self.host = await self.nmap_scan(self.target)
            
            if not self.host.services:
                self.status("No services discovered - target may be filtered", "warning")
                return
            
            web_count = len([s for s in self.host.services if s.name in ['http', 'https']])
            self.status(f"Web Targets Isolated: {web_count}", "info")
            
            self.status("Phase 2: Attack Vector Correlation", "info")
            analysis = await self.query_venice_ai(self.host)
            
            self.status("Phase 3: Data Packaging", "info")
            await self.save_results(analysis)
            
            self.status("Reconnaissance complete - data ready for Sectumsempra", "success")
            
        finally:
            if self.session:
                await self.session.close()

def main():
    parser = argparse.ArgumentParser(
        description='NetWeave v9.0 - Cyan Engine - CTF Reconnaissance Suite',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment Variables:
  VENICE_API_KEY    - API key for Venice AI integration
  VENICE_API_URL    - Venice API endpoint (default: https://api.venice.ai/api/v1/chat/completions)
  VENICE_MODEL      - Model to use (default: default)
        """
    )
    parser.add_argument('target', help='Target IP address')
    parser.add_argument('--no-ai', action='store_true', help='Skip AI analysis, use local heuristics only')
    args = parser.parse_args()
    
    if args.no_ai:
        os.environ['VENICE_API_KEY'] = ''
    
    try:
        asyncio.run(NetWeave().run(args.target))
    except KeyboardInterrupt:
        print(f"\n{Colors.yellow('[!] Operation cancelled by user')}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.red(f'[-] Fatal error: {e}')}")
        sys.exit(1)

if __name__ == "__main__":
    main()
