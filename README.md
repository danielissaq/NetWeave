# NetWeave Automated Reconnaissance and AI Analysis Utility

## System Overview
NetWeave is a network reconnaissance tool designed for CTF architectures. It automates network infrastructure mapping via Nmap and funnels structured output directly into a local Large Language Model endpoint via Ollama to determine initial entry vectors and operational vulnerabilities.

## Prerequisites and Installation
Ensure the local host is running the Ollama orchestration layer and has the correct model pulled before executing the core script

```bash
pip install requests
ollama pull deepseek-r1:8b
```

## Multi Tab Operational Workflow

### Terminal Tab 1 NetWeave Analysis Execution
Run the script passing the target infrastructure IP address as an argument. The script is configured to allow indefinite processing times to handle heavy CPU operations safely.

```bash
python3 pwn_recon.py TARGET_IP
```

## System Output Log Format
* Initiating Nmap scan against target
* Nmap scan completed successfully
* Forwarding scan data to local AI model for automated analysis
