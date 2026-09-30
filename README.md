# NetWeave v8.0 - Council of Wizards Edition

**NetWeave** operates as a local reconnaissance and security testing framework built for CTFs, laboratory environments, and authorized assessments. It transforms raw reconnaissance data into a correlated attack path and a deployable execution workflow using an AI-powered "Council of Wizards" for intelligent decision making.

```text
TARGET
  │
  ▼
RECONNAISSANCE (Nmap + Web Scan)
  │
  ▼
COUNCIL DELIBERATION (AI Analysis)
  │
  ▼
ATTACK PATH (Voted Commands)
  │
  ▼
EXECUTION PAYLOADS (Multi-format)
```

NetWeave maps exposed services, collects host and web information, correlates findings through multiple AI models, and produces structured testing workflows in PowerShell, Bash, and Python formats.

## Key Features v8.0

* **Council of Wizards:** Multiple AI models vote on the best attack vector
* **Multi-Format Payloads:** Generates PowerShell (`.ps1`), Bash (`.sh`), Python (`.py`), and JSON summary
* **Intelligent Fallbacks:** Built-in attack patterns when AI is unavailable
* **Web Scanning:** Automated Gobuster and Nikto integration
* **Parallel Processing:** Concurrent AI model queries for speed

## Deployment

### 1. Clone NetWeave
```bash
git clone https://github.com/danielissaq/NetWeave.git
cd NetWeave
```

### 2. Prepare Python Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install requests
```

### 3. Install PowerShell (Optional)
NetWeave generates PowerShell execution payloads among other formats. To execute `.ps1` files on Linux:

```bash
sudo apt update
sudo apt install -y powershell
pwsh --version
```

### 4. Install Ollama
```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama --version
```

### 5. Start Ollama Service
**Terminal 1:**
```bash
ollama serve
```

### 6. Retrieve Models
The Council supports multiple models. Pull one or more:

```bash
# Recommended - Fast and accurate for CTFs
ollama pull qwen2.5-coder:7b

# Alternatives
ollama pull deepseek-r1:8b
ollama pull llama3.2
ollama pull mistral
```

**Verify models:**
```bash
ollama list
```

### 7. Launch NetWeave
**Interactive mode:**
```bash
python3 pwn_recon.py
```

**With target specified:**
```bash
python3 pwn_recon.py -t 192.168.1.100
```

**Dry run (generate scripts without execution):**
```bash
python3 pwn_recon.py -t 192.168.1.100 --dry-run
```

## Generated Payloads
After completion, NetWeave generates multiple execution scripts:

```text
netweave_<target>_<timestamp>.ps1     # PowerShell
netweave_<target>_<timestamp>.sh      # Bash
netweave_<target>_<timestamp>_exec.py # Python
netweave_<target>_<timestamp>.json    # Summary
```

## Execute Payloads

### Linux/macOS
```bash
# Bash
chmod +x netweave_*.sh
./netweave_192_168_1_100_20250115_143022.sh

# Python
python3 netweave_*_exec.py

# PowerShell
pwsh ./netweave_*.ps1
```

### Windows
```powershell
.\netweave_192_168_1_100_20250115_143022.ps1
```

## The Council of Wizards

| Model | Role | Weight | Timeout | Best For |
| :--- | :--- | :---: | :---: | :--- |
| **qwen2.5-coder:7b** | Battle Mage | 3 | 60s | Fast command generation |
| **deepseek-r1:8b** | Archivist | 3 | 180s | Deep reasoning |
| **llama3.2** | Scout | 2 | 30s | Rapid fallback |
| **mistral** | Duelist | 2 | 45s | Balanced performance |

Models vote on attack commands; higher weight + confidence = stronger vote.

## Command Line Options
```bash
python3 pwn_recon.py [-h] [-t TARGET] [--dry-run] [--resume]

Options:
  -h, --help            Show help message
  -t, --target          Target IP address (optional, will prompt if omitted)
  --dry-run             Generate scripts without execution markers
  --resume              Resume from previous session (not fully implemented)
```

## Attack Pattern Fallbacks
If AI models are unavailable, NetWeave uses built-in patterns:

| Service | Default Action |
| :--- | :--- |
| **HTTP** | Gobuster directory scan |
| **SSH** | Hydra brute force |
| **FTP** | Anonymous login test |
| **SMB** | enum4linux enumeration |

## Next Tactical Step
Once NetWeave completes and isolates the **PRIMARY ATTACK VECTOR**, proceed to your exploitation framework. The JSON summary contains the voted commands for manual execution or automation.

## Requirements
* Python 3.10+
* Ollama (any model from The Council)
* Nmap
* Gobuster (for web scanning)
* Nikto (for web vulnerability scanning)
* PowerShell 7 (optional, for `.ps1` execution)
* 8GB+ RAM recommended for local AI models

## Troubleshooting

**"No module named 'requests'"**
```bash
pip3 install requests
```

**"Ollama not running"**
```bash
# Terminal 1
ollama serve

# Terminal 2 - verify
curl http://localhost:11434/api/tags
```

**Nmap XML parse fails**
NetWeave automatically falls back to TCP connect scan on common ports.

## Legal Notice
NetWeave is strictly intended for CTFs, security research, authorized assessments, and isolated laboratory environments. Only use NetWeave against systems you own or have explicit permission to test. Unauthorized access to computer systems is illegal.
