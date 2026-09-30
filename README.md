# NetWeave v8.1 - Council of Wizards Edition

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

---

## 📦 Key Features v8.1

* **Council of Wizards:** Multiple AI models vote on the best attack vector.
* **Multi-Format Payloads:** Generates PowerShell (`.ps1`), Bash (`.sh`), Python (`.py`), and JSON summaries.
* **Intelligent Fallbacks:** Built-in attack patterns when AI models are unavailable.
* **Web Scanning:** Automated Gobuster and Nikto framework integration.
* **Parallel Processing:** Concurrent AI model queries to optimize speed.
* **Enhanced Error Handling:** Improved logging mechanisms and clearer error messages.
* **Security Checks:** Features built to ensure secure and compliant platform usage.
* **Comprehensive Documentation:** Detailed environment setup guides and command examples.

---

## 🛠️ Tech Stack & Requirements

### System Requirements
* **OS:** Linux / macOS (Windows supported for payload execution)
* **Python Version:** Python 3.10+
* **Hardware:** 8GB+ RAM recommended for hosting local AI models

### Dependencies
* **Core Framework:** Ollama
* **Reconnaissance Tools:** Nmap, Gobuster, Nikto
* **Execution Environment:** PowerShell 7 (Optional, for `.ps1` execution on Linux)

---

## 🚀 Deployment

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
NetWeave generates PowerShell execution payloads among other formats. To execute `.ps1` files natively on Linux:
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
The Council supports multiple models. Pull one or more depending on your configuration:
```bash
# Recommended - Fast and accurate for CTFs
ollama pull qwen2.5-coder:7b

# Alternatives
ollama pull deepseek-r1:8b
ollama pull llama3.2
ollama pull mistral
```
**Verify your local models:**
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
**Dry run (generate scripts without execution markers):**
```bash
python3 pwn_recon.py -t 192.168.1.100 --dry-run
```

---

## 📂 Generated Payloads

After execution completes, NetWeave generates multiple targeted scripts inside your directory:

* `netweave_<target>_<timestamp>.ps1` — PowerShell Execution Script
* `netweave_<target>_<timestamp>.sh` — Bash Execution Script
* `netweave_<target>_<timestamp>_exec.py` — Python Execution Script
* `netweave_<target>_<timestamp>.json` — Attack Summary & Command Metrics

### Executing Payloads

#### Linux/macOS
```bash
# Bash
chmod +x netweave_*.sh
./netweave_192_168_1_100_20250115_143022.sh

# Python
python3 netweave_*_exec.py

# PowerShell
pwsh ./netweave_*.ps1
```

#### Windows
```powershell
.\netweave_192_168_1_100_20250115_143022.ps1
```

---

## 🧙‍♂️ The Council of Wizards

Models vote on attack commands; a higher combination of assigned weight and confidence score generates a stronger strategic vote.

| Model | Role | Weight | Timeout | Best For |
| :--- | :--- | :--- | :--- | :--- |
| **qwen2.5-coder:7b** | Battle Mage | 3 | 60s | Fast command generation |
| **deepseek-r1:8b** | Archivist | 3 | 180s | Deep tactical reasoning |
| **llama3.2** | Scout | 2 | 30s | Rapid fallback execution |
| **mistral** | Duelist | 2 | 45s | Balanced performance metrics |

---

## ⚙️ Command Line Options

```text
python3 pwn_recon.py [-h] [-t TARGET] [--dry-run] [--resume]
```

* `-h, --help` — Show the framework help message
* `-t, --target` — Target IP address (optional, will prompt interactive mode if omitted)
* `--dry-run` — Generate output scripts without execution markers
* `--resume` — Resume from a previous scan session *(Note: not fully implemented)*

---

## 🛡️ Attack Pattern Fallbacks

If AI models are entirely unavailable or hit a timeout constraint, NetWeave uses hardcoded, built-in fallback patterns:

| Service | Default Action |
| :--- | :--- |
| **HTTP** | Gobuster directory scan |
| **SSH** | Hydra brute force testing |
| **FTP** | Anonymous login vulnerability test |
| **SMB** | enum4linux infrastructure enumeration |

---

## 📝 Next Tactical Step

Once NetWeave completes processing and isolates the **PRIMARY ATTACK VECTOR**, proceed directly to your exploitation framework. The generated JSON summary contains the complete ranked, voted commands for manual review or secondary pipeline automation.

---

## 🔍 Troubleshooting

**Error:** `"No module named 'requests'"`
```bash
pip3 install requests
```

**Error:** `"Ollama not running"`
```bash
# Terminal 1 - Restart the engine
ollama serve

# Terminal 2 - Verify active tags connection
curl http://localhost:11434/api/tags
```

**Issue:** `Nmap XML parse fails`
* *Behavior:* NetWeave automatically catches this error and falls back to a clean TCP connect scan across common ports.

---

## ⚖️ Legal Notice

NetWeave is strictly intended for CTFs, security research, authorized assessments, and isolated laboratory environments. Only use NetWeave against systems you own or have explicit, written permission to test. Unauthorized access to computer networks and infrastructure is illegal.
