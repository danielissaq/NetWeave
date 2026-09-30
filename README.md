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
```
