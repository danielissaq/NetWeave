# NetWeave v6.5

**NetWeave** is a fast local reconnaissance and security testing framework for CTFs, labs and authorized assessments.

Turn raw reconnaissance into a correlated attack path and a ready execution workflow.

```text
TARGET
  │
  ▼
RECONNAISSANCE
  │
  ▼
CORRELATION
  │
  ▼
ATTACK PATH
  │
  ▼
EXECUTION PAYLOAD
```

NetWeave maps exposed services, collects host and web information, correlates the findings and produces a structured testing workflow instead of a wall of raw reconnaissance output.

## Deployment

Clone the repository:

```bash
git clone https://github.com/danielissaq/NetWeave.git
cd NetWeave
```

Create the Python environment and install the required dependency:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install requests
```

Install Ollama if it is not already installed:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Open a new terminal and start Ollama:

```bash
ollama serve
```

Leave Ollama running.

Return to the NetWeave terminal:

```bash
cd NetWeave
source .venv/bin/activate
ollama pull deepseek-r1:8b
```

Start NetWeave:

```bash
python pwn_recon.py
```

NetWeave connects to the local Ollama service at:

```text
http://127.0.0.1:11434
```

## Generated Payload

NetWeave generates a PowerShell execution payload from the resulting workflow:

```text
fire_payloads_<target>.ps1
```

On Linux with PowerShell 7:

```bash
pwsh ./fire_payloads_<target>.ps1
```

On Windows PowerShell:

```powershell
.\fire_payloads_<target>.ps1
```

Review generated commands before execution.

## Requirements

```text
Python 3.10+
Ollama
DeepSeek R1 8B
PowerShell 7 for generated .ps1 payloads
```

## Legal Notice

NetWeave is intended for CTFs, security research, authorized assessments and isolated laboratory environments.

Only use NetWeave against systems you own or have explicit permission to test.
