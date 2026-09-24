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

### 1. Clone and enter NetWeave

```bash
git clone https://github.com/danielissaq/NetWeave.git
cd NetWeave
```

### 2. Create the Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install requests
```

### 3. Install and verify Ollama

If Ollama is not already installed:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Verify the installation:

```bash
ollama --version
```

### 4. Start the local Ollama server

Open a **second terminal** and run:

```bash
ollama serve
```

Keep this terminal open.

The Ollama server should listen on:

```text
http://127.0.0.1:11434
```

### 5. Return to the NetWeave terminal

In the first terminal:

```bash
cd NetWeave
source .venv/bin/activate
```

Pull the required model:

```bash
ollama pull deepseek-r1:8b
```

Verify that it is installed:

```bash
ollama list
```

### 6. Start NetWeave

With Ollama still running in the second terminal, return to the first terminal and run:

```bash
python pwn_recon.py
```

NetWeave will connect to the local Ollama service at:

```text
http://127.0.0.1:11434
```

## Generated Payload

After the reconnaissance workflow completes, NetWeave generates a PowerShell execution payload:

```text
fire_payloads_<target>.ps1
```

The payload is saved in the NetWeave working directory.

### Linux

If PowerShell 7 is installed:

```bash
pwsh ./fire_payloads_<target>.ps1
```

### Windows

Open PowerShell and enter the NetWeave directory:

```powershell
cd C:\path\to\NetWeave
```

Find the generated payload:

```powershell
dir fire_payloads_*.ps1
```

Run the generated payload:

```powershell
.\fire_payloads_<target>.ps1
```

Review generated commands before execution and only use NetWeave against systems you own or have explicit permission to test.

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
