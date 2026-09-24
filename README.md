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

### 1. Clone NetWeave

```bash
git clone https://github.com/danielissaq/NetWeave.git
cd NetWeave
```

### 2. Set up Python

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install requests
```

### 3. Install PowerShell

NetWeave generates PowerShell execution payloads. On Kali Linux:

```bash
sudo apt update
sudo apt install -y powershell
```

Verify the installation:

```bash
pwsh --version
```

### 4. Install Ollama

If Ollama is not already installed:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Verify the installation:

```bash
ollama --version
```

### 5. Start Ollama

Open a second terminal and run:

```bash
ollama serve
```

Keep this terminal running.

NetWeave uses the local Ollama service at:

```text
http://127.0.0.1:11434
```

### 6. Prepare the model

Return to the first terminal and enter the NetWeave directory:

```bash
cd NetWeave
source .venv/bin/activate
```

Pull the required model:

```bash
ollama pull deepseek-r1:8b
```

Verify that the model is available:

```bash
ollama list
```

You should see:

```text
deepseek-r1:8b
```

### 7. Launch NetWeave

With Ollama still running in the second terminal:

```bash
python pwn_recon.py
```

NetWeave will connect to the local Ollama service and begin the workflow.

## Generated Payload

After the workflow completes, NetWeave generates a PowerShell execution payload:

```text
fire_payloads_<target>.ps1
```

The generated payload is saved in the NetWeave working directory.

### Execute on Linux

PowerShell 7 is already installed during deployment. Run the generated payload with:

```bash
pwsh ./fire_payloads_<target>.ps1
```

### Execute on Windows

Open PowerShell and navigate to the NetWeave directory:

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
PowerShell 7
```

## Legal Notice

NetWeave is intended for CTFs, security research, authorized assessments and isolated laboratory environments.

Only use NetWeave against systems you own or have explicit permission to test.
