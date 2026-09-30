# NetWeave v7.0

**NetWeave** is a fast local reconnaissance and security testing framework for CTFs, labs, and authorized assessments. 

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

NetWeave maps exposed services, collects host and web information, correlates the findings, and produces a structured testing workflow instead of a wall of raw reconnaissance output.

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
Open a second terminal tab and run:
```bash
ollama serve
```
Keep this terminal running. NetWeave uses the local Ollama service at `http://127.0.0.1:11434`.

### 6. Prepare the Model
Open a separate terminal tab and pull the required model:
```bash
ollama pull deepseek-r1:8b
```

Verify that the model is available:
```bash
ollama list
```

### 7. Launch NetWeave
With Ollama still running in the background, run the core framework script in your active project environment tab:
```bash
python pwn_recon.py
```

## Generated Payload
After the workflow completes, NetWeave generates an automated tactical execution payload inside your local working directory:
```text
fire_payloads_<target>.ps1
```

### Execute on Linux
```bash
pwsh ./fire_payloads_<target>.ps1
```

### Execute on Windows
```powershell
cd C:\path\to\NetWeave
.\fire_payloads_<target>.ps1
```

## Next Tactical Step: Attacking the Target
Once NetWeave completes its execution loop and isolates the **GOLDEN PATH** attack vector, do not leave your terminal idle. Proceed directly to your exploitation framework to weaponize these findings:
* Switch directly over to **Sectumsempra v1.0** to instantly compile your reverse shell staging assets and post-exploitation scripts tailored to this target environment.

## Requirements
```text
Python 3.10+
Ollama (DeepSeek R1 8B)
PowerShell 7
```

## Legal Notice
NetWeave is intended for CTFs, security research, authorized assessments, and isolated laboratory environments. Only use NetWeave against systems you own or have explicit permission to test.
