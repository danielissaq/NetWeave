# NetWeave v7.0

NetWeave operates as a local reconnaissance and security testing framework built for CTFs, laboratory environments, and authorized assessments. It transforms raw reconnaissance data into a correlated attack path and a deployable execution workflow.

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
NetWeave maps exposed services, collects host and web information, correlates findings, and produces a structured testing workflow to replace raw output logs.

Deployment
1. Clone NetWeave
Bash
git clone [https://github.com/danielissaq/NetWeave.git](https://github.com/danielissaq/NetWeave.git)
cd NetWeave
2. Prepare Python Environment
Bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install requests
3. Install PowerShell
NetWeave generates PowerShell execution payloads. Run the following on Kali Linux:

Bash
sudo apt update
sudo apt install -y powershell
Verify your installation:

Bash
pwsh --version
4. Install Ollama
If Ollama is missing from your system, install it directly:

Bash
curl -fsSL [https://ollama.com/install.sh](https://ollama.com/install.sh) | sh
Verify your installation:

Bash
ollama --version
5. Start Ollama Service
Open a second terminal tab and execute:

Bash
ollama serve
Keep this terminal active. NetWeave connects to the local Ollama service at http://127.0.0.1:11434.

6. Retrieve the Model
Open a separate terminal tab and pull the required language model:

Bash
ollama pull deepseek-r1:8b
Verify the model is available:

Bash
ollama list
7. Launch NetWeave
With Ollama running in the background, execute the core framework script in your active project environment:

Bash
python pwn_recon.py
Generated Payload
After the workflow completes, NetWeave generates an automated tactical execution payload inside your local working directory:

Plaintext
fire_payloads_<target>.ps1
Execute on Linux
Bash
pwsh ./fire_payloads_<target>.ps1
Execute on Windows
PowerShell
cd C:\path\to\NetWeave
.\fire_payloads_<target>.ps1
Next Tactical Step
Once NetWeave completes its execution loop and isolates the GOLDEN PATH attack vector, proceed directly to your exploitation framework to operationalize the findings. Switch to Sectumsempra v1.0 to compile your reverse shell staging assets and post exploitation scripts tailored to the target environment.

Requirements
Python 3.10 or higher

Ollama (DeepSeek R1 8B)

PowerShell 7

Minimum 8GB RAM recommended for local model execution

Legal Notice
NetWeave is strictly intended for CTFs, security research, authorized assessments, and isolated laboratory environments. Only use NetWeave against systems you own or have explicit permission to test.
