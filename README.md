# The 3/3 CTF Speedrun Suite

**A high performance, fully offline, automated penetration testing pipeline for HackTheBox (HTB) and TryHackMe (THM).**

```text
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   <TARGET_IP>   │────▶│    NetWeave      │────▶│  Sectumsempra   │
│                 │     │    v9.2 Cyan     │     │   v1.2 Green    │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                              │                            │
                    ┌─────────┴──────────┐                 │
                    ▼                    ▼                 ▼
            ┌──────────────┐    ┌──────────────┐   ┌─────────────────┐
            │   Nmap/OS    │    │  Ollama AI   │   │   Morsmordre    │
            │  Detection   │    │   Council    │   │    v1.0 Red     │
            └──────────────┘    └──────────────┘   │   Autonomous    │
                                                   │   Enumeration   │
                                                   └─────────────────┘
```

**Core Principle:** Zero cloud dependencies. 100% local Ollama inference. Seamless stdin/stdout bridging between tools.

---

## 📦 The Three Engines

| Tool | Color | Function | Input | Output |
|------|-------|----------|-------|--------|
| **NetWeave** | Cyan | OS-aware reconnaissance & AI correlation | `<TARGET_IP>` | `netweave_<TARGET>.json` |
| **Sectumsempra** | Green | Payload generation, listener, handoff | `netweave_<TARGET>.json` | Active socket bridge |
| **Morsmordre** | Red | Autonomous post-exploitation enumeration | Socket via stdin/stdout | `morsmordre_<TARGET>_<TIME>.json` |

---

## 🚀 Quick Start

### 1. Install Dependencies

```bash
# System dependencies
sudo apt update
sudo apt install -y nmap python3-pip

# Python dependencies (System-wide for Kali to bypass PEP 668)
sudo apt install -y python3-aiohttp python3-rich python3-netifaces

# Install Ollama (local AI)
curl -fsSL https://ollama.com/install.sh | sh

# Pull Council Models
ollama pull qwen2.5-coder:7b
ollama pull llama3.2
ollama pull mistral
```

### 2. Start the Pipeline

**Terminal 1 - Start AI Engine:**
```bash
ollama serve
```

**Terminal 2 - Run Reconnaissance:**
```bash
python3 netweave.py <TARGET_IP>
```

**Terminal 3 - Execute & Listen:**
```bash
python3 sectumsempra.py
# Displays payload command, starts listener
```

**On Target Machine:**
```bash
# Copy the displayed command from sectumsempra output
bash payload_linux_<TARGET_IP>.sh

# Or for Windows:
powershell -ExecutionPolicy Bypass -File payload_windows_<TARGET_IP>.ps1
```

*Result: Morsmordre activates automatically and begins autonomous enumeration.*

---

## 🔧 Individual Tool Reference

### NetWeave v9.2 (Cyan Engine)
**Purpose:** Discovers target OS and services, correlates attack vectors via local AI.

**Usage:**
```bash
python3 netweave.py <TARGET_IP>              # Full AI correlation
python3 netweave.py <TARGET_IP> --no-ai      # Pattern-only (faster)
```
**Output:** `netweave_<TARGET_IP>.json`

**Features:**
* Nmap OS detection with heuristic fallback
* Async port scanning (top 22 CTF ports)
* Council of Wizards (multi-model voting)
* Structured JSON contract generation

### Sectumsempra v1.2 (Green Engine)
**Purpose:** Generates OS-appropriate payloads, binds listener, bridges shell to Morsmordre.

**Usage:**
```bash
python3 sectumsempra.py                      # Auto-find latest contract
python3 sectumsempra.py --contract netweave_<TARGET>.json
```
**Output:**
* `payload_linux_<TARGET>.sh` or `payload_windows_<TARGET>.ps1`
* Active listener on port 4444
* Automatic Morsmordre handoff on connection

**Features:**
* Auto-detects `tun0` interface
* OS-aware payload generation (bash/PowerShell)
* Async socket server
* Seamless stdin/stdout bridging to Tool 3/3

### Morsmordre v1.0 (Red Engine)
**Purpose:** Autonomous post-exploitation enumeration and credential harvesting.

**Usage:** Never run manually. Spawned automatically by Sectumsempra.

**Output:** `morsmordre_<TARGET>_<TIMESTAMP>.json`

**Enumeration Commands:**

| OS | Commands |
| :--- | :--- |
| **Linux** | `id`, `uname`, `/etc/passwd`, `/etc/shadow`, `sudo -l`, SUID find, `netstat`, `ps aux`, `crontab` |
| **Windows** | `whoami`, `systeminfo`, `net user`, `ipconfig`, `tasklist`, registry queries |

**Loot Categories:**
* **Credentials:** `passwd`, `shadow`, database configurations, tokens
* **Privilege Escalation:** `sudo` rights, SUID binaries, capabilities
* **Network:** active connections, local interfaces, routing tables
* **Persistence:** `cron` jobs, startup services, user registry keys

---

## 📋 JSON Schema

### NetWeave Contract
```json
{
  "target": "<TARGET_IP>",
  "operating_system": "Linux",
  "os_confidence": 91,
  "ports": [
    {"port": 22, "service": "ssh", "version": "OpenSSH 8.2", "notes": ""}
  ],
  "recommended_vector": {
    "vector_name": "SSH_Enumeration",
    "target_port": 22,
    "vulnerability_type": "Configuration",
    "technical_summary": "Primary attack vector"
  },
  "commands": {
    "primary": "hydra -l root -P rockyou.txt ssh://<TARGET_IP>",
    "alternatives": [],
    "source": "Council"
  }
}
```

### Morsmordre Loot
```json
{
  "target": "<TARGET_IP>",
  "os": "Linux",
  "commands_executed": 11,
  "loot": [
    {
      "timestamp": "2026-01-01T12:00:00",
      "category": "credentials",
      "data": "root:$6$xyz...",
      "source": "cat /etc/shadow"
    }
  ]
}
```

---

## 🛠️ Architecture Details

### Data Flow
1. **NetWeave** scans target → generates contract JSON on disk
2. **Sectumsempra** reads contract → generates script payload → binds local background listener
3. **Target** machine executes payload → connects back to active listener
4. **Sectumsempra** spawns **Morsmordre** process with socket bridged directly to stdin/stdout
5. **Morsmordre** injects automated commands → parses return responses → writes structural loot JSON

### Communication Protocol
* **Tool 1 → 2:** Local JSON state contract file on system storage
* **Tool 2 → 3:** Unix stdin/stdout pipes (socket descriptors bridging)
* **Tool 3 → Disk:** Normalized JSON loot metric file output

---

## 🐛 Troubleshooting

### NetWeave Issues
* **"Ollama not responding"**
  ```bash
  # Terminal 1 - Restart the execution daemon
  ollama serve
  # Verify connection status
  curl http://localhost:11434/api/tags
  ```
* **"No services found"**
  * Check target connectivity: `ping <TARGET_IP>`
  * Verify target isn't blocking probes: `nmap -Pn <TARGET_IP>`
* **"Server disconnected" (Ollama crash)**
  * Reduce engine model load: Run with `--no-ai` flag to pass raw diagnostics
  * Hard restart service: `pkill ollama && ollama serve`

### Sectumsempra Issues
* **"No NetWeave contract found"**
  ```bash
  # Run NetWeave deployment stage first
  python3 netweave.py <TARGET_IP>
  # Or supply explicit parameter definitions path
  python3 sectumsempra.py --contract ./netweave_<TARGET>.json
  ```
* **"Address already in use" (Port 4444)**
  ```bash
  # Terminate conflicting active processing sockets
  sudo lsof -ti:4444 | xargs kill -9
  ```
* **"Payload won't execute on target"**
  * Verify LHOST detection: Confirm active `tun0` interface configurations exist
  * Manual override adjustments: Append raw configuration variables directly inside the payload file asset

### Morsmordre Issues
* **"No output from commands"**
  * Ensure the process is automatically spawned by Sectumsempra (do not run standalone)
  * Verify target binary execution path environment variables are valid
* **"Commands timeout"**
  * Target lab box might be experiencing resource constraints or non-interactive shell states
  * Run `echo $SHELL` on target to verify environment initialization defaults to `/bin/bash` or equivalent shell configurations

---

## ⚙️ Environment Variables

| Variable | Set By | Description |
|:---|:---|:---|
| `MORSMORDRE_TARGET` | Sectumsempra | Target lab destination IP address |
| `MORSMORDRE_OS` | Sectumsempra | Target environment architecture footprint (`Linux`/`Windows`) |
| `MORSMORDRE_LHOST` | Sectumsempra | Attacker local connection adapter tunnel IP (`tun0`) |
| `OLLAMA_URL` | User Override | Target address for local loopback AI communications (default: `localhost:11434`) |

---

## 📁 File Structure

```text
project/
├── netweave.py          # Tool 1/3 - Cyan Engine
├── sectumsempra.py      # Tool 2/3 - Green Engine
├── morsmordre.py        # Tool 3/3 - Red Engine
├── README.md            # This framework guide file
├── netweave_*.json      # Generated target context contracts
├── payload_*.sh         # Output Linux script stagers
├── payload_*.ps1        # Output Windows script stagers
└── morsmordre_*.json    # Normalized system loot capture files
```

---

## 🎯 Execution Checklist

1. [ ] Ollama service validation check complete (`ollama serve` active)
2. [ ] Local model dependencies downloaded (`ollama list` confirms target wizards)
3. [ ] Run Cyan reconnaissance phase: `python3 netweave.py <TARGET>`
4. [ ] Verify compilation contract creation state: `ls netweave_*.json`
5. [ ] Execute Green staging bridge pipeline handler: `python3 sectumsempra.py`
6. [ ] Isolate stager code payload information block and copy text parameters
7. [ ] Execute stager payload assembly vector directly onto the remote lab system
8. [ ] Verify automatic Morsmordre Red post-exploitation execution loop engagement
9. [ ] Extract final local machine loot reports file asset: `ls morsmordre_*.json`

---

## ⚖️ Legal Notice

Authorized Use Only. This suite is designed exclusively for authorized CTF competitions (HackTheBox, TryHackMe), sanctioned penetration testing laboratories, and educational security research in isolated lab environments. Requirements include explicit written authorization for target systems, compliance with local computer crime laws (CFAA, etc.), and network owner permission. Unauthorized access to computer systems is highly illegal. The authors assume no liability for misuse.

---

## 📝 Version Information

| Tool | Version | Role | Status |
|:---|:---|:---|:---|
| **NetWeave** | v9.2 | Reconnaissance Analysis | Stable |
| **Sectumsempra** | v1.2 | Exploitation Staging Bridge | Stable |
| **Morsmordre** | v1.0 | Post-Exploitation Triage | Stable |
