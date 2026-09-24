# NetWeave v6.5

**NetWeave** is a local reconnaissance and security testing framework for CTFs, labs and authorized assessments.

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

## Example

```text
┌─ NETWEAVE CORE INTELLIGENCE CORRELATION ──────────────────────────────┐
│                                                                       │
│  TARGET     45.33.32.156                                             │
│  SERVICES   HTTP :80   SSH :22                                       │
│                                                                       │
│  DISCOVERY                                                           │
│  ├─ HTTP headers collected                                           │
│  ├─ SSH service identified                                           │
│  └─ Exposed attack surface indexed                                   │
│                                                                       │
│  CORRELATION                                                         │
│  ├─ HTTP service → header analysis                                   │
│  └─ SSH service → authentication testing                            │
│                                                                       │
│  ATTACK PATH                                                         │
│  ├─ http reconnaissance                                              │
│  └─ ssh authentication assessment                                    │
│                                                                       │
│  OUTPUT                                                              │
│  ├─ Report generated                                                 │
│  └─ Execution payload generated                                      │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘

[+] Intelligence correlation complete
[+] Report saved
[+] Execution workflow generated
```

The result is a structured path from discovered infrastructure to the relevant testing workflow instead of a wall of disconnected reconnaissance output.

## Deployment

Clone the repository:

```bash
git clone https://github.com/danielissaq/NetWeave.git
cd NetWeave
```

Create the Python environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install requests
```

Start Ollama in a new terminal:

```bash
ollama serve
```

Return to NetWeave and pull the required model:

```bash
ollama pull deepseek-r1:8b
```

Then launch:

```bash
python pwn_recon.py
```

NetWeave connects to the local Ollama service at:

```text
http://127.0.0.1:11434
```

## Terminal Layout

```text
TERMINAL 1
$ ollama serve

TERMINAL 2
$ cd NetWeave
$ source .venv/bin/activate
$ python pwn_recon.py
```

If you are already inside the NetWeave directory, do not run `cd NetWeave` again.

## Legal Notice

NetWeave is intended for CTFs, security research, authorized assessments and isolated laboratory environments.

Only use it against systems you own or have explicit permission to test.
