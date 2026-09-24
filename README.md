# NetWeave v6.5

NetWeave is a local reconnaissance and security testing framework built for CTFs, labs and authorized assessments.

It takes reconnaissance data, correlates the findings and turns them into a clear attack path with generated commands and an execution payload.

```text
RECON
  ↓
CORRELATION
  ↓
ATTACK PATH
  ↓
PAYLOAD
```

## Deployment

Clone the repository:

```bash
git clone https://github.com/danielissaq/NetWeave.git
cd NetWeave
```

Set up Python:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install requests
```

Open a new terminal and start Ollama:

```bash
ollama serve
```

Back in the NetWeave terminal:

```bash
ollama pull deepseek-r1:8b
python pwn_recon.py
```

NetWeave uses the local Ollama service at:

```text
http://127.0.0.1:11434
```

## What You Get

NetWeave processes discovered services and web information into actionable output instead of leaving you with pages of raw reconnaissance.

Example:

```text
NETWEAVE CORE INTELLIGENCE CORRELATION

1. nmap ...
2. nmap ...
3. ...

[+] Operational data cached
[+] Execution payload created
```

The generated files contain the resulting commands and execution workflow for review.

## Legal Notice

Built for CTFs, security research, authorized assessments and isolated lab environments.

Only use NetWeave against systems you own or have explicit permission to test.
