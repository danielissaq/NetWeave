# NetWeave v6.5

Localized network reconnaissance and security-audit framework for authorized testing, CTFs and lab environments.

## Requirements

- Linux
- Python 3.10+
- Ollama
- `deepseek-r1:8b`

## Installation

Clone the repository:

```bash
git clone https://github.com/danielissaq/NetWeave.git
cd NetWeave
```

Create the Python environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Ollama

Install Ollama if you don't already have it:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Start Ollama in a separate terminal:

```bash
ollama serve
```

Then, in the NetWeave terminal, download the model:

```bash
ollama pull deepseek-r1:8b
```

Verify:

```bash
ollama list
```

You should see:

```text
deepseek-r1:8b
```

## Run

With Ollama running in the other terminal:

```bash
cd NetWeave
source .venv/bin/activate
python pwn_recon.py
```

NetWeave connects to the local Ollama API at:

```text
http://127.0.0.1:11434
```

## Quick Setup

After Ollama is installed, the normal workflow is simply:

**Terminal 1**
```bash
ollama serve
```

**Terminal 2**
```bash
git clone https://github.com/danielissaq/NetWeave.git
cd NetWeave
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
ollama pull deepseek-r1:8b
python pwn_recon.py
```

## Legal Notice

NetWeave is intended only for authorized security testing, CTFs, academic research and isolated laboratory environments. Only scan or assess systems you own or have explicit permission to test.
