# NetWeave v6.5

Localized network reconnaissance framework for authorized security testing, CTFs and laboratory environments.

## Deployment

Clone the repository:

```bash
git clone https://github.com/danielissaq/NetWeave.git
cd NetWeave
```

Create and activate the Python environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install Ollama if it is not already installed:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Open a **new terminal tab** and start the local Ollama server:

```bash
ollama serve
```

Leave `ollama serve` running.

Return to the NetWeave terminal and download the required model:

```bash
ollama pull deepseek-r1:8b
```

Verify that the model is installed:

```bash
ollama list
```

You should see:

```text
deepseek-r1:8b
```

Then start NetWeave:

```bash
cd NetWeave
source .venv/bin/activate
python pwn_recon.py
```

NetWeave uses the local Ollama API:

```text
http://127.0.0.1:11434
```

### Terminal layout

**Terminal 1:**

```bash
ollama serve
```

**Terminal 2:**

```bash
cd NetWeave
source .venv/bin/activate
python pwn_recon.py
```

That's it. Ollama must remain running in Terminal 1 while NetWeave is running in Terminal 2.

## Legal Notice

NetWeave is intended for authorized security testing, CTFs, academic research and isolated laboratory environments. Only assess systems you own or have explicit permission to test.
