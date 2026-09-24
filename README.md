# NetWeave v6.5

## Deployment

### 1. Clone

```bash
git clone https://github.com/danielissaq/NetWeave.git
cd NetWeave
```

### 2. Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install requests
```

### 3. Install Ollama

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

### 4. Start the local engine

Open a new terminal tab:

```bash
ollama serve
```

Leave it running.

### 5. Pull the model

Back in the NetWeave terminal:

```bash
ollama pull deepseek-r1:8b
```

Check that it is installed:

```bash
ollama list
```

You should see:

```text
deepseek-r1:8b
```

### 6. Launch NetWeave

```bash
source .venv/bin/activate
python pwn_recon.py
```

NetWeave connects locally through:

```text
http://127.0.0.1:11434
```

## Terminal Setup

Terminal 1

```bash
ollama serve
```

Terminal 2

```bash
cd NetWeave
source .venv/bin/activate
python pwn_recon.py
```

If you are already inside the NetWeave directory, do not run `cd NetWeave` again.

## Legal Notice

NetWeave is built for authorized security testing, CTFs and isolated laboratory environments.

Only use it against systems you own or have explicit permission to test.
