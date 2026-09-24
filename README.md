# NetWeave v6.5

A localized network reconnaissance framework and automated attack chain generator designed for cybersecurity audit verification and capture the flag environments.

## Core Capabilities

The architecture performs automated service discovery by executing low level TCP socket connections against target infrastructure. It queries common operational ports to harvest application banners and software version signatures, including OpenSSH, Apache, and Nginx. 

The web assessment module extracts hidden HTML source artifacts, parses comment blocks, and audits directory configurations to locate restricted administrative endpoints, repository leaks, and system path responses based on HTTP status codes.

Telemetry harvested during execution is parsed through a localized relational database engine to correlate host exposure and isolate high probability attack vectors. Validated command structures are extracted, modified to match host operating system abstractions, and compiled into an independent executable script file for fast deployment.

## Deployment Instructions

System requirements include Python 3.10 or newer and a synchronized local data engine node active on port 11434.

Clone the framework configuration to the target workspace:
```bash
git clone https://github.com/danielissaq/NetWeave.git
cd NetWeave
```

Initialize the background database layer:
```bash
ollama serve
```

Execute the core automation loop:
```bash
python pwn_recon.py
```

## Operational Sequence

The user defines the destination host target parameters.

NetWeave maps open network sockets, harvests software signatures, and feeds the output directly into the offline correlation matrix.

The analytical engine structures a prioritized execution strategy, isolating specific terminal syntax, targeted curl commands, and session configurations.

An automated execution script named fire payloads IP.ps1 is cached directly to the active directory workspace, allowing immediate multi terminal payload deployment.

Legal Notice: This asset is built strictly for authorized white hat infrastructure mapping, academic network testing environments, and isolated laboratory verification.
