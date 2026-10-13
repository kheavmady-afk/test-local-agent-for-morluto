# REA (Reverse Engineer Anything) Deployment Guide

This guide provides complete instructions for deploying and using **REA** on **Ubuntu / Linux** and **Windows** using Docker, Docker Compose, and native automation scripts.

---

## ⚡ Quick Daily Workflow Recap

1. **Drop APKs to analyze**: Put any APK into `morluto/targets/` (e.g. `targets/my-app.apk`).
2. **Analyze in GUI**: Open **http://localhost:6274** and enter `/workspace/targets/my-app.apk`.
3. **Analyze in Terminal CLI**:
   ```bash
   ./deploy/deploy.sh cli search-android-classes /workspace/targets/my-app.apk MainActivity
   ```
4. **Analyze with AI Agents** _(Cursor, Claude, Gemini, Continue with Ollama)_:
   Ask your AI agent in plain English: _"Inspect `/workspace/targets/my-app.apk` and report all API endpoints and package details."_
   _(See [QUICKSTART.md](QUICKSTART.md) and [example-ai-agent.md](example-ai-agent.md) for full details)._

---

## 1. Project Overview & Architecture

**REA** is a unified reverse engineering toolkit and Model Context Protocol (MCP) server. It enables AI coding agents (Claude Code, Cursor, Codex, Gemini CLI, Grok Build, etc.) and human security analysts to inspect and decompile targets without source code:

- **Native Binaries**: Pseudocode, assembly, symbols, call graphs, strings, mitigations (integrating with Hopper, Ghidra, and IDA).
- **JavaScript & Electron Apps**: ASAR extraction, source maps, module graphs, IPC channels, and preload boundaries.
- **Mobile & Managed Code**: Android APKs (manifests, decompiled Java/Smali), .NET assemblies (CIL, P/Invoke), Flutter, HarmonyOS.
- **Smart Contracts & Bytecode**: EVM bytecode disassembly and ABI selector recovery.
- **Websites & Runtimes**: Chrome DevTools Protocol (CDP) live tracing, event listeners, network captures (HAR, PCAP, SAZ, Qlog).
- **Firmware & Embedded**: Partition layouts, binwalk/unblob integration, logic analyzer signal traces.

### Deployment Components & Service Groups

To ensure maximum flexibility and prevent interference with other projects running on your machine, REA services are divided into **independent service groups**:

| Service Group   | Container Name   | Default Port                            | Description                                                                                                                                   |
| --------------- | ---------------- | --------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| **`core`**      | `rea-core`       | _Internal / Stdio_                      | REA CLI engine and Agent MCP server daemon. Mounts `./targets` (read-only) and `./output` (read-write).                                       |
| **`web`**       | `rea-web`        | **4173** (HTTP)                         | High-performance Nginx server hosting the complete REA multi-language documentation, visual architecture guides, and showcases.               |
| **`inspector`** | `rea-inspector`  | **6274** (Web UI)<br>**6275** (Sandbox) | Official Model Context Protocol (MCP) Web Inspector for interactively exploring, invoking, and testing all 189 REA MCP tools in your browser. |
| **`all`**       | _All containers_ | **4173, 6274, 6275**                    | Deploys all services together under one unified project.                                                                                      |

---

## 2. Port Conflict Protection & Isolation

If you run multiple Docker stacks or microservices on your system (e.g., PostgreSQL on 5432, Redis on 6379, Web applications on 3000–3003, Kafka on 9092, Prometheus on 9090, Security scanners like OpenVAS or reNgine), REA provides strict isolation:

1. **Dedicated Project Namespace**: REA runs with `COMPOSE_PROJECT_NAME=rea`. Docker commands in the deployment scripts strictly manage the `rea` project and will **never** stop, remove, or modify other containers.
2. **Dedicated Bridge Network**: All REA containers communicate through an isolated `rea-network` bridge.
3. **Safe Default Ports**:
   - `REA_WEB_PORT=4173` (Does not conflict with 80, 443, 3000–3003, 5000, 8080–8082, etc.)
   - `REA_INSPECTOR_PORT=6274` & `6275` (Safe, standard MCP inspector range)
4. **Pre-flight Port Conflict Verification**: Both `deploy.sh` and `deploy.ps1` automatically check if host ports are already bound and warn you before launching.
5. **Configurable via `.env`**: You can override any port or folder path at any time by editing `.env`.

---

## 3. Ubuntu / Linux / macOS Deployment

### Prerequisites

- Docker Engine 24+ and Docker Compose v2 (`docker compose version`)
- Normal user added to `docker` group (`sudo usermod -aG docker $USER`)

### Quick Start

```bash
# Make script executable
chmod +x deploy.sh

# Start all services (core, web docs, and inspector)
./deploy.sh start all
```

### Management Commands

```bash
# Check status and health of containers
./deploy.sh status

# Start only a specific group
./deploy.sh start core       # Only the REA engine
./deploy.sh start web        # Only documentation (http://localhost:4173)
./deploy.sh start inspector  # Only MCP Inspector (http://localhost:6274)

# Stop services
./deploy.sh stop

# Restart services
./deploy.sh restart all

# View container logs
./deploy.sh logs rea-web
./deploy.sh logs rea-core

# Rebuild Docker images
./deploy.sh build all

# Clean up REA containers, volumes, and networks
./deploy.sh clean
```

---

## 4. Windows Deployment

### Prerequisites

- Docker Desktop for Windows with WSL2 backend running.
- PowerShell 5.1+ or PowerShell 7+ (or Command Prompt).

### Quick Start with PowerShell (`deploy.ps1`)

Open PowerShell as Administrator or regular user inside the repository directory:

```powershell
# Start all services
.\deploy.ps1 start all
```

### Quick Start with Command Prompt (`deploy.bat`)

```cmd
deploy.bat start all
```

### Management Commands on Windows

```powershell
# View container status and mapped ports
.\deploy.ps1 status

# Start specific service groups
.\deploy.ps1 start core
.\deploy.ps1 start web
.\deploy.ps1 start inspector

# Stop services
.\deploy.ps1 stop

# Restart services
.\deploy.ps1 restart all

# Tail logs
.\deploy.ps1 logs rea-core

# Rebuild containers
.\deploy.ps1 build all

# Clean up
.\deploy.ps1 clean
```

---

## 5. Connecting AI Agents to the REA Docker Deployment

AI coding agents support connecting to MCP servers via standard I/O (`stdio`). You can point your AI agent directly to the running `rea-core` container.

### A. Cursor Configuration

In Cursor Settings -> **Features** -> **MCP Servers** -> **Add New MCP Server**:

- **Name**: `rea`
- **Type**: `command`
- **Command**: `docker exec -i rea-core rea mcp`

Or in `~/.cursor/mcp.json` (or `%USERPROFILE%\.cursor\mcp.json` on Windows):

```json
{
  "mcpServers": {
    "rea": {
      "command": "docker",
      "args": ["exec", "-i", "rea-core", "rea", "mcp"]
    }
  }
}
```

### B. Claude Code Configuration

Add the REA container MCP server:

```bash
claude mcp add rea -- docker exec -i rea-core rea mcp
```

### C. Gemini CLI Configuration

Add to `~/.gemini/config/mcp_config.json`:

```json
{
  "mcpServers": {
    "rea": {
      "command": "docker",
      "args": ["exec", "-i", "rea-core", "rea", "mcp"]
    }
  }
}
```

### D. Codex / Grok Build / Antigravity

Configure the server command as:

```text
docker exec -i rea-core rea mcp
```

---

## 6. How to Use REA

### 1. Using the REA CLI from Your Host

The deployment script provides a convenient `cli` wrapper that forwards commands straight into `rea-core`:

```bash
# Linux / Ubuntu
./deploy.sh cli --version
./deploy.sh cli doctor --json

# Windows
.\deploy.ps1 cli --version
.\deploy.ps1 cli doctor --json
```

### 2. Analyzing Targets

Place target binaries, APKs, or JavaScript applications inside the `./targets/` directory on your host machine. They are automatically mounted inside the container at `/workspace/targets`:

```bash
# Example: Analyze a JavaScript / Electron application
./deploy.sh cli analyze-javascript-application /workspace/targets/sample-js-app --json

# Example: Inspect a WebAssembly binary
./deploy.sh cli inspect-wasm-artifact /workspace/targets/module.wasm --json

# Example: Inspect SQLite database schema
./deploy.sh cli inspect-sqlite-database /workspace/targets/app.db --json
```

Output reports and recovered source files are saved to `/workspace/output`, which maps directly to `./output/` on your host.

### 3. Browsing the Web Documentation & Showcase

Once `rea-web` is running:

- Open: **`http://localhost:4173/`**
- Browse case studies (e.g., DX-Ball sound reconstruction, Notion Electron IPC clipboard bridge, TH04 PC-98 reverse engineering).
- Read detailed guides on binary disassembly, network analysis, and agent prompting.

### 4. Interactive Testing with the MCP Web Inspector

Once `rea-inspector` is running:

- Open: **`http://localhost:6274/`**
- Interactively explore all **189 MCP tools** and **6 prompts**.
- Execute any tool with test parameters and view formatted evidence responses in real time.

---

## 7. Configuration Reference (`.env`)

| Variable               | Default      | Purpose                                                               |
| ---------------------- | ------------ | --------------------------------------------------------------------- |
| `COMPOSE_PROJECT_NAME` | `rea`        | Namespace isolating REA containers from other host containers.        |
| `REA_WEB_PORT`         | `4173`       | Host port for the Nginx documentation & showcase site.                |
| `REA_INSPECTOR_PORT`   | `6274`       | Host port for the MCP Inspector Web UI.                               |
| `REA_SANDBOX_PORT`     | `6275`       | Host port for the MCP Inspector Sandbox.                              |
| `REA_TARGETS_DIR`      | `./targets`  | Host directory containing binaries and applications to analyze.       |
| `REA_OUTPUT_DIR`       | `./output`   | Host directory where analysis results and decompiled files are saved. |
| `REA_LOG_LEVEL`        | `info`       | Logging verbosity (`info`, `debug`, `error`, `silent`).               |
| `NODE_ENV`             | `production` | Node.js execution environment.                                        |

---

## 8. Verification & Troubleshooting

### Verify Running Containers

```bash
docker ps --filter "name=rea-"
```

Expected output:

```text
CONTAINER ID   IMAGE           COMMAND                  STATUS          PORTS                         NAMES
xxxxxxxxxxxx   rea:inspector   "docker-entrypoint.s…"   Up (healthy)    0.0.0.0:6274-6275->6274-6275  rea-inspector
yyyyyyyyyyyy   rea:core        "docker-entrypoint.s…"   Up (healthy)                                  rea-core
zzzzzzzzzzzz   rea:web         "/docker-entrypoint.…"   Up (healthy)    0.0.0.0:4173->80/tcp          rea-web
```

### Port Conflict Resolution

If a port is already taken by an existing service:

1. Open `.env`.
2. Change `REA_WEB_PORT` or `REA_INSPECTOR_PORT` to an unused port (e.g., `4175` or `6280`).
3. Run `./deploy.sh restart` (or `.\deploy.ps1 restart`).
