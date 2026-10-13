# Quick Start Guide: Reverse Engineering with REA

This guide covers the day-to-day workflow for analyzing Android APKs and binaries using REA.

---

## 🚀 Quick Recap of Your Setup

### 1. Drop APKs to Analyze

Put any APK file into the `targets/` directory in this repository:

```bash
# Path on host computer:
morluto/targets/my-app.apk
```

_Note: Any file placed here is instantly visible inside the Docker container at `/workspace/targets/my-app.apk` without rebuilding or restarting._

---

### 2. Analyze in GUI (MCP Inspector)

1. Open your web browser to:
   ```
   http://localhost:6274
   ```
2. Make sure the top-right indicator shows **Connected**.
3. Under the **Tools** tab, select a tool (e.g., `search_android_classes` or `inspect_android_package`).
4. Enter the container path:
   ```
   /workspace/targets/my-app.apk
   ```
5. Click **Run Tool**.

---

### 3. Analyze with Terminal CLI

Run reverse engineering commands directly from your terminal:

- **Search Android Classes**:
  ```bash
  ./deploy/deploy.sh cli search-android-classes /workspace/targets/my-app.apk MainActivity
  ```
- **Inspect Android Package & Manifest**:
  ```bash
  ./deploy/deploy.sh cli inspect-android-package /workspace/targets/my-app.apk
  ```
- **Identify Flutter Build**:
  ```bash
  ./deploy/deploy.sh cli identify-flutter-build /workspace/targets/my-app.apk
  ```

---

### 4. Analyze with AI Agents (Cursor, Claude, Gemini, Continue with Ollama)

When connected via MCP (see `deploy/example-ai-agent.md`), simply ask your AI agent in plain English:

> _"Use the REA tools to inspect `/workspace/targets/my-app.apk` and extract all API endpoints, package details, and Flutter architecture."_

The AI agent will call the decompiler inside Docker in the background and write a full intelligence report for you.

---

## 🛠️ Service Management Commands

Manage your REA Docker services from the project root:

| Action                   | Command                      |
| :----------------------- | :--------------------------- |
| **Check service status** | `./deploy/deploy.sh status`  |
| **Start all services**   | `./deploy/deploy.sh start`   |
| **Stop all services**    | `./deploy/deploy.sh stop`    |
| **Restart services**     | `./deploy/deploy.sh restart` |
| **View live logs**       | `./deploy/deploy.sh logs -f` |

---

## 🌐 Endpoints & Ports

- **MCP Inspector GUI**: [http://localhost:6274](http://localhost:6274)
- **Web Documentation**: [http://localhost:4173](http://localhost:4173)
- **AI Agent MCP Server**: `docker exec -i rea-core rea mcp`

---

## 📚 Complete Tool Inventory

For the full catalog of all 189 reverse-engineering tools with descriptions and required arguments, see:

- [scan-tools.md](scan-tools.md)
