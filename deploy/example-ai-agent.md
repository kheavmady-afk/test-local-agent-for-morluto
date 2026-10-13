# AI Agent Integration Guide for REA (Method 1: Docker MCP)

This guide explains how to connect your **AI Agents** (Claude Desktop, Cursor, Windsurf, VS Code Continue with local Ollama, Cline, Open WebUI) to REA using **Method 1 (Docker MCP)**.

---

## 🌟 Why Method 1 (Docker MCP)?

- **Zero Host Clutter**: Java 17, JADX headless decompiler, Node.js 22, Python 3, and reverse-engineering binaries stay isolated inside Docker.
- **Works with Local Ollama & Cloud LLMs**: Any client can execute REA via `docker exec -i rea-core rea mcp`.
- **Sandboxed & Safe**: Decompilation of untrusted APKs or binaries runs inside the container without risking your host machine.
- **Guaranteed Consistency**: Eliminates "works on my machine" errors across Linux, macOS, and Windows.

---

## ⚙️ Quick Prerequisites

Ensure your REA Docker core service is running:

```bash
./deploy/deploy.sh start
# or: cd deploy && ./deploy.sh start
```

Place your target APKs or binaries in the `./targets/` directory on your host:

```bash
cp /path/to/my-app.apk ./targets/
```

Inside the container, this file will be available at:

```
/workspace/targets/my-app.apk
```

---

## 🔌 AI Agent Configurations

### 1. Claude Desktop

Open or create your Claude Desktop config file:

- **Linux**: `~/.config/Claude/claude_desktop_config.json`
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

Add the `rea` server:

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

_Restart Claude Desktop. The hammer icon (Tools) will now show all REA reverse-engineering tools._

---

### 2. Cursor IDE

Open Cursor:

1. Go to **Settings** (`Ctrl + ,` or `Cmd + ,`).
2. Navigate to **Features** &rarr; **MCP**.
3. Click **Add New MCP Server**:
   - **Name**: `rea`
   - **Type**: `command`
   - **Command**: `docker exec -i rea-core rea mcp`
4. Click **Save**. Cursor will show a green dot indicating connected REA tools.

Or directly in `.cursor/mcp.json` in your workspace:

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

---

### 3. VS Code with Local Ollama (Continue.dev)

If you run **Ollama locally** with models like `qwen2.5-coder`, `llama3.1`, or `deepseek-r1`:

1. Install the **Continue** extension in VS Code.
2. Edit `~/.continue/config.json`:

```json
{
  "models": [
    {
      "title": "Local Ollama Qwen2.5",
      "provider": "ollama",
      "model": "qwen2.5-coder:14b",
      "apiBase": "http://localhost:11434"
    }
  ],
  "experimental": {
    "modelContextProtocolServers": [
      {
        "transport": {
          "type": "stdio",
          "command": "docker",
          "args": ["exec", "-i", "rea-core", "rea", "mcp"]
        }
      }
    ]
  }
}
```

---

### 4. Windsurf IDE

Open `~/.codeium/windsurf/mcp_config.json`:

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

---

### 5. Cline / Roo Code (VS Code Extension)

Open Cline MCP settings (`cline_mcp_settings.json`):

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

---

### 6. Gemini CLI & Antigravity

Open or edit `~/.gemini/config/mcp_config.json`:

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

---

### 7. Hermes Agent

If using terminal AI agents like Hermes:

```bash
# Add REA Docker MCP server to Hermes
hermes mcp add rea -- docker exec -i rea-core rea mcp
```

---

## 🎯 Example Prompts to Use With Your AI Agent

Once connected, you can chat with your AI Agent in plain English. Here are proven prompts:

### Prompt 1: Full App Architecture & API Reconnaissance

> _"Use the REA MCP tools to perform deep reverse engineering on `/workspace/targets/SMIS-Parents-app-v0.1.apk`. Extract the package details, manifest permissions, Flutter build metadata, Dart snapshot hash, backend server URLs, and all API endpoints. Present the findings in a structured markdown report."_

### Prompt 2: Security & Attack Surface Audit

> _"Inspect the Android manifest and exported components of `/workspace/targets/SMIS-Parents-app-v0.1.apk`. Identify exported activities, broadcast receivers, deep link schemas, and sensitive permissions."_

### Prompt 3: Flutter & Dart Binary Inspection

> _"Check if `/workspace/targets/SMIS-Parents-app-v0.1.apk` is a Flutter app. Identify the bundled ABIs, Dart engine commit, toolchain version, and state management libraries used."_

---

## 📊 Example Output Produced by the AI Agent

When you give the prompt above to your connected AI Agent, it calls REA's MCP tools autonomously and generates a complete report:

```markdown
Backend infrastructure relies on 'https://devsmn.tele-ict.com', with identified authentication and student-related API endpoints.
Here is the deep reverse engineering analysis of libapp.so and the Flutter runtime:

### 1. Dart Runtime & Snapshot Profile

| Property                  | Value                                                            |
| :------------------------ | :--------------------------------------------------------------- |
| **Framework**             | Flutter AOT (Ahead-of-Time)                                      |
| **Dart SDK Version**      | 3.13.4                                                           |
| **Snapshot Hash**         | `0451907c2eaa8467e848c0067bfe8ed4`                               |
| **Engine Commit**         | `af7e796e161ae0bb1ff0758c71a7105418bd9ded`                       |
| **Build Flags**           | product, dwarf_stack_traces, arm64, android, compressed-pointers |
| **Source Project Path**   | `/Users/meanpheakdey/MPTC/Development/mptc-schoolis-flutter-app` |
| **Package ID / App Name** | `com.cspp_mobiles.dev` / "CSPP Dev"                              |

### 2. Binary Layout (libapp.so)

The binary contains standard Dart AOT data sections:

- `_kDartSnapshotData` (.rodata, offset 0x0002c0, 1.66 MB): Serialized Dart heap containing strings, class symbols, metadata, and routing definitions.
- `_kDartSnapshotText` (.text, offset 0x1a0000, 4.95 MB): Compiled AArch64 machine instructions for all Dart business logic.
- **State Management & Persistence**: Built with GetX (`SmartManagement`) and local storage via `GetStorage`.

### 3. Backend Infrastructure & Discovered Endpoints

**Primary Server Host**: `https://devsmn.tele-ict.com`

#### Authentication & Security

- `POST /api/v2/auth/signIn/parent/username` (Parent login flow)
- `POST mobile-api/auth/sign-in/student` (Student login flow)
- `POST mobile-api/auth/sign-in/email/otp` (OTP verification)
- `POST mobile-api/auth/refresh-token`
- `POST mobile-api/auth/password/change`
- `POST mobile-api/auth/logout`

#### Student, Academic & Operations

- `GET mobile-api/student/home`
- `GET mobile-api/student/profile`
- `GET mobile-api/student/preferences`
- `GET mobile-api/student/schedule`
- `GET mobile-api/student/calendar/events`
- `GET mobile-api/student/announcements` & `/api/v1/announcement/`
- `GET mobile-api/student/academic/results/ranking`
- `GET mobile-api/student/academic/results/transcripts`
- `GET /api/v1/students/`

### 4. Client Application Route Map (GetX Routing)

- `/splash` &rarr; Initial launcher splash view
- `/login` &rarr; User credential authentication
- `/parent-home` &rarr; Parent dashboard container
- `/student-dashboard` &rarr; Grades, courses, and attendance overview
```

---

## 🛠️ Verification & Troubleshooting

To verify that the MCP server is responding before launching your AI Agent:

```bash
docker exec -i rea-core rea --version
```

Should output:

```
6.4.0
```

To test MCP communication manually:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | docker exec -i rea-core rea mcp
```

If this returns a JSON result with `serverInfo: {"name":"rea"}`, your setup is 100% operational and ready for your AI agent!
