# REA Automated APK Scanner & Security Auditor Instruction Guide

This guide explains how to use the automated Python APK scanner (`auto_scan.py`) to run REA's full reverse engineering CLI suite on Android APKs with interactive target selection, executive reporting, interactive dark-mode HTML dashboards, and structured evidence storage.

---

## 🚀 Quick Start

### 1. Place Your Target APK

Drop any Android `.apk` file into the `targets/` directory at the project root:

```bash
cp /path/to/my-app.apk targets/
```

### 2. Run the Scanner

You can run the script from the repository root or from inside the `deploy/` directory:

```bash
# Option A: Interactive mode (searches targets/ and prompts you to select)
python3 deploy/py_scan/auto_scan.py

# Option B: Run on a specific APK directly
python3 deploy/py_scan/auto_scan.py SMIS-Parents-app-v0.1.apk

# Option C: Batch scan ALL APKs in targets/ and build a comparative matrix
python3 deploy/py_scan/auto_scan.py --all

# Option D: Quick search inside the latest scan results (endpoints, tokens, classes)
python3 deploy/py_scan/auto_scan.py --search cloudinary

# Option E: Scan AND extract raw files (assets, DEX, native .so libraries)
python3 deploy/py_scan/auto_scan.py SMIS-Parents-app-v0.1.apk --extract
```

---

## 🔬 The 10-Stage Reverse Engineering & Audit Pipeline

When executed, `auto_scan.py` automatically runs the following REA engine tools and security checks in sequence:

| Stage  | Tool / Capability                             | Purpose                                                                                                                                                                                                                                       |
| :----: | :-------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **1**  | `identify-flutter-build`                      | Detects Flutter framework, native ABIs (`arm64-v8a`, `armeabi-v7a`, `x86_64`), Dart snapshot hashes, and Clang toolchain lines.                                                                                                               |
| **2**  | `inspect-android-package`                     | Parses `AndroidManifest.xml` for package name, version, min/target SDK, declared permissions, activities, and receivers.                                                                                                                      |
| **3**  | `search-android-classes`                      | Indexes the entire DEX bytecode hierarchy and catalogs all classes (e.g., 686 classes).                                                                                                                                                       |
| **4**  | `inspect-android-class`                       | Inspects fields, constructors, and method signatures of the automatically discovered `MainActivity`.                                                                                                                                          |
| **5**  | `inspect-android-method`                      | Decompiles the constructor `<init>` or entry method into Java/Smali bytecode.                                                                                                                                                                 |
| **6**  | `trace-android-references`                    | Discovers callers, incoming cross-references (xrefs), and dependency links into the entry activity.                                                                                                                                           |
| **7**  | `inspect-artifact`                            | Maps the full 180+ node occurrence graph of DEX segments, assets, native `.so` files, and SHA256 digests.                                                                                                                                     |
| **8**  | `project-android-application-graph`           | Projects application topology and component boundaries.                                                                                                                                                                                       |
| **9**  | **Flutter AOT Deep Extraction** (`libapp.so`) | Automatically extracts **Primary Server Hosts** (`https://devsmn.tele-ict.com`), **Auth & Student API Endpoints**, **GetX Route Maps** (`/loginparen`, `/loginstudent`), **Cloudinary / CDN assets**, and **Developer Machine Source Paths**. |
| **10** | **Native ELF Hardening & Secrets Audit**      | Audits native `.so` binaries for Stack Canaries, PIE, RELRO, NX Stack; evaluates manifest security configurations; maps exported attack surfaces with ready-to-run ADB test commands.                                                         |

---

## 📊 Scan Results & Storage Structure

All scan outputs are saved inside `deploy/py_scan/results/` under a dedicated folder named `<apk_name>_<timestamp>/`. A `latest` symlink is automatically maintained for easy access.

```text
deploy/py_scan/
├── auto_scan.py                # Scanner script
├── py-scan-instruction.md      # This guide
└── results/
    ├── latest -> SMIS-Parents-app-v0.1_20261013_181317
    └── SMIS-Parents-app-v0.1_20261013_181317/
        ├── summary.json                     # Machine-readable summary metrics & audit checklist
        ├── SCAN_REPORT.md                   # Complete human-readable markdown report
        ├── SCAN_REPORT.html                 # Standalone interactive dark-mode HTML dashboard
        ├── 01_flutter_identification.json   # Full Flutter / Dart / ELF details
        ├── 02_package_manifest.json         # Decoded AndroidManifest & permissions
        ├── 03_classes_inventory.json        # Complete 686-class list
        ├── 04_main_class_inspection.json    # Methods & fields of MainActivity
        ├── 05_main_method_decompiled.json   # Decompiled constructor bytecode
        ├── 06_class_references.json         # Cross-references into MainActivity
        ├── 07_artifact_graph.json           # Occurrence node graph
        ├── 08_application_graph.json        # Structural application graph
        ├── 09_flutter_endpoints.json        # Extracted API Endpoints, Routes, Hosts
        ├── 10_security_and_secrets.json     # Native ELF audit, manifest flags, attack surface
        └── extracted_apk/                   # (Created only if --extract was used)
```

---

## 📋 Explicit Scanned Items Checklist (`summary.json`)

To eliminate ambiguity, `summary.json` includes a dedicated top-level `scanned_items_checklist` where every security check, runtime attribute, and credential pattern explicitly states **`Found (...)`** or **`Not found`** (instead of blank arrays or omitted keys):

```json
  "scanned_items_checklist": {
    "flutter_framework": "Found (Flutter AOT)",
    "dart_sdk_version": "Found (3.13.4)",
    "primary_server_host": "Found (https://devsmn.tele-ict.com)",
    "google_api_keys": "Not found",
    "aws_access_keys": "Not found",
    "jwt_tokens": "Not found",
    "custom_uri_schemes": "Found (fb-messenger://user/)",
    "background_services": "Not found",
    "android_debuggable": "Not found (Disabled - Production Build)",
    "cleartext_http_traffic": "Not found (Enforced HTTPS)",
    "native_stack_canaries": "Found in libdartjni.so, libflutter.so (Not found in libapp.so)",
    "native_relro": "Not found (Disabled)"
  }
```

---

## 🖥️ Interactive HTML Dashboard (`SCAN_REPORT.html`)

Every scan generates a standalone, zero-dependency, dark-mode HTML report:

- **Interactive Search Filter**: Live real-time typing filter for discovered API endpoints.
- **Attack Surface Triggers**: One-click "Copy" buttons for `adb shell am` commands to launch exported activities or broadcast receivers.
- **Audit Checklist Table**: Color-coded green `Found` badges and grey `Not found` badges for every scanned capability.
- **No external server required**: Open `deploy/py_scan/results/latest/SCAN_REPORT.html` directly in any web browser.

---

## 🛠️ CLI Flags Reference

| Flag           | Description                                                                                    | Example                                                    |
| :------------- | :--------------------------------------------------------------------------------------------- | :--------------------------------------------------------- |
| `[apk]`        | Optional APK filename or path. If omitted, prompts interactively.                              | `python3 deploy/py_scan/auto_scan.py my-app.apk`           |
| `--all`        | Batch scan all APKs in `targets/` and generate `deploy/py_scan/results/COMPARATIVE_MATRIX.md`. | `python3 deploy/py_scan/auto_scan.py --all`                |
| `--search <q>` | Fast substring search across all JSON and markdown evidence files of the latest scan.          | `python3 deploy/py_scan/auto_scan.py --search auth`        |
| `--extract`    | Unpacks all internal assets, `.so` files, and XMLs into `extracted_apk/`.                      | `python3 deploy/py_scan/auto_scan.py my-app.apk --extract` |
| `--help`       | Displays usage options and help.                                                               | `python3 deploy/py_scan/auto_scan.py --help`               |
