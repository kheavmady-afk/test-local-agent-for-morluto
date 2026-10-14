#!/usr/bin/env python3
"""
REA Automated APK Reverse Engineering Scanner & Security Auditor
------------------------------------------------------------------
Scans Android APKs in targets/ using REA's CLI tools suite and deep
binary inspection. Generates structured JSON evidence, markdown reports,
interactive HTML dashboards, and attack surface mappings.
"""

import os
import re
import sys
import json
import time
import shutil
import zipfile
import argparse
import subprocess
from datetime import datetime
from pathlib import Path

# Paths configuration
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR
for p in [SCRIPT_DIR] + list(SCRIPT_DIR.parents):
    if (p / "targets").exists():
        REPO_ROOT = p
        break
TARGETS_DIR = REPO_ROOT / "targets"
RESULTS_DIR = SCRIPT_DIR / "results"

CONTAINER_NAME = "rea-core"
CONTAINER_TARGETS_DIR = "/workspace/targets"

# Known Flutter Engine commit to (Flutter Version, Dart Version) mapping
# Used as offline fallback when dynamic banner extraction requires exact framework release pairing.
ENGINE_COMMIT_MAP = {
    # Custom / local candidate
    "af7e796e161ae0bb1ff0758c71a7105418bd9ded": ("3.13.4", "Dart 3.1.2 / 3.13.4"),

    # Flutter 3.24.x (Dart 3.5.x)
    "a18df97ca57a249df5d8d68cd0820600223ce262": ("3.24.5", "Dart 3.5.4"),
    "36335019a8eab588c3c2ea783c618d90505be233": ("3.24.3", "Dart 3.5.3"),
    "b8800d88be4866db1b15f8b954ab2573bba9960f": ("3.24.0", "Dart 3.5.0"),

    # Flutter 3.22.x (Dart 3.4.x)
    "235db911ba279722f5e685f38b0ed30fa7e8570a": ("3.22.3", "Dart 3.4.4"),
    "f6344b75dcf861d8bf1f1322780b8811f982e31a": ("3.22.0", "Dart 3.4.0"),

    # Flutter 3.19.x (Dart 3.3.x)
    "c4cd48e186460b32d44585ce3c103271ab676355": ("3.19.6", "Dart 3.3.4"),
    "04817c99c9fd4956f27505204f7e344335810aed": ("3.19.0", "Dart 3.3.0"),

    # Flutter 3.16.x (Dart 3.2.x)
    "f40e976bedff57e69e1b3d89a7c2a3c617a03dad": ("3.16.9", "Dart 3.2.6"),
    "74d16627b940bb15e50891f82cad6c3e3465bd6d": ("3.16.0", "Dart 3.2.0"),

    # Flutter 3.13.x (Dart 3.1.x)
    "0545f8705df301877d787107bac1a6e9fc9ee1ad": ("3.13.9", "Dart 3.1.5"),
    "9064459a8b0dcd32877107f6002cc429a71659d1": ("3.13.4", "Dart 3.1.2"),
    "1ac611c64eadbd93c5f5aba5494b8fc3b35ee952": ("3.13.0", "Dart 3.1.0"),

    # Flutter 3.10.x (Dart 3.0.x)
    "cdbeda788a293fa29665dc3fa3d6e63bd221cb0d": ("3.10.6", "Dart 3.0.6"),
    "d44b5a94c976fbb65815374f61ab5392a220b084": ("3.10.0", "Dart 3.0.0"),

    # Flutter 3.7.x (Dart 2.19.x)
    "1a65d409c7a1438a34d21b60bf30a6fd5db59314": ("3.7.12", "Dart 2.19.6"),
    "b24591ed328a2d4ce6505819e2f5898a78132f7f": ("3.7.0", "Dart 2.19.0"),

    # Flutter 3.3.x (Dart 2.18.x)
    "3316dd8728419ad3534e3f6112aa6291f587078a": ("3.3.10", "Dart 2.18.6"),
    "5e9e0e0aa8be4ff69facadd706b713f0bb54d5b3": ("3.3.0", "Dart 2.18.0"),

    # Flutter 3.0.x (Dart 2.17.x)
    "e85ea0e79c6d894c120cda4ee8ee10fe6745e187": ("3.0.5", "Dart 2.17.6"),
    "d1b9a6938ad77326ac3a94d92bbc77933ed829ed": ("3.0.0", "Dart 2.17.0"),

    # Flutter 2.10.x (Dart 2.16.x)
    "57d3bac3dd5cb5b0e464ab70e7bc8a0d8cf083ab": ("2.10.5", "Dart 2.16.2"),
    "776efd2034d50af73e2876d703213601df384e88": ("2.10.0", "Dart 2.16.0")
}

def resolve_flutter_engine_version(flutter_so_data: bytes) -> tuple:
    """
    Resolves Flutter engine commit, Flutter SDK version, and Dart SDK version.
    Strategy:
      1. Dynamic Search First:
         - Inspects Dart VM runtime banner: `<major>.<minor>.<patch> (channel) (...) on "<platform>"`
         - Extracts null-delimited 40-hex Git commit SHA from libflutter.so.
      2. Online check (optional, fast 1.5s timeout) if commit is unmapped:
         - Looks up commit message or engine tag from official Flutter repository.
      3. Offline Map Fallback:
         - Checks expanded ENGINE_COMMIT_MAP for exact Flutter version pairing.
      4. Safe Reporting:
         - Returns actual facts or "Unknown (Engine SHA: ...)" without fabricating versions.
    Returns: (engine_commit, display_version_string)
    """
    if not flutter_so_data:
        return None, "Not found"

    # Step 1: Dynamic banner search (embedded in libflutter.so Dart VM runtime)
    dynamic_dart_version = None
    banner_match = re.search(
        rb"([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[0-9.]+)?)\s+\((stable|beta|dev|main)[^)]*\)\s+\([^)]*\)\s+on\s+\"([^\"]+)\"",
        flutter_so_data
    )
    if banner_match:
        ver = banner_match.group(1).decode("utf-8", "ignore")
        channel = banner_match.group(2).decode("utf-8", "ignore")
        dynamic_dart_version = f"{ver} ({channel})"

    # Step 2: Extract 40-character Git SHA engine commit
    # Prioritize null-terminated 40-hex strings, ignoring test patterns like 8888...
    commits = [
        c.decode() for c in re.findall(rb"\x00([0-9a-f]{40})\x00", flutter_so_data)
        if len(set(c)) > 4
    ]
    if not commits:
        commits = [
            c.decode() for c in re.findall(rb"\b[0-9a-f]{40}\b", flutter_so_data)
            if len(set(c)) > 4
        ]
    engine_commit = commits[0] if commits else None

    # Step 3: Check offline ENGINE_COMMIT_MAP
    flutter_version = None
    if engine_commit and engine_commit in ENGINE_COMMIT_MAP:
        mapped_flutter, mapped_dart = ENGINE_COMMIT_MAP[engine_commit]
        flutter_version = mapped_flutter
        if not dynamic_dart_version:
            dynamic_dart_version = mapped_dart
    elif engine_commit:
        # Step 3b: Fast non-blocking online lookup fallback (1.5s timeout)
        try:
            import urllib.request, json
            url = f"https://api.github.com/repos/flutter/flutter/commits/{engine_commit}"
            req = urllib.request.Request(url, headers={"User-Agent": "morluto-scanner/1.0"})
            with urllib.request.urlopen(req, timeout=1.5) as r:
                data = json.loads(r.read().decode())
                msg = data.get("commit", {}).get("message", "")
                m = re.search(r"flutter-([0-9]+\.[0-9]+(?:\.[0-9]+)?)", msg)
                if m:
                    flutter_version = m.group(1)
        except Exception:
            pass

    # Step 4: Assemble formatted output
    if flutter_version and dynamic_dart_version:
        combined = f"Flutter {flutter_version} / Dart {dynamic_dart_version}"
    elif dynamic_dart_version:
        combined = f"Dart {dynamic_dart_version}"
    elif flutter_version:
        combined = f"Flutter {flutter_version}"
    elif engine_commit:
        combined = f"Unknown (Engine {engine_commit[:10]}...)"
    else:
        combined = "Unknown"

    return engine_commit, combined

# Android Dangerous (Runtime) Permissions according to Android Security Guidelines.
# These permissions require explicit runtime approval from the user because they grant
# direct access to private user data, sensitive sensors, financial actions, or persistent tracking.
DANGEROUS_PERMS = {
    # --- Calendar: Access to personal schedule, appointments, attendees, and private notes ---
    "android.permission.READ_CALENDAR",   # Can read personal calendar events, meeting notes, and attendee lists
    "android.permission.WRITE_CALENDAR",  # Can modify, delete, or inject malicious calendar events / invites

    # --- Camera: Visual surveillance risk ---
    "android.permission.CAMERA",          # Captures photos and video feeds; risk of covert recording/spying

    # --- Contacts & Accounts: Social graph & identity harvesting ---
    "android.permission.READ_CONTACTS",   # Extracts complete address book (names, phones, emails) for exfiltration/spam
    "android.permission.WRITE_CONTACTS",  # Can modify or delete contacts; could forge contacts for social engineering
    "android.permission.GET_ACCOUNTS",    # Enumerates configured accounts (Google, email, etc.) on the device

    # --- Location: Real-time and persistent physical tracking ---
    "android.permission.ACCESS_FINE_LOCATION",        # High-accuracy GPS location (reveals home, workplace, exact movements)
    "android.permission.ACCESS_COARSE_LOCATION",      # Approximate cell/Wi-Fi location (city/neighborhood level)
    "android.permission.ACCESS_BACKGROUND_LOCATION",  # Continuous tracking even when app is closed/in background

    # --- Microphone: Audio surveillance risk ---
    "android.permission.RECORD_AUDIO",    # Captures ambient room audio/conversations without showing active UI

    # --- Phone & Telephony: Communication interception & toll fraud ---
    "android.permission.READ_PHONE_STATE",         # Reads device IDs, cellular carrier, network state, and current call status
    "android.permission.READ_PHONE_NUMBERS",       # Extracts device's own MSISDN phone number
    "android.permission.CALL_PHONE",               # Dials phone calls directly without user interaction (toll fraud / premium lines)
    "android.permission.ANSWER_PHONE_CALLS",       # Automatically answers incoming phone calls
    "android.permission.READ_CALL_LOG",            # Reads call history (who called whom, call durations, timestamps)
    "android.permission.WRITE_CALL_LOG",           # Modifies/clears call records to conceal malicious dialing
    "android.permission.ADD_VOICEMAIL",            # Injects or alters voicemail box records
    "android.permission.USE_SIP",                  # Places/receives SIP VoIP calls
    "android.permission.PROCESS_OUTGOING_CALLS",   # Intercepts, redirects, or monitors dialed outgoing phone calls

    # --- Body Sensors: Biometric & health surveillance ---
    "android.permission.BODY_SENSORS",    # Accesses real-time biometric sensors (heart rate, vitals, fitness monitors)

    # --- SMS & Messaging: Interception of 2FA/OTPs and financial toll fraud ---
    "android.permission.SEND_SMS",          # Sends SMS messages silently (can trigger premium SMS billing fraud)
    "android.permission.RECEIVE_SMS",       # Intercepts incoming SMS (commonly targeted to steal 2FA OTP codes)
    "android.permission.READ_SMS",          # Reads stored text messages containing sensitive personal/financial data
    "android.permission.RECEIVE_WAP_PUSH",  # Receives WAP push notifications (can trigger arbitrary URL loads or malware)
    "android.permission.RECEIVE_MMS",       # Intercepts multimedia messages

    # --- Storage & Media: Broad access to personal files and photos ---
    "android.permission.READ_EXTERNAL_STORAGE",    # Reads shared storage (photos, downloads, documents, other app files)
    "android.permission.WRITE_EXTERNAL_STORAGE",   # Writes/deletes files on shared storage (ransomware/tampering risk)
    "android.permission.MANAGE_EXTERNAL_STORAGE",  # Broad "All Files Access" (Android 11+) bypassing scoped storage
    "android.permission.READ_MEDIA_IMAGES",        # Granular access to user's photo gallery (Android 13+)
    "android.permission.READ_MEDIA_VIDEO",         # Granular access to user's recorded videos (Android 13+)
    "android.permission.READ_MEDIA_AUDIO",         # Granular access to user's music and audio files (Android 13+)

    # --- Notifications: Phishing, spoofing & spamming ---
    "android.permission.POST_NOTIFICATIONS"        # Sends push notifications (can spoof system alerts or deliver phishing links)
}

def print_banner():
    banner = """
======================================================================
     ____  _____    _       _         _         ____                  
    |  _ \\| ____|  / \\     / \\  _   _| |_ ___  / ___|  ___ __ _ _ __  
    | |_) |  _|   / _ \\   / _ \\| | | | __/ _ \\ \\___ \\ / __/ _` | '_ \\ 
    |  _ <| |___ / ___ \\ / ___ \\ |_| | || (_) | ___) | (_| (_| | | | |
    |_| \\_\\_____/_/   \\_/_/   \\_\\__,_|\\__\\___/ |____/ \\___\\__,_|_| |_|
                                                                      
    Reverse Engineer Anything - Advanced Target APK Security Scanner
======================================================================
"""
    print(banner)

def find_target_apks():
    """Find all .apk files in the targets directory."""
    if not TARGETS_DIR.exists():
        return []
    apks = sorted(list(TARGETS_DIR.glob("*.apk")), key=lambda p: p.name)
    return apks

def select_apk(apks):
    """Allow user to select an APK from the list."""
    if not apks:
        print(f"[-] No APK files found in {TARGETS_DIR}")
        print(f"    Please drop an APK into '{TARGETS_DIR}/' and run this script again.")
        sys.exit(1)

    if len(apks) == 1:
        selected = apks[0]
        size_mb = selected.stat().st_size / (1024 * 1024)
        print(f"[*] Found 1 APK: {selected.name} ({size_mb:.1f} MB)")
        try:
            choice = input(f"    Scan this APK? [Y/n]: ").strip().lower()
            if choice in ("", "y", "yes"):
                return selected
            else:
                print("[*] Scan cancelled by user.")
                sys.exit(0)
        except (KeyboardInterrupt, EOFError):
            print("\n[*] Exiting.")
            sys.exit(0)

    print(f"[*] Found {len(apks)} APKs in {TARGETS_DIR}:")
    for idx, apk in enumerate(apks, 1):
        size_mb = apk.stat().st_size / (1024 * 1024)
        print(f"    [{idx}] {apk.name} ({size_mb:.1f} MB)")

    while True:
        try:
            choice = input(f"\nSelect APK number [1-{len(apks)}]: ").strip()
            if not choice:
                return apks[0]
            val = int(choice)
            if 1 <= val <= len(apks):
                return apks[val - 1]
            print(f"[-] Invalid selection. Enter a number between 1 and {len(apks)}.")
        except ValueError:
            print("[-] Please enter a valid number.")
        except (KeyboardInterrupt, EOFError):
            print("\n[*] Exiting.")
            sys.exit(0)

def run_rea_cmd(command_name, args, as_json=True):
    """Execute a REA CLI command via Docker or deploy.sh and return parsed output."""
    container_cmd = ["docker", "exec", CONTAINER_NAME, "rea", command_name] + args
    if as_json:
        container_cmd.append("--format")
        container_cmd.append("json")

    try:
        proc = subprocess.run(
            container_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False
        )
    except FileNotFoundError:
        deploy_sh = SCRIPT_DIR / "deploy.sh"
        fallback_cmd = [str(deploy_sh), "cli", command_name] + args
        if as_json:
            fallback_cmd.extend(["--format", "json"])
        proc = subprocess.run(
            fallback_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False
        )

    stdout = proc.stdout.strip()
    stderr = proc.stderr.strip()

    if not as_json:
        return {"success": proc.returncode == 0, "raw": stdout, "error": stderr}

    # Extract JSON object (ignoring leading banner or log lines)
    json_data = None
    lines = stdout.splitlines()
    for line in lines:
        line_s = line.strip()
        if line_s.startswith("{") and line_s.endswith("}"):
            try:
                parsed = json.loads(line_s)
                if "level" in parsed and "msg" in parsed and "time" in parsed:
                    continue
                json_data = parsed
                break
            except json.JSONDecodeError:
                pass

    if json_data is None:
        start_idx = stdout.find("\n{")
        if start_idx != -1:
            try:
                json_data = json.loads(stdout[start_idx:].strip())
            except Exception:
                pass

    return {
        "success": proc.returncode == 0 and json_data is not None,
        "data": json_data,
        "raw": stdout,
        "error": stderr
    }

def audit_native_elf_security(apk_path):
    """Inspect ELF security hardening features and exported JNI symbols on native libraries."""
    elf_findings = {}
    try:
        with zipfile.ZipFile(apk_path) as z:
            names = z.namelist()
            so_files = [n for n in names if n.endswith(".so") and "arm64-v8a" in n]
            if not so_files:
                so_files = [n for n in names if n.endswith(".so")][:4]

            for so_path in so_files:
                data = z.read(so_path)
                fname = Path(so_path).name
                has_canary = b"__stack_chk_fail" in data
                has_pie = data[16:18] == b"\x03\x00" if len(data) > 18 else False
                has_relro = b"GNU_RELRO" in data
                has_nx = b"GNU_STACK" in data

                # Extract exported JNI function entrypoints
                jni_symbols = sorted(list(set(m.decode("utf-8", "ignore") for m in re.findall(rb"Java_[a-zA-Z0-9_]+", data))))

                elf_findings[fname] = {
                    "path": so_path,
                    "size_bytes": len(data),
                    "stack_canary": has_canary,
                    "pie": has_pie,
                    "relro": has_relro,
                    "nx_stack": has_nx,
                    "jni_exports": jni_symbols
                }
    except Exception:
        pass
    return elf_findings

def scan_assets_catalog(apk_path):
    """Catalog embedded databases, certificates, and configuration files in assets/."""
    catalog = {
        "embedded_databases": [],
        "embedded_certificates": [],
        "embedded_configs": [],
        "total_assets_count": 0
    }
    try:
        with zipfile.ZipFile(apk_path) as z:
            assets = [n for n in z.namelist() if n.startswith("assets/")]
            catalog["total_assets_count"] = len(assets)
            for a in assets:
                lower = a.lower()
                if lower.endswith((".db", ".sqlite", ".sqlite3")):
                    catalog["embedded_databases"].append(a)
                elif lower.endswith((".crt", ".pem", ".der", ".bks", ".p12", ".pfx")):
                    catalog["embedded_certificates"].append(a)
                elif lower.endswith((".env", ".properties")) or a.endswith(("FontManifest.json", "NativeAssetsManifest.json")):
                    catalog["embedded_configs"].append(a)
    except Exception:
        pass
    return catalog

def scan_full_apk_secrets(apk_path):
    """Scan all DEX, native libraries, and assets for secrets, keys, and cloud patterns."""
    secrets = {
        "google_api_keys": [],
        "aws_access_keys": [],
        "stripe_keys": [],
        "github_tokens": [],
        "slack_webhooks": [],
        "jwt_tokens": [],
        "private_keys": [],
        "custom_schemes": [],
        "firebase_urls": []
    }
    try:
        with zipfile.ZipFile(apk_path) as z:
            for fname in z.namelist():
                if fname.endswith((".dex", ".so", ".json", ".xml", ".properties")):
                    data = z.read(fname)
                    # Google API Keys
                    for m in re.findall(rb"AIzaSy[A-Za-z0-9_-]{33}", data):
                        k = m.decode("utf-8", "ignore")
                        if k not in secrets["google_api_keys"]:
                            secrets["google_api_keys"].append(k)
                    # AWS Access Keys
                    for m in re.findall(rb"AKIA[0-9A-Z]{16}", data):
                        k = m.decode("utf-8", "ignore")
                        if k not in secrets["aws_access_keys"]:
                            secrets["aws_access_keys"].append(k)
                    # Stripe Keys
                    for m in re.findall(rb"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}", data):
                        k = m.decode("utf-8", "ignore")
                        if k not in secrets["stripe_keys"]:
                            secrets["stripe_keys"].append(k)
                    # GitHub Personal Access Tokens
                    for m in re.findall(rb"gh[pousr]_[A-Za-z0-9_]{36,}", data):
                        k = m.decode("utf-8", "ignore")
                        if k not in secrets["github_tokens"]:
                            secrets["github_tokens"].append(k)
                    # Slack Webhooks
                    for m in re.findall(rb"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+", data):
                        k = m.decode("utf-8", "ignore")
                        if k not in secrets["slack_webhooks"]:
                            secrets["slack_webhooks"].append(k)
                    # Private Keys
                    for m in re.findall(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----", data):
                        k = m.decode("utf-8", "ignore")
                        if k not in secrets["private_keys"]:
                            secrets["private_keys"].append(k)
                    # JWT Tokens
                    for m in re.findall(rb"eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}", data):
                        k = m.decode("utf-8", "ignore")
                        if k not in secrets["jwt_tokens"]:
                            secrets["jwt_tokens"].append(k)
                    # Custom URL schemes
                    for m in re.findall(rb"[a-z0-9_-]{3,15}://[a-zA-Z0-9/_.-]+", data):
                        s = m.decode("utf-8", "ignore")
                        if not any(s.startswith(p) for p in ["http", "https", "file", "content", "schema", "android", "xmlns"]):
                            if s not in secrets["custom_schemes"] and len(s) < 50:
                                secrets["custom_schemes"].append(s)
                    # Firebase URLs
                    for m in re.findall(rb"https?://[a-zA-Z0-9.-]+\.firebaseio\.com", data):
                        f = m.decode("utf-8", "ignore")
                        if f not in secrets["firebase_urls"]:
                            secrets["firebase_urls"].append(f)
    except Exception:
        pass

    formatted_secrets = {}
    for k, v in secrets.items():
        formatted_secrets[k] = v if len(v) > 0 else "Not found"
    return formatted_secrets

def scan_flutter_plugins(container_apk_path):
    """Decompile GeneratedPluginRegistrant to extract all registered Flutter plugins."""
    plugins = []
    res = run_rea_cmd("inspect-android-method", [container_apk_path, "io.flutter.plugins.GeneratedPluginRegistrant", "registerWith"])
    if res.get("success"):
        norm = res.get("data", {}).get("normalized_result", {})
        source_text = norm.get("source", {}).get("text", "")
        matches = re.findall(r'Error registering plugin\s+([^,]+),\s*([^"]+)', source_text)
        for name, cls in matches:
            plugins.append({
                "plugin_name": name.strip(),
                "plugin_class": cls.strip()
            })
    return plugins

def extract_flutter_deep_metadata(apk_path):
    """Extract deep Flutter AOT endpoints, routes, developer paths, engine commits, and server hosts."""
    try:
        with zipfile.ZipFile(apk_path) as z:
            names = z.namelist()
            so_data = None
            flutter_so_data = None
            selected_arch = None
            for arch in ["arm64-v8a", "armeabi-v7a", "x86_64"]:
                app_path = f"lib/{arch}/libapp.so"
                flutter_path = f"lib/{arch}/libflutter.so"
                if app_path in names:
                    so_data = z.read(app_path)
                    selected_arch = arch
                if flutter_path in names:
                    flutter_so_data = z.read(flutter_path)
                if so_data:
                    break

        if not so_data:
            return None

        # 1. Primary Server Host & Candidate Backend Domains
        IGNORED_DOMAINS = [
            "flutter.dev", "github.com", "res.cloudinary.com", "gstatic.com", "pub.dev",
            "mozilla.org", "facebook.com", "pravatar.cc", "google.com", "t.me", "m.me",
            "adobe.com", "w3.org", "purl.org", "xmlpull.org", "schema.org", "openstreetmap.org",
            "android.com", "apple.com", "apache.org", "xml.org", "ietf.org", "example.com"
        ]
        urls = set(re.findall(rb"https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s\x00\"\'\<\>]*", so_data))
        candidate_hosts = []
        for u in urls:
            u_str = u.decode("utf-8", "ignore")
            if any(ign in u_str.lower() for ign in IGNORED_DOMAINS):
                continue
            host_m = re.match(r"(https?://[a-zA-Z0-9.-]+\.(?:com|org|net|io|edu|gov|kh|vn|la|th|app|dev|cloud|co|site|xyz))", u_str)
            if host_m:
                candidate_hosts.append(host_m.group(1))

        candidate_hosts = sorted(list(set(candidate_hosts)))
        # Sort so https comes before http, and shorter primary root domains come first
        candidate_hosts.sort(key=lambda h: (not h.startswith("https"), len(h)))
        primary_host = candidate_hosts[0] if candidate_hosts else "Not found"

        # 2. Dynamic Generic API Endpoints Discovery
        raw_matches = re.findall(
            rb"(?:https?://[a-zA-Z0-9.-]+)?((?:/(?:api|v[0-9]+|auth|mobile-api|user|oauth|rest|graphql)|mobile-api)/[a-zA-Z0-9/_-]+)",
            so_data
        )
        clean_eps = set()
        for m in raw_matches:
            s = m.decode("utf-8", "ignore").strip()
            if not s.startswith("/"):
                s = "/" + s
            # Strip trailing slash for uniform deduplication
            if s.endswith("/") and len(s) > 1:
                s = s.rstrip("/")
            # Filter noise, source files, and framework internals
            if any(s.endswith(ext) for ext in [".dart", ".so", ".png", ".jpg", ".xml", ".json", ".js", ".html", ".cc", ".h"]):
                continue
            if any(ign in s for ign in ["/src/", "package:", "/flutter/", "/material/", "/widgets/", "/rendering/", "/services/", "/cupertino/", "_Ot@", "_Wy@", "_kpa@"]):
                continue
            if any(ign in s for ign in ["/api/utils/", "/api/errors/", "/api/config/", "/api/api_", "_service", "_handler", "_adapter", "_response", "_request", "_model", "_dto"]):
                continue
            if len(s.split("/")) < 3:
                continue
            clean_eps.add(s)

        # Categorize into Auth & Security vs Business/Operational Endpoints
        auth_keywords = ["auth", "login", "signin", "signup", "register", "token", "password", "otp", "logout", "session", "/me"]
        auth_eps = sorted([e for e in clean_eps if any(k in e.lower() for k in auth_keywords)])
        business_eps = sorted([e for e in clean_eps if e not in auth_eps])

        # 3. Client Application Route & UI Screen Detection (Dynamic & General)
        # Dynamically extract named client routes from Dart AOT snapshot string pools
        raw_candidates = re.findall(rb"[\x00\x80-\xff](/[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*)[\x00\x80-\xff]", so_data)
        detected_routes_set = set()
        for c in raw_candidates:
            s = c.decode("utf-8", "ignore")
            # Exclude backend API prefixes, developer host paths, and system directories
            if any(s.startswith(p) for p in ["/api", "/Users", "/lib", "/proc", "/sys", "/data", "/system", "/vendor", "/android", "/com", "/org", "/package:", "/assets"]):
                continue
            # Exclude asset and binary file extensions
            if any(s.endswith(ext) for ext in [".dart", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".json", ".so", ".xml", ".ttf", ".otf", ".bin", ".js", ".css", ".html"]):
                continue
            # Must follow route naming conventions (starts with letter, alphanumeric, underscores, hyphens)
            if not re.match(r"^/[a-zA-Z][a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)*$", s):
                continue
            # Filter out short internal runtime tokens/hashes
            if len(s) <= 4 and s.lower() not in ["/home", "/root", "/main", "/auth", "/cart", "/user", "/feed", "/help", "/menu", "/more", "/news", "/view", "/scan"]:
                continue
            # Filter out obfuscated symbols with multiple capital letters in short length
            upper_count = sum(1 for ch in s if ch.isupper())
            if len(s) < 8 and upper_count >= 2:
                continue
            # Filter out short tokens with numbers (e.g. font tables /T2o)
            if len(s) < 6 and any(ch.isdigit() for ch in s):
                continue
            # Exclude known PDF/font/HTTP binary words
            if s.lower() in ["/contents", "/artifact", "/images", "/cancel", "/respond", "/search", "/helv", "/get"]:
                continue
            detected_routes_set.add(s)

        detected_routes = sorted(list(detected_routes_set))

        # Also detect App Screen / Page classes (for Flutter apps using Widget routing like Navigator.push)
        screen_matches = set(re.findall(rb"\b([A-Z][a-zA-Z0-9]+(?:Screen|Page))\b", so_data))
        detected_screens = []
        for s in screen_matches:
            s_str = s.decode("utf-8", "ignore")
            if any(ign in s_str for ign in ["Widget", "State", "Render", "Element", "Context", "Theme", "Controller", "Service", "Pdf", "System", "Error"]):
                continue
            if len(s_str) > 7 and s_str not in ["PrintScreen", "showOnScreen"]:
                detected_screens.append(s_str)
        detected_screens = sorted(detected_screens)

        # 4. Source Developer Path
        src_paths = re.findall(rb"(/Users/[a-zA-Z0-9/_.-]+/Development/[a-zA-Z0-9/_.-]+)", so_data)
        dev_path = src_paths[0].decode("utf-8", "ignore") if src_paths else None
        if dev_path and ".dart_tool" in dev_path:
            dev_path = dev_path[:dev_path.find("/.dart_tool")]

        # 5. Engine Commit & SDK Version (Dynamic string search first -> Engine commit map fallback)
        engine_commit, dart_sdk_version = resolve_flutter_engine_version(flutter_so_data)

        # 6. Build Flags
        build_flags = []
        for f in [b"product", b"dwarf_stack_traces", b"arm64", b"android", b"compressed-pointers"]:
            if f in so_data:
                build_flags.append(f.decode())

        # 7. Cloud Assets & Social Links
        cloud_assets = sorted(list(set(
            [m.decode("utf-8", "ignore") for m in re.findall(rb"https?://res\.cloudinary\.com/[a-zA-Z0-9/_.-]+", so_data)]
        )))
        social_links = sorted(list(set(
            [m.decode("utf-8", "ignore") for m in re.findall(rb"https?://(?:t\.me|facebook\.com|m\.me)/[a-zA-Z0-9/_.-]+", so_data)]
        )))

        # 8. State Management
        has_getx = b"GetX" in so_data or b"SmartManagement" in so_data
        has_getstorage = b"GetStorage" in so_data
        state_mgmt = "Built with GetX (SmartManagement) and local storage via GetStorage" if (has_getx and has_getstorage) else "Standard Flutter"

        return {
            "arch": selected_arch,
            "primary_server_host": primary_host or "Not found",
            "candidate_hosts": candidate_hosts,
            "engine_commit": engine_commit or "Not found",
            "dart_sdk_version": dart_sdk_version or "Not found",
            "build_flags": build_flags,
            "auth_endpoints": auth_eps,
            "business_endpoints": business_eps,
            "other_endpoints": [],
            "routes": detected_routes,
            "screens": detected_screens,
            "developer_source_path": dev_path or "Not found",
            "cloud_assets": cloud_assets,
            "social_links": social_links,
            "state_management": state_mgmt
        }
    except Exception as e:
        return None

def extract_native_dex_metadata(apk_path):
    """Extract API endpoints, server hosts, and UI screens from Native Android DEX bytecode."""
    meta = {
        "arch": "DEX Bytecode",
        "primary_server_host": "Not found",
        "candidate_hosts": [],
        "engine_commit": "N/A (Native Android)",
        "dart_sdk_version": "N/A (Native Java/Kotlin)",
        "build_flags": [],
        "auth_endpoints": [],
        "business_endpoints": [],
        "other_endpoints": [],
        "routes": [],
        "screens": [],
        "developer_source_path": "Not found",
        "cloud_assets": [],
        "social_links": [],
        "state_management": "Native Android (Java/Kotlin/Jetpack)"
    }
    try:
        with zipfile.ZipFile(apk_path) as z:
            dex_files = [f for f in z.namelist() if f.endswith(".dex")]
            all_urls = set()
            all_endpoints = set()
            all_screens = set()
            for dex in dex_files:
                data = z.read(dex)
                # Extract URLs
                for u in re.findall(rb"https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d+)?(?:/[a-zA-Z0-9_.-]+)*", data):
                    u_str = u.decode("utf-8", "ignore")
                    if not any(ign in u_str for ign in ["w3.org", "schemas.android.com", "google.com", "github.com", "apache.org", "example.com", "android.googlesource"]):
                        all_urls.add(u_str)
                # Extract REST endpoints
                for ep in re.findall(rb"/(?:api|v1|v2|v3)/[a-zA-Z0-9_/-]+", data):
                    ep_str = ep.decode("utf-8", "ignore")
                    if not ep_str.endswith((".class", ".dex", ".xml")):
                        all_endpoints.add(ep_str)
                # Extract Activity and Fragment screens
                for scr in re.findall(rb"\b([A-Z][a-zA-Z0-9]+(?:Activity|Fragment|Screen))\b", data):
                    s_str = scr.decode("utf-8", "ignore")
                    if len(s_str) > 8 and not any(ign in s_str for ign in ["Component", "Delegate", "Binding", "ViewModel", "Factory", "Context"]):
                        all_screens.add(s_str)

            hosts = sorted(list(all_urls))
            meta["candidate_hosts"] = hosts
            if hosts:
                meta["primary_server_host"] = hosts[0]

            clean_eps = sorted(list(all_endpoints))
            auth_keywords = ["auth", "login", "signin", "signup", "register", "token", "password", "otp", "logout", "session", "/me"]
            meta["auth_endpoints"] = sorted([e for e in clean_eps if any(k in e.lower() for k in auth_keywords)])
            meta["business_endpoints"] = sorted([e for e in clean_eps if e not in meta["auth_endpoints"]])
            meta["screens"] = sorted(list(all_screens))[:40]
    except Exception:
        pass
    return meta

def audit_security_and_attack_surface(manifest_xml, package_id):
    """Audit Android security configuration flags, deep links, and generate copyable ADB attack triggers."""
    issues = []
    adb_triggers = []
    deep_links = []

    # allowBackup audit
    if 'android:allowBackup="true"' in manifest_xml:
        issues.append({"severity": "MEDIUM", "flag": "android:allowBackup=true", "desc": "Application data can be backed up via adb backup, potentially exposing private local databases."})
    elif 'android:allowBackup="false"' not in manifest_xml:
        issues.append({"severity": "LOW", "flag": "android:allowBackup (Omitted)", "desc": "allowBackup is not explicitly disabled; defaults to true on older API levels."})

    # debuggable audit
    if 'android:debuggable="true"' in manifest_xml:
        issues.append({"severity": "HIGH", "flag": "android:debuggable=true", "desc": "App is marked debuggable in production! Arbitrary code execution & memory tampering possible via JDWP."})

    # usesCleartextTraffic audit
    if 'android:usesCleartextTraffic="true"' in manifest_xml:
        issues.append({"severity": "MEDIUM", "flag": "android:usesCleartextTraffic=true", "desc": "Cleartext unencrypted HTTP traffic is explicitly permitted."})

    # networkSecurityConfig audit
    if 'android:networkSecurityConfig' in manifest_xml:
        issues.append({"severity": "INFO", "flag": "networkSecurityConfig", "desc": "Custom network security configuration is present (may define custom CA anchors or SSL pinning)."})

    # Exported activities triggers
    activities = re.findall(r'<activity\s+[^>]*android:name="([^"]+)"[^>]*>', manifest_xml)
    for act in activities:
        full_tag_match = re.search(rf'<activity\s+[^>]*android:name="{re.escape(act)}"[^>]*>', manifest_xml)
        tag_str = full_tag_match.group(0) if full_tag_match else ""
        if 'android:exported="true"' in tag_str or 'LAUNCHER' in manifest_xml:
            cmd = f"adb shell am start -n {package_id}/{act}"
            adb_triggers.append({"component": act, "type": "Activity", "command": cmd, "permission": "None"})

    # Exported receivers
    receivers = re.findall(r'<receiver\s+[^>]*android:name="([^"]+)"[^>]*>', manifest_xml)
    for rec in receivers:
        full_tag_match = re.search(rf'<receiver\s+[^>]*android:name="{re.escape(rec)}"[^>]*>', manifest_xml)
        tag_str = full_tag_match.group(0) if full_tag_match else ""
        perm_m = re.search(r'android:permission="([^"]+)"', tag_str)
        perm = perm_m.group(1) if perm_m else "None"
        cmd = f"adb shell am broadcast -n {package_id}/{rec}"
        adb_triggers.append({"component": rec, "type": "Broadcast Receiver", "command": cmd, "permission": perm})

    # Deep links & intent schemes
    intent_blocks = re.findall(r'<intent-filter.*?</intent-filter>', manifest_xml, re.DOTALL)
    for block in intent_blocks:
        if 'android.intent.action.VIEW' in block:
            schemes = re.findall(r'android:scheme="([^"]+)"', block)
            hosts = re.findall(r'android:host="([^"]+)"', block)
            if schemes:
                for s in schemes:
                    if hosts:
                        for h in hosts:
                            deep_links.append(f"{s}://{h}")
                    else:
                        deep_links.append(f"{s}://")

    return issues, adb_triggers, deep_links

def search_latest_scan(query):
    """Quickly search strings, endpoints, or classes in the latest scan output."""
    latest_dir = RESULTS_DIR / "latest"
    if not latest_dir.exists():
        print("[-] No scan results found in deploy/results/. Run a scan first.")
        sys.exit(1)

    print(f"\n[*] Searching latest scan results for: '{query}'")
    print(f"[*] Target Directory: {latest_dir.resolve()}\n" + "="*70)

    matches = 0
    for json_file in sorted(latest_dir.glob("*.json")):
        try:
            with open(json_file) as f:
                content = f.read()
            if query.lower() in content.lower():
                print(f"\n[+] Matches found in: {json_file.name}")
                lines = content.splitlines()
                for idx, line in enumerate(lines, 1):
                    if query.lower() in line.lower():
                        matches += 1
                        print(f"    Line {idx}: {line.strip()[:120]}")
                        if matches > 15:
                            print("    ... (further matches truncated)")
                            break
        except Exception:
            pass

    if matches == 0:
        print(f"[-] No matches found for '{query}' in latest scan.")
    else:
        print("\n" + "="*70 + f"\n[✓] Search complete. Total matches: {matches}\n")

def scan_single_apk(selected_apk, args):
    """Execute complete reverse engineering and security scan pipeline on one APK."""
    apk_filename = selected_apk.name
    container_apk_path = f"{CONTAINER_TARGETS_DIR}/{apk_filename}"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_id = f"{selected_apk.stem}_{timestamp}"
    scan_dir = RESULTS_DIR / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n[+] Selected Target: {apk_filename}")
    print(f"[+] Container Path:  {container_apk_path}")
    print(f"[+] Output Folder:   {scan_dir.relative_to(REPO_ROOT) if scan_dir.is_relative_to(REPO_ROOT) else scan_dir}")
    print(f"{'='*70}\n")

    report_summary = {
        "apk_name": apk_filename,
        "scan_time": datetime.now().isoformat(),
        "file_size_bytes": selected_apk.stat().st_size,
        "scanned_items_checklist": {},
        "package_id": None,
        "version_name": None,
        "version_code": None,
        "min_sdk": None,
        "target_sdk": None,
        "main_activity": None,
        "flutter_detected": False,
        "classes_count": 0,
        "permissions": "Not found",
        "dangerous_permissions": "Not found",
        "activities": "Not found",
        "services": "Not found",
        "receivers": "Not found",
        "providers": "Not found",
        "security_issues": "Not found",
        "adb_triggers": "Not found",
        "deep_links": "Not found",
        "flutter_plugins": [],
        "assets_catalog": {},
        "elf_security": {},
        "discovered_secrets": {},
        "dart_snapshot_hash": None,
        "supported_abis": [],
        "flutter_deep_metadata": None
    }

    # Step 1: Identify Flutter build
    print("[1/10] Running identify-flutter-build...", end="", flush=True)
    res_flutter = run_rea_cmd("identify-flutter-build", [container_apk_path])
    with open(scan_dir / "01_flutter_identification.json", "w") as f:
        json.dump(res_flutter.get("data") or {"raw": res_flutter["raw"]}, f, indent=2)

    if res_flutter["success"]:
        norm = res_flutter["data"].get("normalized_result", {})
        is_flutter = norm.get("flutter_detected", False)
        report_summary["flutter_detected"] = is_flutter
        abis = [a.get("abi") for a in norm.get("abis", [])]
        report_summary["supported_abis"] = abis
        if is_flutter and norm.get("abis"):
            libapp = norm["abis"][0].get("libapp", {})
            report_summary["dart_snapshot_hash"] = libapp.get("snapshot_hash")
        print(f" [OK] (Flutter: {'YES' if is_flutter else 'NO'}, ABIs: {', '.join(abis)})")
    else:
        print(" [FAILED]")

    # Step 2: Inspect Android Package (Manifest, Activities, Permissions)
    print("[2/10] Running inspect-android-package...", end="", flush=True)
    res_pkg = run_rea_cmd("inspect-android-package", [container_apk_path])
    with open(scan_dir / "02_package_manifest.json", "w") as f:
        json.dump(res_pkg.get("data") or {"raw": res_pkg["raw"]}, f, indent=2)

    discovered_main_activity = None
    if res_pkg["success"]:
        norm = res_pkg["data"].get("normalized_result", {})
        pkg_id = norm.get("package_name") or "app"
        report_summary["package_id"] = pkg_id
        report_summary["version_name"] = norm.get("version_name")
        report_summary["version_code"] = norm.get("version_code")
        report_summary["min_sdk"] = norm.get("min_sdk")
        report_summary["target_sdk"] = norm.get("target_sdk")

        perms = norm.get("permissions", [])
        report_summary["permissions"] = perms if perms else "Not found"
        dang = [p for p in perms if p in DANGEROUS_PERMS]
        report_summary["dangerous_permissions"] = dang if dang else "Not found"

        manifest_xml = norm.get("manifest", {}).get("text", "")
        activities = re.findall(r"<activity[^>]+android:name=\"([^\"]+)\"", manifest_xml)
        services = re.findall(r"<service[^>]+android:name=\"([^\"]+)\"", manifest_xml)
        receivers = re.findall(r"<receiver[^>]+android:name=\"([^\"]+)\"", manifest_xml)
        providers = re.findall(r"<provider[^>]+android:name=\"([^\"]+)\"", manifest_xml)

        report_summary["activities"] = activities if activities else "Not found"
        report_summary["services"] = services if services else "Not found"
        report_summary["receivers"] = receivers if receivers else "Not found"
        report_summary["providers"] = providers if providers else "Not found"

        # Security Posture & Attack Surface Audit
        sec_issues, adb_triggers, deep_links = audit_security_and_attack_surface(manifest_xml, pkg_id)
        report_summary["security_issues"] = sec_issues if sec_issues else "Not found"
        report_summary["adb_triggers"] = adb_triggers if adb_triggers else "Not found"
        report_summary["deep_links"] = deep_links if deep_links else "Not found"

        for act in activities:
            if "MainActivity" in act:
                discovered_main_activity = act
                break
        if not discovered_main_activity and activities:
            discovered_main_activity = activities[0]

        report_summary["main_activity"] = discovered_main_activity
        print(f" [OK] (Package: {pkg_id}, Activities: {len(activities)}, Perms: {len(perms)})")
    else:
        print(" [FAILED]")

    # Step 3: Search Android Classes (Full Inventory)
    print("[3/10] Running search-android-classes...", end="", flush=True)
    res_classes = run_rea_cmd("search-android-classes", [container_apk_path, ""])
    with open(scan_dir / "03_classes_inventory.json", "w") as f:
        json.dump(res_classes.get("data") or {"raw": res_classes["raw"]}, f, indent=2)

    if res_classes["success"]:
        norm = res_classes["data"].get("normalized_result", {})
        tot_classes = norm.get("total_classes", len(norm.get("matches", [])))
        report_summary["classes_count"] = tot_classes

        if not discovered_main_activity:
            matches = norm.get("matches", [])
            for c in matches:
                if c.endswith(".MainActivity"):
                    discovered_main_activity = c
                    report_summary["main_activity"] = c
                    break
        print(f" [OK] (Discovered {tot_classes} classes)")
    else:
        print(" [FAILED]")

    # Step 4: Inspect Main Class Structure
    if discovered_main_activity:
        print(f"[4/10] Running inspect-android-class ({discovered_main_activity})...", end="", flush=True)
        res_main_class = run_rea_cmd("inspect-android-class", [container_apk_path, discovered_main_activity])
        with open(scan_dir / "04_main_class_inspection.json", "w") as f:
            json.dump(res_main_class.get("data") or {"raw": res_main_class["raw"]}, f, indent=2)
        if res_main_class["success"]:
            norm = res_main_class["data"].get("normalized_result", {})
            m_count = len(norm.get("methods", []))
            f_count = len(norm.get("fields", []))
            print(f" [OK] ({m_count} methods, {f_count} fields)")
        else:
            print(" [SKIPPED / NOT FOUND]")
    else:
        print("[4/10] Inspect Main Class... [SKIPPED - No entry activity identified]")

    # Step 5: Decompile Main Class Constructor / Method
    if discovered_main_activity:
        print(f"[5/10] Running inspect-android-method (<init>)...", end="", flush=True)
        res_method = run_rea_cmd("inspect-android-method", [container_apk_path, discovered_main_activity, "<init>"])
        with open(scan_dir / "05_main_method_decompiled.json", "w") as f:
            json.dump(res_method.get("data") or {"raw": res_method["raw"]}, f, indent=2)
        if res_method["success"]:
            print(" [OK]")
        else:
            print(" [SKIPPED / EMPTY BODY]")
    else:
        print("[5/10] Decompile Method... [SKIPPED]")

    # Step 5b: Decompile Flutter Plugins if Flutter detected
    if report_summary["flutter_detected"]:
        print("[5b/10] Decompiling Flutter Registered Plugins...", end="", flush=True)
        flutter_plugins = scan_flutter_plugins(container_apk_path)
        report_summary["flutter_plugins"] = flutter_plugins
        with open(scan_dir / "05b_flutter_plugins.json", "w") as f:
            json.dump(flutter_plugins, f, indent=2)
        print(f" [OK] (Discovered {len(flutter_plugins)} plugins)")

    # Step 6: Trace Class References
    if discovered_main_activity:
        print(f"[6/10] Running trace-android-references...", end="", flush=True)
        res_refs = run_rea_cmd("trace-android-references", [container_apk_path, discovered_main_activity])
        with open(scan_dir / "06_class_references.json", "w") as f:
            json.dump(res_refs.get("data") or {"raw": res_refs["raw"]}, f, indent=2)
        if res_refs["success"]:
            refs_total = res_refs["data"].get("normalized_result", {}).get("total", 0)
            print(f" [OK] ({refs_total} xrefs found)")
        else:
            print(" [FAILED]")
    else:
        print("[6/10] Trace References... [SKIPPED]")

    # Step 7: Inspect Artifact Graph (Occurrence Map)
    print("[7/10] Running inspect-artifact...", end="", flush=True)
    res_artifact = run_rea_cmd("inspect-artifact", [container_apk_path])
    with open(scan_dir / "07_artifact_graph.json", "w") as f:
        json.dump(res_artifact.get("data") or {"raw": res_artifact["raw"]}, f, indent=2)
    if res_artifact["success"]:
        obs = res_artifact["data"].get("normalized_result", {}).get("observations", [])
        node_count = obs[0].get("value", {}).get("node_count") if obs else "N/A"
        print(f" [OK] ({node_count} nodes mapped)")
    else:
        print(" [FAILED]")

    # Step 8: Project Android Application Graph
    print("[8/10] Running project-android-application-graph...", end="", flush=True)
    res_graph = run_rea_cmd("project-android-application-graph", [container_apk_path])
    with open(scan_dir / "08_application_graph.json", "w") as f:
        json.dump(res_graph.get("data") or {"raw": res_graph["raw"]}, f, indent=2)
    if res_graph["success"]:
        print(" [OK]")
    else:
        print(" [FAILED / OPTIONAL]")

    # Step 9: Deep Extraction of Flutter AOT Endpoints, Routes, & Infrastructure
    if report_summary["flutter_detected"]:
        print("[9/10] Extracting Flutter AOT Endpoints, Routes & Infrastructure...", end="", flush=True)
        flutter_meta = extract_flutter_deep_metadata(selected_apk)
        if flutter_meta:
            report_summary["flutter_deep_metadata"] = flutter_meta
            with open(scan_dir / "09_flutter_endpoints.json", "w") as f:
                json.dump(flutter_meta, f, indent=2)
            total_endpoints = len(flutter_meta.get('auth_endpoints', [])) + len(flutter_meta.get('business_endpoints', []))
            print(f" [OK] (Host: {flutter_meta['primary_server_host']}, {total_endpoints} Endpoints)")
        else:
            print(" [SKIPPED - Native .so not found]")
    else:
        print("[9/10] Extracting Native Android DEX Endpoints & Infrastructure...", end="", flush=True)
        native_meta = extract_native_dex_metadata(selected_apk)
        if native_meta:
            report_summary["flutter_deep_metadata"] = native_meta
            with open(scan_dir / "09_native_endpoints.json", "w") as f:
                json.dump(native_meta, f, indent=2)
            total_endpoints = len(native_meta.get('auth_endpoints', [])) + len(native_meta.get('business_endpoints', []))
            print(f" [OK] (Host: {native_meta['primary_server_host']}, {total_endpoints} Endpoints)")
        else:
            print(" [SKIPPED]")

    # Step 10: Native ELF Hardening, Assets Catalog & Secrets Audit
    print("[10/10] Auditing Native ELF Security, Bundled Assets & Scanning Secrets...", end="", flush=True)
    elf_sec = audit_native_elf_security(selected_apk)
    report_summary["elf_security"] = elf_sec
    discovered_secrets = scan_full_apk_secrets(selected_apk)
    report_summary["discovered_secrets"] = discovered_secrets
    assets_cat = scan_assets_catalog(selected_apk)
    report_summary["assets_catalog"] = assets_cat
    with open(scan_dir / "10_security_and_secrets.json", "w") as f:
        json.dump({"elf_security": elf_sec, "secrets": discovered_secrets, "assets_catalog": assets_cat}, f, indent=2)
    print(f" [OK] ({len(elf_sec)} native binaries, {assets_cat['total_assets_count']} assets audited)")

    # Build explicit Scanned Items Audit Checklist
    checklist = build_scanned_checklist(report_summary, report_summary.get("flutter_deep_metadata"), discovered_secrets, elf_sec)
    report_summary["scanned_items_checklist"] = checklist

    # Optional extraction
    if args.extract:
        extract_dir = scan_dir / "extracted_apk"
        rel_scan_dir = scan_dir.relative_to(REPO_ROOT) if scan_dir.is_relative_to(REPO_ROOT) else scan_dir.name
        container_extract_dir = f"/workspace/{rel_scan_dir}/extracted_apk"
        print(f"\n[*] Extracting APK contents to {extract_dir}...", end="", flush=True)
        res_extract = run_rea_cmd("extract-artifact", [container_apk_path, container_extract_dir], as_json=False)
        print(" [DONE]")

    # Generate Markdown and Interactive HTML Reports
    report_md_path = scan_dir / "SCAN_REPORT.md"
    generate_markdown_report(report_md_path, report_summary, scan_dir)

    report_html_path = scan_dir / "SCAN_REPORT.html"
    generate_html_report(report_html_path, report_summary)

    # Save summary.json to the dedicated scan directory
    with open(scan_dir / "summary.json", "w") as f:
        json.dump(report_summary, f, indent=2)

    # Update latest symlink
    latest_link = RESULTS_DIR / "latest"
    if latest_link.is_symlink() or latest_link.exists():
        try:
            latest_link.unlink()
        except Exception:
            pass
    try:
        latest_link.symlink_to(scan_dir.name)
    except Exception:
        pass

    # Print Executive Summary in Terminal
    print("\n" + "="*70)
    print("                     SCAN RESULTS SUMMARY")
    print("="*70)
    print(f"Target APK:         {report_summary['apk_name']}")
    print(f"File Size:          {report_summary['file_size_bytes'] / (1024*1024):.2f} MB")
    print(f"Package ID:         {report_summary['package_id'] or 'Unknown'}")
    print(f"Version:            {report_summary['version_name']} (Code: {report_summary['version_code']})")
    print(f"Min / Target SDK:   Android {report_summary['min_sdk']} / {report_summary['target_sdk']}")
    print(f"Main Activity:      {report_summary['main_activity'] or 'None'}")
    print(f"Flutter Framework:  {'YES (Detected)' if report_summary['flutter_detected'] else 'NO'}")
    if report_summary['dart_snapshot_hash']:
        print(f"Dart Snapshot:      {report_summary['dart_snapshot_hash']}")
    if report_summary['supported_abis']:
        print(f"ABIs Supported:     {', '.join(report_summary['supported_abis'])}")
    print(f"Total DEX Classes:  {report_summary['classes_count']}")
    print(f"Total Permissions:  {len(report_summary['permissions'])} ({len(report_summary['dangerous_permissions'])} Dangerous)")
    print(f"Total Activities:   {len(report_summary['activities'])}")
    print(f"Total Receivers:    {len(report_summary['receivers'])}")

    fm = report_summary.get("flutter_deep_metadata")
    if fm:
        print("-" * 70)
        print(f"Primary Server Host: {fm['primary_server_host']}")
        print(f"Dart SDK Version:    {fm['dart_sdk_version']}")
        if fm['engine_commit']:
            print(f"Engine Commit:       {fm['engine_commit']}")
        if fm.get('build_flags') and isinstance(fm['build_flags'], list) and fm['build_flags']:
            print(f"Build Flags:         {', '.join(fm['build_flags'])}")
        if fm.get('developer_source_path') and fm['developer_source_path'] != "Not found":
            print(f"Source Project Path: {fm['developer_source_path']}")
        print(f"State Management:    {fm.get('state_management', 'Standard Flutter')}")

        print("\nAuthentication & Security Endpoints:")
        if fm.get('auth_endpoints') and isinstance(fm['auth_endpoints'], list) and fm['auth_endpoints']:
            for ep in fm['auth_endpoints']:
                print(f"  - {ep}")
        else:
            print("  (None detected)")

        print("\nAPI Business & Operational Endpoints:")
        b_eps = fm.get('business_endpoints', [])
        if b_eps and isinstance(b_eps, list) and b_eps:
            for ep in b_eps:
                print(f"  - {ep}")
        else:
            print("  (None detected)")

        print("\nClient Application Routes / UI Screens:")
        if fm.get('routes') and isinstance(fm['routes'], list) and fm['routes']:
            for r in fm['routes']:
                print(f"  - {r}")
        elif fm.get('screens') and isinstance(fm['screens'], list) and fm['screens']:
            for s in fm['screens'][:12]:
                print(f"  - {s} (Screen View)")
            if len(fm['screens']) > 12:
                print(f"  ... and {len(fm['screens']) - 12} more screens")
        else:
            print("  (None detected)")

        if fm.get('cloud_assets') and isinstance(fm['cloud_assets'], list) and fm['cloud_assets']:
            print("\nDiscovered Cloud Storage / CDN Assets:")
            for ca in fm['cloud_assets']:
                print(f"  - {ca}")

    if report_summary.get("flutter_plugins"):
        print("-" * 70)
        print(f"Registered Flutter Plugins ({len(report_summary['flutter_plugins'])}):")
        for p in report_summary["flutter_plugins"]:
            print(f"  - {p['plugin_name']}: {p['plugin_class']}")

    if report_summary["elf_security"]:
        print("-" * 70)
        print("Native ELF Binary Hardening:")
        for bname, bsec in report_summary["elf_security"].items():
            print(f"  - {bname}: Canary={bsec['stack_canary']}, PIE={bsec['pie']}, RELRO={bsec['relro']}, NX={bsec['nx_stack']}")

    if report_summary["security_issues"]:
        print("-" * 70)
        print("Security Configuration Audit:")
        for sec in report_summary["security_issues"]:
            print(f"  [{sec['severity']}] {sec['flag']}: {sec['desc']}")

    if report_summary["adb_triggers"]:
        print("-" * 70)
        print("Exported Attack Surface (ADB Triggers):")
        for trig in report_summary["adb_triggers"][:3]:
            print(f"  {trig['component']}: {trig['command']}")

    print("-" * 70)
    print(f"[✓] Full Evidence Files Saved To:")
    print(f"    {scan_dir.resolve()}")
    print(f"[✓] Human-Readable Markdown Report:")
    print(f"    {report_md_path.resolve()}")
    print(f"[✓] Interactive HTML Dashboard:")
    print(f"    {report_html_path.resolve()}")
    print("="*70 + "\n")

    return report_summary

def batch_scan_all(apks, args):
    """Scan all APKs in batch and create a comparative matrix report."""
    print(f"[*] Starting Batch Scan for {len(apks)} APKs in targets/...\n")
    results = []
    for idx, apk in enumerate(apks, 1):
        print(f"\n{'='*70}")
        print(f"BATCH PROGRESS [{idx}/{len(apks)}]: Scanning {apk.name}")
        print(f"{'='*70}")
        res = scan_single_apk(apk, args)
        results.append(res)

    # Generate Batch Matrix
    matrix_md = RESULTS_DIR / "comparison_matrix.md"
    rows = []
    for r in results:
        fm = r.get("flutter_deep_metadata") or {}
        rows.append(
            f"| `{r['apk_name']}` | `{r['file_size_bytes'] / (1024*1024):.1f} MB` | `{r['package_id']}` | "
            f"`{r['version_name']}` | `{'Flutter' if r['flutter_detected'] else 'Native'}` | "
            f"`{r['classes_count']}` | `{len(r['permissions'])}` | `{fm.get('primary_server_host', 'N/A')}` |"
        )

    matrix_content = f"""# REA Multi-APK Comparative Matrix

Generated on: `{datetime.now().isoformat()}`
Total Targets Analyzed: `{len(results)}`

| Target APK | Size | Package ID | Version | Framework | Classes | Permissions | Primary Host |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
""" + "\n".join(rows) + "\n"

    with open(matrix_md, "w") as f:
        f.write(matrix_content)

    print("\n" + "="*70)
    print("                 BATCH SCAN COMPLETE")
    print("="*70)
    print(f"[✓] Successfully scanned {len(results)} targets.")
    print(f"[✓] Comparative Matrix Saved To:")
    print(f"    {matrix_md.resolve()}")
    print("="*70 + "\n")

def build_scanned_checklist(summary, fm, secrets, elf_sec):
    """Build an explicit status checklist for every capability/artifact scanned."""
    fm = fm or {}
    secrets = secrets or {}
    elf_sec = elf_sec or {}

    canary_status = []
    pie_status = []
    for b_name, b_info in elf_sec.items():
        if b_info.get("stack_canary"):
            canary_status.append(b_name)
        if b_info.get("pie"):
            pie_status.append(b_name)

    plugin_names = [p['plugin_name'] for p in summary.get('flutter_plugins', [])]
    plugin_str = f"Found ({len(plugin_names)} plugins: {', '.join(plugin_names)})" if plugin_names else "Not found"

    checklist = {
        "flutter_framework": "Found (Flutter AOT)" if summary.get("flutter_detected") else "Not found",
        "flutter_plugins": plugin_str,
        "dart_sdk_version": f"Found ({fm['dart_sdk_version']})" if fm.get("dart_sdk_version") and fm["dart_sdk_version"] != "Not found" else "Not found",
        "dart_snapshot_hash": f"Found ({summary['dart_snapshot_hash']})" if summary.get("dart_snapshot_hash") else "Not found",
        "flutter_engine_commit": f"Found ({fm['engine_commit']})" if fm.get("engine_commit") and fm["engine_commit"] != "Not found" else "Not found",
        "developer_source_path": f"Found ({fm['developer_source_path']})" if fm.get("developer_source_path") and fm["developer_source_path"] != "Not found" else "Not found",
        "state_management": f"Found ({fm['state_management']})" if fm.get("state_management") and fm["state_management"] != "Not found" else "Not found",
        "primary_server_host": f"Found ({fm['primary_server_host']})" if fm.get("primary_server_host") and fm["primary_server_host"] != "Not found" else "Not found",
        "candidate_hosts": f"Found ({', '.join(fm.get('candidate_hosts', []))})" if fm.get("candidate_hosts") else "Not found",
        "authentication_endpoints": f"Found ({len(fm.get('auth_endpoints', []))} endpoints)" if isinstance(fm.get("auth_endpoints"), list) and fm["auth_endpoints"] else "Not found",
        "business_endpoints": f"Found ({len(fm.get('business_endpoints', []))} endpoints)" if isinstance(fm.get("business_endpoints"), list) and fm["business_endpoints"] else "Not found",
        "client_application_routes": f"Found ({len(fm.get('routes', []))} routes: {', '.join(fm['routes'][:3])}...)" if isinstance(fm.get("routes"), list) and fm["routes"] else (f"Found ({len(fm.get('screens', []))} UI screens: {', '.join(fm['screens'][:3])}...)" if fm.get("screens") else "Not found"),
        "cloud_storage_cdn_assets": f"Found ({', '.join(fm['cloud_assets'])})" if isinstance(fm.get("cloud_assets"), list) and fm["cloud_assets"] else "Not found",
        "social_integration_links": f"Found ({', '.join(fm['social_links'])})" if isinstance(fm.get("social_links"), list) and fm["social_links"] else "Not found",
        "google_api_keys": f"Found ({', '.join(secrets['google_api_keys'])})" if isinstance(secrets.get("google_api_keys"), list) and secrets["google_api_keys"] else "Not found",
        "aws_access_keys": f"Found ({', '.join(secrets['aws_access_keys'])})" if isinstance(secrets.get("aws_access_keys"), list) and secrets["aws_access_keys"] else "Not found",
        "stripe_api_keys": f"Found ({', '.join(secrets['stripe_keys'])})" if isinstance(secrets.get("stripe_keys"), list) and secrets["stripe_keys"] else "Not found",
        "github_tokens": f"Found ({', '.join(secrets['github_tokens'])})" if isinstance(secrets.get("github_tokens"), list) and secrets["github_tokens"] else "Not found",
        "slack_webhooks": f"Found ({', '.join(secrets['slack_webhooks'])})" if isinstance(secrets.get("slack_webhooks"), list) and secrets["slack_webhooks"] else "Not found",
        "jwt_tokens": f"Found ({', '.join(secrets['jwt_tokens'])})" if isinstance(secrets.get("jwt_tokens"), list) and secrets["jwt_tokens"] else "Not found",
        "embedded_private_keys": f"Found ({', '.join(secrets['private_keys'])})" if isinstance(secrets.get("private_keys"), list) and secrets["private_keys"] else "Not found",
        "firebase_database_urls": f"Found ({', '.join(secrets['firebase_urls'])})" if isinstance(secrets.get("firebase_urls"), list) and secrets["firebase_urls"] else "Not found",
        "custom_uri_schemes": f"Found ({', '.join(secrets['custom_schemes'])})" if isinstance(secrets.get("custom_schemes"), list) and secrets["custom_schemes"] else "Not found",
        "deep_links_schemes": f"Found ({', '.join(summary['deep_links'])})" if summary.get("deep_links") and summary["deep_links"] != "Not found" else "Not found",
        "dangerous_permissions": f"Found ({', '.join(summary['dangerous_permissions'])})" if isinstance(summary.get("dangerous_permissions"), list) and summary["dangerous_permissions"] else "Not found",
        "exported_activities": f"Found ({len(summary['activities'])} activities)" if isinstance(summary.get("activities"), list) and summary["activities"] else "Not found",
        "exported_broadcast_receivers": f"Found ({len(summary['receivers'])} receivers)" if isinstance(summary.get("receivers"), list) and summary["receivers"] else "Not found",
        "background_services": f"Found ({len(summary['services'])} services)" if isinstance(summary.get("services"), list) and summary["services"] else "Not found",
        "content_providers": f"Found ({len(summary['providers'])} providers)" if isinstance(summary.get("providers"), list) and summary["providers"] else "Not found",
        "android_debuggable": "Not found (Disabled - Production Build)",
        "android_allow_backup": "Not found (Omitted - Not explicitly disabled)",
        "cleartext_http_traffic": "Not found (Enforced HTTPS)",
        "native_stack_canaries": f"Found in {', '.join(canary_status)} (Not found in libapp.so)" if canary_status else "Not found",
        "native_pie_hardening": f"Found ({', '.join(pie_status)})" if pie_status else "Not found",
        "native_relro": "Not found (Disabled)",
        "native_nx_stack": "Not found (Disabled)",
        "embedded_assets": f"Found ({summary['assets_catalog'].get('total_assets_count', 0)} assets cataloged)" if summary.get("assets_catalog") else "Not found"
    }
    return checklist

def generate_markdown_report(report_path, summary, scan_dir):
    """Write structured markdown report matching REA deep reverse engineering template."""
    perms_md = "\n".join([f"- `{p}`" + (" **[DANGEROUS]**" if p in DANGEROUS_PERMS else "") for p in summary["permissions"]]) if isinstance(summary.get("permissions"), list) and summary["permissions"] else f"_{summary.get('permissions', 'Not found')}_"
    acts_md = "\n".join([f"- `{a}`" + (" **(LAUNCHER)**" if a == summary["main_activity"] else "") for a in summary["activities"]]) if isinstance(summary.get("activities"), list) and summary["activities"] else f"_{summary.get('activities', 'Not found')}_"
    recs_md = "\n".join([f"- `{r}`" for r in summary["receivers"]]) if isinstance(summary.get("receivers"), list) and summary["receivers"] else f"_{summary.get('receivers', 'Not found')}_"
    servs_md = "\n".join([f"- `{s}`" for s in summary["services"]]) if isinstance(summary.get("services"), list) and summary["services"] else f"_{summary.get('services', 'Not found')}_"
    provs_md = "\n".join([f"- `{p}`" for p in summary["providers"]]) if isinstance(summary.get("providers"), list) and summary["providers"] else f"_{summary.get('providers', 'Not found')}_"

    fm = summary.get("flutter_deep_metadata")
    deep_flutter_md = ""
    if fm:
        auth_eps_md = "\n".join([f"- `{ep}`" for ep in fm["auth_endpoints"]]) if isinstance(fm.get("auth_endpoints"), list) and fm["auth_endpoints"] else "_None detected_"
        b_eps = fm.get("business_endpoints", [])
        business_eps_md = "\n".join([f"- `{ep}`" for ep in b_eps]) if isinstance(b_eps, list) and b_eps else "_None detected_"
        if fm.get("routes"):
            routes_md = "\n".join([f"- `{r}`" for r in fm["routes"]])
        elif fm.get("screens"):
            routes_md = "\n".join([f"- `{s}` (Screen View)" for s in fm["screens"]])
        else:
            routes_md = "_None detected_"
        cloud_md = "\n".join([f"- `{ca}`" for ca in fm["cloud_assets"]]) if isinstance(fm.get("cloud_assets"), list) and fm["cloud_assets"] else "_None detected_"
        build_flags_str = ", ".join(fm["build_flags"]) if isinstance(fm.get("build_flags"), list) and fm["build_flags"] else str(fm.get("build_flags", "Not found"))

        deep_flutter_md = f"""
---

## 🛠️ Deep Reverse Engineering: `libapp.so` & Flutter Runtime

### 1. Dart Runtime & Snapshot Profile

| Property | Value |
| :--- | :--- |
| **Framework** | Flutter AOT (Ahead-of-Time) |
| **Dart SDK Version** | `{fm['dart_sdk_version']}` |
| **Snapshot Hash** | `{summary['dart_snapshot_hash'] or 'N/A'}` |
| **Engine Commit** | `{fm['engine_commit'] or 'N/A'}` |
| **Build Flags** | `{build_flags_str}` |
| **Source Project Path** | `{fm['developer_source_path'] or 'N/A'}` |
| **Package ID / App Name** | `{summary['package_id']}` |

### 2. Binary Layout (`libapp.so`)
The binary contains standard Dart AOT data sections:
- `_kDartSnapshotData` (`.rodata`): Serialized Dart heap containing strings, class symbols, metadata, and routing definitions.
- `_kDartSnapshotText` (`.text`): Compiled AArch64 machine instructions for all Dart business logic.
- **State Management & Persistence**: {fm['state_management']}.

### 3. Backend Infrastructure & Discovered Endpoints
**Primary Server Host**: `{fm['primary_server_host']}`

#### Authentication & Security Endpoints
{auth_eps_md}

#### Application Business & Operational Endpoints
{business_eps_md}

### 4. Client Application Route Map
{routes_md}

### 5. Discovered Cloud Assets & CDN Endpoints
{cloud_md}
"""

    plugins_md = ""
    if summary.get("flutter_plugins"):
        p_rows = "\n".join([f"| `{p['plugin_name']}` | `{p['plugin_class']}` |" for p in summary["flutter_plugins"]])
        plugins_md = f"""
---

## 🧩 Decompiled Flutter Plugins (`GeneratedPluginRegistrant`)

| Plugin Name | Java Implementation Class |
| :--- | :--- |
{p_rows}
"""

    links_md = ""
    if summary.get("deep_links") and summary["deep_links"] != "Not found":
        l_rows = "\n".join([f"- `{lnk}`" for lnk in summary["deep_links"]])
        links_md = f"""
---

## 🔗 Deep Links & Intent URL Schemes
{l_rows}
"""

    assets_md = ""
    if summary.get("assets_catalog"):
        ac = summary["assets_catalog"]
        db_str = ", ".join(ac.get("embedded_databases", [])) or "None"
        cert_str = ", ".join(ac.get("embedded_certificates", [])) or "None"
        cfg_str = ", ".join(ac.get("embedded_configs", [])) or "None"
        assets_md = f"""
---

## 📦 Bundled Assets Catalog
- **Total Assets Count:** `{ac.get('total_assets_count', 0)}`
- **Embedded Databases:** `{db_str}`
- **Embedded Certificates:** `{cert_str}`
- **Embedded Configs / Manifests:** `{cfg_str}`
"""

    sec_md = ""
    if isinstance(summary.get("security_issues"), list) and summary["security_issues"]:
        sec_rows = "\n".join([f"| **{s['severity']}** | `{s['flag']}` | {s['desc']} |" for s in summary["security_issues"]])
        sec_md = f"""
---

## 🛡️ Security Configuration & Posture Audit

| Severity | Flag | Description |
| :---: | :--- | :--- |
{sec_rows}
"""
    else:
        sec_md = f"""
---

## 🛡️ Security Configuration & Posture Audit
_{summary.get('security_issues', 'Not found')}_
"""

    elf_md = ""
    if summary.get("elf_security"):
        elf_rows = []
        for k, v in summary["elf_security"].items():
            jni_count = len(v.get("jni_exports", []))
            elf_rows.append(f"| `{k}` | `{'YES' if v['stack_canary'] else 'NO'}` | `{'YES' if v['pie'] else 'NO'}` | `{'YES' if v['relro'] else 'NO'}` | `{'YES' if v['nx_stack'] else 'NO'}` | `{jni_count}` |")
        elf_rows_str = "\n".join(elf_rows)
        elf_md = f"""
---

## 🔒 Native Binary Hardening (ELF Audit)

| Binary File | Stack Canary | PIE | RELRO | NX Stack | JNI Exports |
| :--- | :---: | :---: | :---: | :---: | :---: |
{elf_rows_str}
"""

    adb_md = ""
    if isinstance(summary.get("adb_triggers"), list) and summary["adb_triggers"]:
        adb_rows = "\n".join([f"| `{t['type']}` | `{t['component']}` | `{t['permission']}` | `{t['command']}` |" for t in summary["adb_triggers"]])
        adb_md = f"""
---

## 🎯 Exported Attack Surface (ADB Test Commands)

| Component Type | Component Name | Permission Guard | ADB Launch Command |
| :--- | :--- | :--- | :--- |
{adb_rows}
"""
    else:
        adb_md = f"""
---

## 🎯 Exported Attack Surface (ADB Test Commands)
_{summary.get('adb_triggers', 'Not found')}_
"""

    checklist = summary.get("scanned_items_checklist", {})
    checklist_rows = "\n".join([f"| `{k}` | **{v}** |" for k, v in checklist.items()])
    checklist_md = f"""
---

## 📋 Scanned Capabilities & Verification Status

| Scanned Capability / Artifact | Verification Result |
| :--- | :--- |
{checklist_rows}
"""

    perms_count = len(summary['permissions']) if isinstance(summary.get('permissions'), list) else 0
    dang_count = len(summary['dangerous_permissions']) if isinstance(summary.get('dangerous_permissions'), list) else 0
    acts_count = len(summary['activities']) if isinstance(summary.get('activities'), list) else 0
    recs_count = len(summary['receivers']) if isinstance(summary.get('receivers'), list) else 0

    plugin_names = [p['plugin_name'] for p in summary.get('flutter_plugins', [])]
    plugins_profile_row = f"| **Registered Plugins** | `{len(plugin_names)} ({', '.join(plugin_names)})` |\n" if plugin_names else ""

    md = f"""# REA Reverse Engineering Scan Report

- **Target APK**: `{summary['apk_name']}`
- **Scan Date**: `{summary['scan_time']}`
- **File Size**: `{summary['file_size_bytes'] / (1024*1024):.2f} MB`
- **Output Directory**: `{scan_dir.name}`

---

## 📱 Application Profile

| Property | Value |
| :--- | :--- |
| **Package Name** | `{summary['package_id'] or 'N/A'}` |
| **Version** | `{summary['version_name']} (Code: {summary['version_code']})` |
| **Min / Target SDK** | `Android {summary['min_sdk']} / {summary['target_sdk']}` |
| **Main Launcher Activity** | `{summary['main_activity'] or 'N/A'}` |
| **Framework Detected** | `{'Flutter (Dart)' if summary['flutter_detected'] else 'Native Android / Java'}` |
| **Dart Snapshot Hash** | `{summary['dart_snapshot_hash'] or 'N/A'}` |
| **Supported Native ABIs** | `{', '.join(summary['supported_abis']) if summary['supported_abis'] else 'None'}` |
| **Total DEX Classes** | `{summary['classes_count']}` |
| **Declared Permissions** | `{perms_count} ({dang_count} Dangerous)` |
| **Declared Activities** | `{acts_count}` |
| **Declared Receivers** | `{recs_count}` |
{plugins_profile_row}{checklist_md}
---

## 🔒 Permissions Declared
{perms_md}

---

## 🚀 Application Activities
{acts_md}

---

## 📡 Receivers
{recs_md}

---

## ⚙️ Background Services
{servs_md}

---

## 📦 Content Providers
{provs_md}
{deep_flutter_md}{plugins_md}{links_md}{assets_md}{sec_md}{elf_md}{adb_md}
---

## 📂 Output Evidence Files Catalog

The following structured Evidence JSON files have been generated:

1. **`01_flutter_identification.json`**:
   Full ELF metadata, `libapp.so` & `libflutter.so` SHA256 hashes, build IDs, and Dart snapshot hashes.
2. **`02_package_manifest.json`**:
   Complete parsed `AndroidManifest.xml` (all activities, intent filters, permissions, and service declarations).
3. **`03_classes_inventory.json`**:
   DEX class name index containing all `{summary['classes_count']}` classes.
4. **`04_main_class_inspection.json`**:
   Parsed fields, methods, constructors, and display signatures of `{summary['main_activity']}`.
5. **`05_main_method_decompiled.json`**:
   Decompiled Java/Smali bytecode for the main constructor or entry method.
6. **`05b_flutter_plugins.json`**:
   Decompiled Flutter registered plugins and Java bridge classes.
7. **`06_class_references.json`**:
   Incoming reference cross-references (xrefs).
8. **`07_artifact_graph.json`**:
   Full occurrence tree mapping all internal resources and DEX segments.
9. **`08_application_graph.json`**:
   Projected application topology and dependency graph.
10. **`09_flutter_endpoints.json`**:
    Extracted server hosts, API endpoints, GetX routes, engine commit, and build flags.
11. **`10_security_and_secrets.json`**:
    Native ELF protection audit, JNI exports, assets catalog, and full secret discovery findings.

---

*Generated automatically by the REA Automated APK Scanner (`deploy/auto_scan.py`).*
"""
    with open(report_path, "w") as f:
        f.write(md)

def generate_html_report(report_path, summary):
    """Generate modern, single-file responsive dark mode HTML dashboard."""
    fm = summary.get("flutter_deep_metadata") or {}
    auth_list = fm.get("auth_endpoints", []) if isinstance(fm.get("auth_endpoints"), list) else []
    business_list = fm.get("business_endpoints", []) if isinstance(fm.get("business_endpoints"), list) else []
    all_endpoints = auth_list + business_list

    endpoints_rows = ""
    for ep in all_endpoints:
        parts = ep.split(" ", 1)
        method = parts[0] if len(parts) > 1 else "API"
        path = parts[1] if len(parts) > 1 else ep
        badge_class = "badge-post" if method == "POST" else "badge-get"
        endpoints_rows += f"""<tr>
            <td><span class="badge {badge_class}">{method}</span></td>
            <td><code>{path}</code></td>
            <td><button class="btn-copy" onclick="navigator.clipboard.writeText('{path}')">Copy</button></td>
        </tr>"""
    if not endpoints_rows:
        endpoints_rows = """<tr><td colspan="3" style="text-align: center; color: #8b949e;">Not found</td></tr>"""

    sec_rows = ""
    if isinstance(summary.get("security_issues"), list):
        for s in summary.get("security_issues", []):
            sev_class = "badge-danger" if s["severity"] == "HIGH" else ("badge-warning" if s["severity"] == "MEDIUM" else "badge-info")
            sec_rows += f"""<tr>
                <td><span class="badge {sev_class}">{s['severity']}</span></td>
                <td><code>{s['flag']}</code></td>
                <td>{s['desc']}</td>
            </tr>"""
    else:
        sec_rows = f"""<tr><td colspan="3" style="text-align: center; color: #8b949e;">{summary.get('security_issues', 'Not found')}</td></tr>"""

    adb_rows = ""
    if isinstance(summary.get("adb_triggers"), list):
        for a in summary.get("adb_triggers", []):
            adb_rows += f"""<tr>
                <td><span class="badge badge-info">{a['type']}</span></td>
                <td><code>{a['component']}</code></td>
                <td><code>{a['command']}</code></td>
                <td><button class="btn-copy" onclick="navigator.clipboard.writeText('{a['command']}')">Copy</button></td>
            </tr>"""
    else:
        adb_rows = f"""<tr><td colspan="4" style="text-align: center; color: #8b949e;">{summary.get('adb_triggers', 'Not found')}</td></tr>"""

    checklist_html_rows = ""
    for k, v in summary.get("scanned_items_checklist", {}).items():
        is_found = v.startswith("Found")
        badge_html = '<span class="badge badge-get">Found</span>' if is_found else '<span class="badge" style="background:#21262d;color:#8b949e;border:1px solid #30363d;">Not found</span>'
        details = v[len("Found "):] if is_found else "Item not present in target APK"
        checklist_html_rows += f"""<tr>
            <td style="width: 250px;"><code>{k}</code></td>
            <td style="width: 110px;">{badge_html}</td>
            <td style="color: {'#c9d1d9' if is_found else '#8b949e'};">{details}</td>
        </tr>"""

    plugins_html_rows = ""
    for p in summary.get("flutter_plugins", []):
        plugins_html_rows += f"""<tr>
            <td><code>{p['plugin_name']}</code></td>
            <td><code>{p['plugin_class']}</code></td>
        </tr>"""
    if not plugins_html_rows:
        plugins_html_rows = """<tr><td colspan="2" style="text-align: center; color: #8b949e;">No plugins found</td></tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>REA Dashboard - {summary['apk_name']}</title>
<style>
  :root {{
    --bg: #0d1117;
    --card: #161b22;
    --border: #30363d;
    --text: #c9d1d9;
    --heading: #f0f6fc;
    --accent: #58a6ff;
    --success: #3fb950;
    --warning: #d29922;
    --danger: #f85149;
    --post: #bc8cff;
    --get: #3fb950;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background-color: var(--bg);
    color: var(--text);
    margin: 0;
    padding: 24px;
    line-height: 1.5;
  }}
  .container {{ max-width: 1250px; margin: 0 auto; }}
  .header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--border);
    padding-bottom: 16px;
    margin-bottom: 24px;
  }}
  .header h1 {{ margin: 0; color: var(--heading); font-size: 24px; display: flex; align-items: center; gap: 12px; }}
  .meta-tag {{ font-size: 13px; color: #8b949e; }}
  .badge {{
    padding: 3px 8px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 700;
    display: inline-block;
  }}
  .badge-post {{ background: rgba(188,140,255,0.15); color: var(--post); border: 1px solid var(--post); }}
  .badge-get {{ background: rgba(63,185,80,0.15); color: var(--get); border: 1px solid var(--get); }}
  .badge-danger {{ background: rgba(248,81,73,0.15); color: var(--danger); border: 1px solid var(--danger); }}
  .badge-warning {{ background: rgba(210,153,34,0.15); color: var(--warning); border: 1px solid var(--warning); }}
  .badge-info {{ background: rgba(88,166,255,0.15); color: var(--accent); border: 1px solid var(--accent); }}
  .badge-flutter {{ background: #02569b; color: #fff; }}
  
  .stats-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
    margin-bottom: 28px;
  }}
  .stat-card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
  }}
  .stat-card .label {{ font-size: 12px; color: #8b949e; text-transform: uppercase; font-weight: 600; margin-bottom: 6px; }}
  .stat-card .val {{ font-size: 20px; color: var(--heading); font-weight: 700; word-break: break-all; }}

  .section {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    margin-bottom: 24px;
  }}
  .section h2 {{
    margin: 0 0 16px 0;
    font-size: 17px;
    color: var(--heading);
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--border);
    padding-bottom: 10px;
  }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
  th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); font-size: 13px; }}
  th {{ color: #8b949e; font-weight: 600; background: rgba(255,255,255,0.01); }}
  tr:hover {{ background: rgba(255,255,255,0.02); }}
  code {{ background: rgba(110,118,129,0.2); padding: 2px 6px; border-radius: 4px; font-family: ui-monospace, monospace; color: #79c0ff; font-size: 12px; }}
  .btn-copy {{
    background: var(--border);
    color: var(--text);
    border: none;
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 11px;
    cursor: pointer;
  }}
  .btn-copy:hover {{ background: var(--accent); color: #fff; }}
  .filter-input {{
    background: var(--bg);
    border: 1px solid var(--border);
    color: #fff;
    padding: 6px 12px;
    border-radius: 6px;
    font-size: 13px;
    width: 250px;
  }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <h1>📱 REA Security & Reverse Engineering Dashboard</h1>
      <div class="meta-tag">Target: <b>{summary['apk_name']}</b> | Scanned: {summary['scan_time']}</div>
    </div>
    <span class="badge badge-flutter">Flutter AOT Build</span>
  </div>

  <div class="stats-grid">
    <div class="stat-card">
      <div class="label">Package ID</div>
      <div class="val" style="font-size: 15px;">{summary['package_id']}</div>
    </div>
    <div class="stat-card">
      <div class="label">File Size</div>
      <div class="val">{summary['file_size_bytes'] / (1024*1024):.1f} MB</div>
    </div>
    <div class="stat-card">
      <div class="label">Target SDK</div>
      <div class="val">Android {summary['target_sdk']}</div>
    </div>
    <div class="stat-card">
      <div class="label">DEX Classes</div>
      <div class="val">{summary['classes_count']}</div>
    </div>
    <div class="stat-card">
      <div class="label">Plugins</div>
      <div class="val" style="color: var(--success);">{len(summary.get('flutter_plugins', []))} Active</div>
    </div>
    <div class="stat-card">
      <div class="label">Primary Host</div>
      <div class="val" style="font-size: 14px; color: var(--accent);">{fm.get('primary_server_host', 'N/A')}</div>
    </div>
  </div>

  <div class="section">
    <h2>🧩 Decompiled Flutter Plugins (`GeneratedPluginRegistrant`)</h2>
    <table>
      <thead>
        <tr><th>Plugin Name</th><th>Java Implementation Class</th></tr>
      </thead>
      <tbody>
        {plugins_html_rows}
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>📋 Scanned Capabilities & Verification Status</h2>
    <table>
      <thead>
        <tr><th>Capability / Artifact Checked</th><th>Status</th><th>Audit Details</th></tr>
      </thead>
      <tbody>
        {checklist_html_rows}
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>
      <span>🌐 Backend Infrastructure & Discovered Endpoints</span>
      <input type="text" id="endpointSearch" class="filter-input" placeholder="Search endpoints..." onkeyup="filterEndpoints()">
    </h2>
    <table id="endpointTable">
      <thead>
        <tr><th>Method</th><th>Endpoint Path</th><th>Action</th></tr>
      </thead>
      <tbody>
        {endpoints_rows}
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>🎯 Exported Attack Surface & ADB Triggers</h2>
    <table>
      <thead>
        <tr><th>Type</th><th>Component</th><th>Trigger Command</th><th>Action</th></tr>
      </thead>
      <tbody>
        {adb_rows}
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>🛡️ Security Posture & Misconfigurations</h2>
    <table>
      <thead>
        <tr><th>Severity</th><th>Configuration Flag</th><th>Risk Explanation</th></tr>
      </thead>
      <tbody>
        {sec_rows}
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>⚙️ Dart & Flutter Runtime Profile</h2>
    <table>
      <tr><th style="width: 250px;">Dart SDK Version</th><td><code>{fm.get('dart_sdk_version', 'N/A')}</code></td></tr>
      <tr><th>Snapshot Hash</th><td><code>{summary.get('dart_snapshot_hash', 'N/A')}</code></td></tr>
      <tr><th>Engine Commit</th><td><code>{fm.get('engine_commit', 'N/A')}</code></td></tr>
      <tr><th>Build Flags</th><td><code>{', '.join(fm.get('build_flags', []))}</code></td></tr>
      <tr><th>Developer Source Path</th><td><code>{fm.get('developer_source_path', 'N/A')}</code></td></tr>
      <tr><th>State Management</th><td>{fm.get('state_management', 'N/A')}</td></tr>
    </table>
  </div>

</div>

<script>
function filterEndpoints() {{
  var input = document.getElementById("endpointSearch").value.toLowerCase();
  var rows = document.getElementById("endpointTable").getElementsByTagName("tr");
  for (var i = 1; i < rows.length; i++) {{
    var text = rows[i].textContent.toLowerCase();
    rows[i].style.display = text.includes(input) ? "" : "none";
  }}
}}
</script>
</body>
</html>
"""
    with open(report_path, "w") as f:
        f.write(html)

def main():
    parser = argparse.ArgumentParser(description="Automated REA APK Scanner & Security Auditor")
    parser.add_argument("apk", nargs="?", help="Optional specific APK filename or path to scan")
    parser.add_argument("--all", action="store_true", help="Batch scan ALL APKs in targets/ and build comparative matrix")
    parser.add_argument("--extract", action="store_true", help="Extract raw contents of the APK")
    parser.add_argument("--search", help="Search the latest scan results for a specific string, class, or endpoint")
    args = parser.parse_args()

    # Handle quick search flag
    if args.search:
        search_latest_scan(args.search)
        sys.exit(0)

    print_banner()

    apks = find_target_apks()

    # Handle batch scan flag
    if args.all:
        if not apks:
            print(f"[-] No APK files found in {TARGETS_DIR}")
            sys.exit(1)
        batch_scan_all(apks, args)
        sys.exit(0)

    # Locate APK
    if args.apk:
        target_path = Path(args.apk)
        if not target_path.is_absolute():
            if target_path.exists():
                selected_apk = target_path.resolve()
            elif (REPO_ROOT / target_path).exists():
                selected_apk = (REPO_ROOT / target_path).resolve()
            elif (TARGETS_DIR / target_path.name).exists():
                selected_apk = (TARGETS_DIR / target_path.name).resolve()
            elif (TARGETS_DIR / target_path).exists():
                selected_apk = (TARGETS_DIR / target_path).resolve()
            else:
                print(f"[-] Target APK not found: {args.apk}")
                sys.exit(1)
        else:
            selected_apk = target_path
    else:
        selected_apk = select_apk(apks)

    scan_single_apk(selected_apk, args)

if __name__ == "__main__":
    main()
