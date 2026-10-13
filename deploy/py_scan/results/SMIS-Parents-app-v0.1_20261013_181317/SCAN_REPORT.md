# REA Reverse Engineering Scan Report

- **Target APK**: `SMIS-Parents-app-v0.1.apk`
- **Scan Date**: `2026-10-13T18:13:17.137358`
- **File Size**: `56.96 MB`
- **Output Directory**: `SMIS-Parents-app-v0.1_20261013_181317`

---

## 📱 Application Profile

| Property                   | Value                              |
| :------------------------- | :--------------------------------- |
| **Package Name**           | `com.cspp_mobiles.dev`             |
| **Version**                | `1.0.0 (Code: 4)`                  |
| **Min / Target SDK**       | `Android 24 / 36`                  |
| **Main Launcher Activity** | `com.cspp_mobiles.MainActivity`    |
| **Framework Detected**     | `Flutter (Dart)`                   |
| **Dart Snapshot Hash**     | `0451907c2eaa8467e848c0067bfe8ed4` |
| **Supported Native ABIs**  | `arm64-v8a, armeabi-v7a, x86_64`   |
| **Total DEX Classes**      | `686`                              |
| **Declared Permissions**   | `3 (1 Dangerous)`                  |
| **Declared Activities**    | `2`                                |
| **Declared Receivers**     | `1`                                |

---

## 📋 Scanned Capabilities & Verification Status

| Scanned Capability / Artifact  | Verification Result                                                                            |
| :----------------------------- | :--------------------------------------------------------------------------------------------- |
| `flutter_framework`            | **Found (Flutter AOT)**                                                                        |
| `dart_sdk_version`             | **Found (3.13.4)**                                                                             |
| `dart_snapshot_hash`           | **Found (0451907c2eaa8467e848c0067bfe8ed4)**                                                   |
| `flutter_engine_commit`        | **Found (af7e796e161ae0bb1ff0758c71a7105418bd9ded)**                                           |
| `developer_source_path`        | **Found (/Users/meanpheakdey/MPTC/Development/mptc-schoolis-flutter-app)**                     |
| `state_management`             | **Found (Built with GetX (SmartManagement) and local storage via GetStorage)**                 |
| `primary_server_host`          | **Found (https://devsmn.tele-ict.com)**                                                        |
| `authentication_endpoints`     | **Found (6 endpoints)**                                                                        |
| `student_academic_endpoints`   | **Found (8 endpoints)**                                                                        |
| `client_application_routes`    | **Found (6 routes: /loginparen, /loginstudent, /parent...)**                                   |
| `cloud_storage_cdn_assets`     | **Found (https://res.cloudinary.com/kdey/image/upload/v1767948582/Rectangle_6888_jaeua7.png)** |
| `social_integration_links`     | **Found (https://facebook.com/profile.php)**                                                   |
| `google_api_keys`              | **Not found**                                                                                  |
| `aws_access_keys`              | **Not found**                                                                                  |
| `jwt_tokens`                   | **Not found**                                                                                  |
| `embedded_private_keys`        | **Not found**                                                                                  |
| `firebase_database_urls`       | **Not found**                                                                                  |
| `custom_uri_schemes`           | **Found (fb-messenger://user/)**                                                               |
| `dangerous_permissions`        | **Found (android.permission.POST_NOTIFICATIONS)**                                              |
| `exported_activities`          | **Found (2 activities)**                                                                       |
| `exported_broadcast_receivers` | **Found (1 receivers)**                                                                        |
| `background_services`          | **Not found**                                                                                  |
| `content_providers`            | **Found (1 providers)**                                                                        |
| `android_debuggable`           | **Not found (Disabled - Production Build)**                                                    |
| `android_allow_backup`         | **Not found (Omitted - Not explicitly disabled)**                                              |
| `cleartext_http_traffic`       | **Not found (Enforced HTTPS)**                                                                 |
| `native_stack_canaries`        | **Found in libdartjni.so, libflutter.so (Not found in libapp.so)**                             |
| `native_pie_hardening`         | **Found (libapp.so, libdartjni.so, libflutter.so)**                                            |
| `native_relro`                 | **Not found (Disabled)**                                                                       |
| `native_nx_stack`              | **Not found (Disabled)**                                                                       |

---

## 🔒 Permissions Declared

- `android.permission.INTERNET`
- `android.permission.POST_NOTIFICATIONS` **[DANGEROUS]**
- `com.cspp_mobiles.dev.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION`

---

## 🚀 Application Activities

- `com.cspp_mobiles.MainActivity` **(LAUNCHER)**
- `io.flutter.plugins.urllauncher.WebViewActivity`

---

## 📡 Receivers

- `androidx.profileinstaller.ProfileInstallReceiver`

---

## ⚙️ Background Services

_Not found_

---

## 📦 Content Providers

- `androidx.startup.InitializationProvider`

---

## 🛠️ Deep Reverse Engineering: `libapp.so` & Flutter Runtime

### 1. Dart Runtime & Snapshot Profile

| Property                  | Value                                                              |
| :------------------------ | :----------------------------------------------------------------- |
| **Framework**             | Flutter AOT (Ahead-of-Time)                                        |
| **Dart SDK Version**      | `3.13.4`                                                           |
| **Snapshot Hash**         | `0451907c2eaa8467e848c0067bfe8ed4`                                 |
| **Engine Commit**         | `af7e796e161ae0bb1ff0758c71a7105418bd9ded`                         |
| **Build Flags**           | `product, dwarf_stack_traces, arm64, android, compressed-pointers` |
| **Source Project Path**   | `/Users/meanpheakdey/MPTC/Development/mptc-schoolis-flutter-app`   |
| **Package ID / App Name** | `com.cspp_mobiles.dev`                                             |

### 2. Binary Layout (`libapp.so`)

The binary contains standard Dart AOT data sections:

- `_kDartSnapshotData` (`.rodata`): Serialized Dart heap containing strings, class symbols, metadata, and routing definitions.
- `_kDartSnapshotText` (`.text`): Compiled AArch64 machine instructions for all Dart business logic.
- **State Management & Persistence**: Built with GetX (SmartManagement) and local storage via GetStorage.

### 3. Backend Infrastructure & Discovered Endpoints

**Primary Server Host**: `https://devsmn.tele-ict.com`

#### Authentication & Security

- POST /api/v2/auth/signIn/parent/username (Parent login flow)
- POST mobile-api/auth/sign-in/student (Student login flow)
- POST mobile-api/auth/sign-in/email/otp (OTP verification)
- POST mobile-api/auth/refresh-token
- POST mobile-api/auth/password/change
- POST mobile-api/auth/logout

#### Student, Academic & Operations

- GET mobile-api/student/home
- GET mobile-api/student/profile
- GET mobile-api/student/preferences
- GET mobile-api/student/schedule
- GET mobile-api/student/calendar/events
- GET mobile-api/student/announcements & /api/v1/announcement/m
- GET mobile-api/student/academic/results/ranking
- GET mobile-api/student/academic/results/transcripts

### 4. Client Application Route Map (GetX Routing)

- `/loginparen`
- `/loginstudent`
- `/parent`
- `/student`
- `/student_announcement`
- `/student_id_shortcut`

### 5. Discovered Cloud Assets & CDN Endpoints

- `https://res.cloudinary.com/kdey/image/upload/v1767948582/Rectangle_6888_jaeua7.png`

---

## 🛡️ Security Configuration & Posture Audit

| Severity | Flag                            | Description                                                                   |
| :------: | :------------------------------ | :---------------------------------------------------------------------------- |
| **LOW**  | `android:allowBackup (Omitted)` | allowBackup is not explicitly disabled; defaults to true on older API levels. |

---

## 🔒 Native Binary Hardening (ELF Audit)

| Binary File     | Stack Canary |  PIE  | RELRO | NX Stack |
| :-------------- | :----------: | :---: | :---: | :------: |
| `libapp.so`     |     `NO`     | `YES` | `NO`  |   `NO`   |
| `libdartjni.so` |    `YES`     | `YES` | `NO`  |   `NO`   |
| `libflutter.so` |    `YES`     | `YES` | `NO`  |   `NO`   |

---

## 🎯 Exported Attack Surface (ADB Test Commands)

| Component Type       | Component Name                                     | Permission Guard          | ADB Launch Command                                                                                |
| :------------------- | :------------------------------------------------- | :------------------------ | :------------------------------------------------------------------------------------------------ |
| `Activity`           | `com.cspp_mobiles.MainActivity`                    | `None`                    | `adb shell am start -n com.cspp_mobiles.dev/com.cspp_mobiles.MainActivity`                        |
| `Activity`           | `io.flutter.plugins.urllauncher.WebViewActivity`   | `None`                    | `adb shell am start -n com.cspp_mobiles.dev/io.flutter.plugins.urllauncher.WebViewActivity`       |
| `Broadcast Receiver` | `androidx.profileinstaller.ProfileInstallReceiver` | `android.permission.DUMP` | `adb shell am broadcast -n com.cspp_mobiles.dev/androidx.profileinstaller.ProfileInstallReceiver` |

---

## 📂 Output Evidence Files Catalog

The following structured Evidence JSON files have been generated:

1. **`01_flutter_identification.json`**:
   Full ELF metadata, `libapp.so` & `libflutter.so` SHA256 hashes, build IDs, and Dart snapshot hashes.
2. **`02_package_manifest.json`**:
   Complete parsed `AndroidManifest.xml` (all activities, intent filters, permissions, and service declarations).
3. **`03_classes_inventory.json`**:
   DEX class name index containing all `686` classes.
4. **`04_main_class_inspection.json`**:
   Parsed fields, methods, constructors, and display signatures of `com.cspp_mobiles.MainActivity`.
5. **`05_main_method_decompiled.json`**:
   Decompiled Java/Smali bytecode for the main constructor or entry method.
6. **`06_class_references.json`**:
   Incoming reference cross-references (xrefs).
7. **`07_artifact_graph.json`**:
   Full occurrence tree mapping all internal resources and DEX segments.
8. **`08_application_graph.json`**:
   Projected application topology and dependency graph.
9. **`09_flutter_endpoints.json`**:
   Extracted server hosts, API endpoints, GetX routes, engine commit, and build flags.
10. **`10_security_and_secrets.json`**:
    Native ELF protection audit and full secret discovery findings.

---

_Generated automatically by the REA Automated APK Scanner (`deploy/auto_scan.py`)._
