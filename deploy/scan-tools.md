# Complete Inventory of REA Reverse Engineering Tools (189 Tools)

This catalog covers all **189 reverse engineering tools** available in the REA engine.

---

## ⚡ Quick-Start: Analyzing `SMIS-Parents-app-v0.1.apk` Right Now

If you want to immediately analyze the sample APK located at `/workspace/targets/SMIS-Parents-app-v0.1.apk` (host: `targets/SMIS-Parents-app-v0.1.apk`), here are the exact verified commands:

### 1. Identify Flutter & Native Code

```bash
./deploy/deploy.sh cli identify-flutter-build /workspace/targets/SMIS-Parents-app-v0.1.apk
```

_Discovers Dart snapshot hash `0451907c2eaa8467e848c0067bfe8ed4`, Clang 19 toolchain, and extracts ARM64 / ARMv7 / x86_64 `libapp.so` & `libflutter.so` binaries._

### 2. Search Classes in APK

```bash
./deploy/deploy.sh cli search-android-classes /workspace/targets/SMIS-Parents-app-v0.1.apk MainActivity
```

_Finds the real launcher activity: `com.cspp_mobiles.MainActivity` among 686 decompiled classes._

### 3. Extract Package Manifest, Permissions & Activities

```bash
./deploy/deploy.sh cli inspect-android-package /workspace/targets/SMIS-Parents-app-v0.1.apk
```

_Parses package identifier `com.cspp_mobiles`, declared permissions (Internet, Camera, Storage), services, and receivers._

### 4. Inspect Class Members & Methods

```bash
./deploy/deploy.sh cli inspect-android-class /workspace/targets/SMIS-Parents-app-v0.1.apk com.cspp_mobiles.MainActivity
```

_Inspects fields, constructor, and method signatures of the main activity._

### 5. Decompile Method Bytecode to Java/Smali

```bash
./deploy/deploy.sh cli inspect-android-method /workspace/targets/SMIS-Parents-app-v0.1.apk com.cspp_mobiles.MainActivity "<init>"
```

_Decompiles the constructor or target method._

### 6. Trace Class References (Xrefs)

```bash
./deploy/deploy.sh cli trace-android-references /workspace/targets/SMIS-Parents-app-v0.1.apk com.cspp_mobiles.MainActivity
```

_Tracks all callers and cross-references leading to `MainActivity`._

### 7. Inspect File Graph (Structure & Nodes)

```bash
./deploy/deploy.sh cli inspect-artifact /workspace/targets/SMIS-Parents-app-v0.1.apk
```

_Builds full 180-node occurrence graph of all assets, DEX files, and ELF binaries._

### 8. Unpack All Files from APK

```bash
./deploy/deploy.sh cli extract-artifact /workspace/targets/SMIS-Parents-app-v0.1.apk
```

_Safely extracts all APK contents to an inspection directory._

---

## 💡 Important: CLI Commands vs. MCP Interactive Tools

You may notice two different types of tools below:

1. **Standalone CLI Commands (~130 Tools)**:
   - Executable directly from terminal via `./deploy/deploy.sh cli <command> [args]`.
   - Used for direct file inspection (APKs, ELF binaries, PCAPs, ADB devices).
   - _Example_: `./deploy/deploy.sh cli inspect-android-package /workspace/targets/SMIS-Parents-app-v0.1.apk`

2. **Interactive MCP Session Tools (59 Tools)**:
   - Marked with **`🌐 MCP Interactive Tool (Web GUI & AI Agent)`**.
   - These include cursor navigation tools like `current_procedure`, `goto_address`, `next_address`, `list_segments`, and `open_binary`.
   - **Why doesn't `./deploy/deploy.sh cli current-procedure` work?**
     CLI commands are one-shot: they launch, run, and immediately terminate. There is no persistent GUI window or open disassembler cursor in a terminal command.
   - **How to use them?**
     - **In Web GUI**: Go to `http://localhost:6274` -> **Tools** tab -> Select `current_procedure` -> Click **Execute**.
     - **Via AI Agent (Cursor, Claude, Gemini, Continue)**: Ask the agent in plain English: _"Inspect the current procedure at cursor"_ or call `current_procedure()`.

---

## 📑 Category Navigation

- [Native Binary Disassembly & Decompilation (52 tools)](#native-binary-disassembly-decompilation)
- [Evidence, Diffing & Reconstruction Verification (41 tools)](#evidence-diffing-reconstruction-verification)
- [Apple, iOS & macOS Mach-O Analysis (10 tools)](#apple-ios-macos-mach-o-analysis)
- [Managed & Specialized Runtimes (.NET, WASM, EVM, Go) (10 tools)](#managed-specialized-runtimes-net-wasm-evm-go-)
- [Frida Dynamic Instrumentation (9 tools)](#frida-dynamic-instrumentation)
- [Network, PCAP & Signal Analysis (4 tools)](#network-pcap-signal-analysis)
- [Android & Mobile Analysis (12 tools)](#android-mobile-analysis)
- [Firmware & Embedded Systems (2 tools)](#firmware-embedded-systems)
- [Web, JavaScript & Electron Applications (23 tools)](#web-javascript-electron-applications)
- [Android Debug Bridge (ADB) Dynamic Controls (24 tools)](#android-debug-bridge-adb-dynamic-controls)
- [Flutter & Dart Reverse Engineering (2 tools)](#flutter-dart-reverse-engineering)

---

## <a id="native-binary-disassembly-decompilation"></a>Native Binary Disassembly & Decompilation (52 Tools)

### 1. `annotate_native_function`

**Title**: Annotate Native Function

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Atomically update one function name and/or entry comments, read them back, and return a refreshed complete function dossier. Ghidra changes its ephemeral session analysis database only; original executable bytes remain unchanged. Empty comment text clears that comment. Edits remain available to subsequent MCP calls until close; CLI returns the updated dossier before discarding its session. Invalid edits roll back the entire operation. Windows P0 and providers without this capability are unsupported.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli annotate-native-function <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli annotate-native-function /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `procedure` |
| **Optional** | `name`, `comment`, `inline_comment` |

### 2. `inspect_native_load_image`

**Title**: Inspect Native Load Image

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Verify the provider's loaded DOS MZ or explicitly selected COM image against its immutable target snapshot: complete original/modified source-byte digests, header/module file mappings and memory digests, relocations and external entry. Returns measured observations and independent checks with mismatch coordinates. COM verification includes its imposed entry register context and does not claim PSP/runtime coverage. Overlay and uninitialized coverage remain explicit; other formats return unsupported. Does not execute or modify the target.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-native-load-image
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-native-load-image
```

_(Runs verification/inspection; requires no extra arguments)_

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | _None_ |

### 3. `inspect_native_data_type`

**Title**: Inspect Native Data Type

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Inspect one recovered type by exact database category path or defined typed data address. Returns observed size, alignment, packing, fields, bitfields, enum values, and child type identities; source-level authority and flexible-tail semantics remain unknown unless substantiated.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-native-data-type
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-native-data-type
```

_(Runs verification/inspection; requires no extra arguments)_

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `type`, `address`, `document` |

### 4. `inspect_native_instruction`

**Title**: Inspect Native Instruction

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Inspect one exact code or data address: decoded bytes, mnemonic, ordered operand tokens, flow, outgoing instruction references and typed incoming references where available. Incoming references preserve source, access kind, operand index and analysis provenance even at data addresses; they do not prove runtime access. Memory addressing decomposition is unavailable when the provider supplies only tokens. Data, interior instruction addresses and undecodable bytes are distinct outcomes.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-native-instruction <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-native-instruction /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `address` |
| **Optional** | `document` |

### 5. `resolve_native_call_targets`

**Title**: Resolve Native Call Targets

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Resolve one explicit static call site using typed provider call references. Preserves ambiguous targets as candidates and unresolved computed calls as unknown; does not execute code or traverse a call graph.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli resolve-native-call-targets <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli resolve-native-call-targets /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `address` |
| **Optional** | `document` |

### 6. `address_name`

**Title**: Address Name

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Resolve the primary analyzed name at a code or data address. Headless providers require an explicit address; GUI providers may default to their current cursor. Null means the provider has no primary name at that address.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `address_name` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `address_name` on current target session"_ or call tool `address_name()`.

> ⚠️ **Why no CLI command?**
> `address_name` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `document`, `address` |

### 7. `comment`

**Title**: Comment

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Read the regular analysis comment at an address, defaulting to the current cursor. This is read-only and returns null when no comment exists; use set_comment to persist a finding.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `comment` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `comment` on current target session"_ or call tool `comment()`.

> ⚠️ **Why no CLI command?**
> `comment` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `document`, `address` |

### 8. `current_address`

**Title**: Current Address

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Return Hopper's current cursor address for the selected document. Use only for interactive navigation state; prefer explicit addresses in reproducible investigations.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `current_address` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `current_address` on current target session"_ or call tool `current_address()`.

> ⚠️ **Why no CLI command?**
> `current_address` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `document` |

### 9. `current_procedure`

**Title**: Current Procedure

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Return the analyzed procedure containing Hopper's current cursor. This uses GUI cursor state and is not a procedure-name lookup.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `current_procedure` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `current_procedure` on current target session"_ or call tool `current_procedure()`.

> ⚠️ **Why no CLI command?**
> `current_procedure` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `document` |

### 10. `goto_address`

**Title**: Goto Address

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Move Hopper's GUI cursor to a mapped address and return the observed cursor address. Interior coordinates snap to the containing analyzed object's start. Unmapped destinations fail without moving the cursor. This changes navigation state but not analysis data; use explicit-address tools for headless workflows.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `goto_address` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `goto_address` on current target session"_ or call tool `goto_address()`.

> ⚠️ **Why no CLI command?**
> `goto_address` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `address` |
| **Optional** | `document` |

### 11. `inline_comment`

**Title**: Inline Comment

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Read the inline instruction comment at an address, defaulting to the current cursor. Returns null when absent; use set_inline_comment to write one.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `inline_comment` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `inline_comment` on current target session"_ or call tool `inline_comment()`.

> ⚠️ **Why no CLI command?**
> `inline_comment` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `document`, `address` |

### 12. `list_bookmarks`

**Title**: List Bookmarks

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: List every bookmark in the selected Hopper document as address and name pairs; unnamed bookmarks retain a null name. Use bookmarks as analyst-authored navigation aids; this does not discover code references.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `list_bookmarks` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `list_bookmarks` on current target session"_ or call tool `list_bookmarks()`.

> ⚠️ **Why no CLI command?**
> `list_bookmarks` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `document` |

### 13. `list_procedures`

**Title**: List Procedures

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: List every analyzed procedure as address/value pairs after provider analysis. Ghidra metadata distinguishes thunks and external functions; use returned addresses in later function operations.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `list_procedures` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `list_procedures` on current target session"_ or call tool `list_procedures()`.

> ⚠️ **Why no CLI command?**
> `list_procedures` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `document` |

### 14. `list_segments`

**Title**: List Segments

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: List segments or memory blocks using exclusive end addresses. Ghidra reports block permissions, address space, image base, initialization, and overlay facts; Hopper marks unavailable permissions explicitly.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `list_segments` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `list_segments` on current target session"_ or call tool `list_segments()`.

> ⚠️ **Why no CLI command?**
> `list_segments` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `document` |

### 15. `list_strings`

**Title**: List Strings

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: List every provider-defined string object, or filter to one address, as address/value pairs with encoding, terminator status, and byte length when available. Hopper reads complete typed objects and retains its original display text as provider_value; long literals may span adjacent unterminated objects.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `list_strings` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `list_strings` on current target session"_ or call tool `list_strings()`.

> ⚠️ **Why no CLI command?**
> `list_strings` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `document`, `address` |

### 16. `next_address`

**Title**: Next Address

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Return the next analyzed object address after an explicit address or current cursor. This is a navigation primitive, not instruction-flow or CFG analysis.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `next_address` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `next_address` on current target session"_ or call tool `next_address()`.

> ⚠️ **Why no CLI command?**
> `next_address` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `document`, `address` |

### 17. `prev_address`

**Title**: Prev Address

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Return the previous analyzed object start before an explicit address or current cursor. This is a navigation primitive and may fail at document boundaries; data objects and instructions remain distinct from control flow.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `prev_address` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `prev_address` on current target session"_ or call tool `prev_address()`.

> ⚠️ **Why no CLI command?**
> `prev_address` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `document`, `address` |

### 18. `procedure_address`

**Title**: Procedure Address

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Resolve an unambiguous procedure symbol name or provider-normalized address to its canonical entry address. External address spaces remain explicit.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `procedure_address` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `procedure_address` on current target session"_ or call tool `procedure_address()`.

> ⚠️ **Why no CLI command?**
> `procedure_address` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `procedure` |
| **Optional** | `document` |

### 19. `procedure_assembly`

**Title**: Procedure Assembly

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Return assembly for one analyzed procedure identified by symbol or hexadecimal address. Use when pseudocode loses calling-convention or instruction-level detail; output is currently returned as one unpaginated string. Ghidra terminal-call assumptions that may cut the analyzed body are reported in Evidence limitations.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `procedure_assembly` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `procedure_assembly` on current target session"_ or call tool `procedure_assembly()`.

> ⚠️ **Why no CLI command?**
> `procedure_assembly` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `procedure` |
| **Optional** | `document` |

### 20. `procedure_callees`

**Title**: Procedure Callees

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Return the provider's resolved direct callees for one procedure identified by symbol or address. Unresolved indirect calls may be absent; use analyze_function and typed references to preserve available edge uncertainty.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `procedure_callees` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `procedure_callees` on current target session"_ or call tool `procedure_callees()`.

> ⚠️ **Why no CLI command?**
> `procedure_callees` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `procedure` |
| **Optional** | `document` |

### 21. `procedure_callers`

**Title**: Procedure Callers

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Return the provider's resolved direct callers for one procedure identified by symbol or address. Results reflect completed static analysis and may omit unresolved indirect references.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `procedure_callers` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `procedure_callers` on current target session"_ or call tool `procedure_callers()`.

> ⚠️ **Why no CLI command?**
> `procedure_callers` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `procedure` |
| **Optional** | `document` |

### 22. `procedure_info`

**Title**: Procedure Info

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Return provider metadata for one procedure identified by symbol or address: entrypoint, signature, locals, size, block count, and complete inclusive body ranges when observed. Extents reflect the provider's analyzed body; Ghidra terminal-call assumptions that may cut it are reported in Evidence limitations. Hopper locals preserve observed names and signed stack displacements; source types remain unknown. Body byte count and enclosing span remain distinct; unavailable extent is explicit.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `procedure_info` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `procedure_info` on current target session"_ or call tool `procedure_info()`.

> ⚠️ **Why no CLI command?**
> `procedure_info` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `procedure` |
| **Optional** | `document` |

### 23. `read_function_instructions`

**Title**: Read Function Instructions

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Return every raw instruction for one analyzed procedure. Instruction text and body extent are provider-specific. Ghidra terminal-call assumptions that may cut the analyzed body are reported in limitations.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli read-function-instructions <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli read-function-instructions /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `procedure` |
| **Optional** | `document` |

### 24. `address_to_file_offset`

**Title**: Address To File Offset

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Map one provider-normalized virtual address to its original nonnegative file offset. Hopper verifies the original bytes against the selected executable digest and translates FAT image-relative offsets using the loaded header. Results preserve the provider coordinate, image base, and source path. Unmapped addresses fail explicitly; changed or unavailable sources return typed errors retaining native mapping facts as partial evidence.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli address-to-file-offset <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli address-to-file-offset /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `address` |
| **Optional** | `document` |

### 25. `procedure_references`

**Title**: Procedure References

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Return every raw incoming or outgoing reference edge for one procedure. Endpoint procedures are resolved only from provider containment. Ghidra preserves detailed reference flags. Hopper preserves native CallReference classifications and exact endpoints while leaving unavailable detailed flags explicit.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `procedure_references` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `procedure_references` on current target session"_ or call tool `procedure_references()`.

> ⚠️ **Why no CLI command?**
> `procedure_references` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `procedure` |
| **Optional** | `direction`, `document` |

### 26. `procedure_pseudo_code`

**Title**: Procedure Pseudo Code

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Decompile one analyzed procedure by symbol name or provider-normalized address. Returns provider-specific pseudocode, never original source or cross-provider text equivalence, and may return null; request procedure_assembly when instruction precision matters. Ghidra no-return assumptions may cut the analyzed body; Evidence limitations report observed terminal calls and available callee identities.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli procedure-pseudo-code <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli procedure-pseudo-code /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `procedure` |
| **Optional** | `document` |

### 27. `resolve_containing_procedure`

**Title**: Resolve Containing Procedure

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Resolve an arbitrary address, including an interior instruction or exact external entry, to its provider-analyzed containing procedure. A negative result distinguishes outside segments from not in a procedure and is never guessed from nearby symbols.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `resolve_containing_procedure` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `resolve_containing_procedure` on current target session"_ or call tool `resolve_containing_procedure()`.

> ⚠️ **Why no CLI command?**
> `resolve_containing_procedure` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `address` |
| **Optional** | `document` |

### 28. `search_procedures`

**Title**: Search Procedures

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Search every analyzed procedure name using literal matching by default or regex when requested. Results are deterministic and complete. Hopper regex mode uses ECMAScript Unicode syntax in a cancellable worker; a matching deadline leaves its API usable.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli search-procedures <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli search-procedures /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `pattern` |
| **Optional** | `mode`, `case_sensitive`, `document` |

### 29. `search_strings`

**Title**: Search Strings

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Search every provider-defined string object using literal matching by default or regex when requested. Results are deterministic and complete over those defined objects, not every text sequence in artifact bytes. Ghidra may omit packed or undefined literals, including Rust strings; an empty result does not prove text is absent. If an address is known, read_bytes and xrefs inspect its bytes and references. Hopper retains typed byte decoding, native display, and explicit decoding unknowns. Adjacent long-literal fragments match independently. Hopper regex mode uses ECMAScript Unicode syntax in a cancellable worker; a matching deadline leaves its API usable.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli search-strings <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli search-strings /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `pattern` |
| **Optional** | `mode`, `case_sensitive`, `document` |

### 30. `set_address_name`

**Title**: Set Address Name

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Assign an analyst name to one mapped hexadecimal address and report whether the native edit succeeded and exact readback matched. Hopper rejects symbol names exceeding 1024 UTF-16 code units before mutation, and rejects names owned by another address; use set_addresses_names to explicitly move or swap labels among selected addresses. This mutates analysis metadata.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `set_address_name` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `set_address_name` on current target session"_ or call tool `set_address_name()`.

> ⚠️ **Why no CLI command?**
> `set_address_name` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `address`, `name` |
| **Optional** | `document` |

### 31. `set_addresses_names`

**Title**: Set Addresses Names

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Assign analyst names to multiple mapped addresses in one call and return per-address edit/readback success booleans. Hopper validates mapped destinations, native string representations, its 1024 UTF-16 code-unit symbol-name limit, and unique destinations/names before applying edits. Existing labels may move or swap only among explicitly selected addresses; unselected label owners remain unchanged. This mutates analysis metadata; verify failures individually.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `set_addresses_names` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `set_addresses_names` on current target session"_ or call tool `set_addresses_names()`.

> ⚠️ **Why no CLI command?**
> `set_addresses_names` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `names` |
| **Optional** | `document` |

### 32. `set_bookmark`

**Title**: Set Bookmark

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Create or replace a bookmark at a mapped hexadecimal address and report success. This mutates navigation metadata; bookmarks are analyst-authored navigation aids, not binary evidence.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `set_bookmark` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `set_bookmark` on current target session"_ or call tool `set_bookmark()`.

> ⚠️ **Why no CLI command?**
> `set_bookmark` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `address` |
| **Optional** | `name`, `document` |

### 33. `set_comment`

**Title**: Set Comment

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Write a regular analysis comment at a hexadecimal address and return whether readback matched. An empty comment clears it. This mutates the Hopper document; use comments to record evidence IDs or reasoning.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `set_comment` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `set_comment` on current target session"_ or call tool `set_comment()`.

> ⚠️ **Why no CLI command?**
> `set_comment` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `address`, `comment` |
| **Optional** | `document` |

### 34. `set_inline_comment`

**Title**: Set Inline Comment

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Write an inline instruction comment at a hexadecimal address and return whether readback matched. An empty comment clears it; Hopper may flatten newlines, producing false on exact readback. This mutates analysis metadata.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `set_inline_comment` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `set_inline_comment` on current target session"_ or call tool `set_inline_comment()`.

> ⚠️ **Why no CLI command?**
> `set_inline_comment` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `address`, `comment` |
| **Optional** | `document` |

### 35. `unset_bookmark`

**Title**: Unset Bookmark

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Remove the bookmark at a mapped hexadecimal address and return whether it is absent. Hopper also permits removing an existing legacy bookmark outside mapped memory. This mutates navigation metadata and does not alter binary bytes.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `unset_bookmark` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `unset_bookmark` on current target session"_ or call tool `unset_bookmark()`.

> ⚠️ **Why no CLI command?**
> `unset_bookmark` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `address` |
| **Optional** | `document` |

### 36. `xrefs`

**Title**: Xrefs

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Return analyzed references to a code or data address. Hopper may default to its current cursor; headless providers such as Ghidra require an explicit address. Use to connect strings, globals, selectors, and functions; bare addresses are untyped and indirect references may be incomplete. Use inspect_native_instruction at the target address for typed incoming references where supported.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli xrefs <binary_path> <address>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli xrefs /workspace/targets/libapp.so 0x00401000
```

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `document`, `address` |

### 37. `trace_native_values`

**Title**: Trace Native Values

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Trace a bounded static dependency graph from one explicit native procedure. Includes high-p-code def-use, constants, operators, memory and branch operations, resolved call edges, and derived argument/parameter and return/output bindings. Missing bindings, alias semantics, persistent state and RNG roles remain unknown. Budgets bound depth, decompilations, graph size and payloads; nodes are paginated.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli trace-native-values <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli trace-native-values /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `procedure` |
| **Optional** | `max_depth`, `max_functions`, `max_call_sites`, `max_nodes`, `max_edges`, `offset`, `limit` |

### 38. `inspect_native_dispatch_metadata`

**Title**: Inspect Native Dispatch Metadata

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Inspect the bound provider's name inventory for Objective-C class/method symbols and Swift mangled symbols, returning at most max_records decoded names. Includes target SHA-256 when available, provider identity/version, analysis-profile digest, facet coverage, and per-record Evidence. This is symbol-level evidence, not runtime metadata: ivar layouts, protocol conformances, witness/class tables, and relative pointers are explicitly marked unsupported unless a provider supplies those decoders. The provider controls how its name inventory is acquired.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-native-dispatch-metadata
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-native-dispatch-metadata
```

_(Runs verification/inspection; requires no extra arguments)_

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `max_records` |

### 39. `batch_decompile`

**Title**: Batch Decompile

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Decompile each explicit procedure symbol or address concurrently. Preserves each input selector in address and reports the observed canonical entry and entry label in procedure; identity or label failures remain explicit without discarding usable pseudocode. Returns ordered per-item success or error results and aggregate counts.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `batch_decompile` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `batch_decompile` on current target session"_ or call tool `batch_decompile()`.

> ⚠️ **Why no CLI command?**
> `batch_decompile` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `addresses` |

### 40. `get_call_graph`

**Title**: Get Call Graph

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Resolve one symbol or address to its canonical procedure entry, then traverse the bound provider's caller or callee relationships until the reachable graph is exhausted. Every node uses a canonical address and has an ok/error status; failures use safe typed projections. Unresolved indirect calls may be missing and results are not a whole-program CFG.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `get_call_graph` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `get_call_graph` on current target session"_ or call tool `get_call_graph()`.

> ⚠️ **Why no CLI command?**
> `get_call_graph` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `address` |
| **Optional** | `direction` |

### 41. `find_xrefs_to_name`

**Title**: Find Xrefs To Name

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Resolve an exact name against the bound provider's name inventory and return a resolved or unresolved result. Unresolved names use the stable name_not_found reason; this xref workflow returns address-only projections.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `find_xrefs_to_name` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `find_xrefs_to_name` on current target session"_ or call tool `find_xrefs_to_name()`.

> ⚠️ **Why no CLI command?**
> `find_xrefs_to_name` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `name` |
| **Optional** | _None_ |

### 42. `binary_overview`

**Title**: Binary Overview

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Return native-binary metadata, every segment with its length, and exhaustive procedure/string counts. When every provider-reported segment agrees on an analysis image base, return it as image_base so callers can relate provider addresses to their loader coordinates. Use search_procedures, list_procedures, or analyze_function directly when you already know which procedure to inspect.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli binary-overview
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli binary-overview
```

_(Runs verification/inspection; requires no extra arguments)_

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | _None_ |

### 43. `inspect_native_api`

**Title**: Inspect Native Api

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Analyze a native API boundary in one function identified by symbol or provider-returned address. Returns confidence, evidence, jump-table dispatch/data/case mappings, separately evidenced default targets, unsupported branches, and residual unknowns. Null case values mean unresolved cases, never a known default.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-native-api <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-native-api /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `procedure` |
| **Optional** | _None_ |

### 44. `trace_native_ui_action`

**Title**: Trace Native Ui Action

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Trace one unique compiled UI action, object ID, native symbol or exact function address through authored connections, encoded or symbolized Objective-C handlers, and bounded static call references. Typed direct and resolved indirect calls, ambiguous candidates, inferred untyped provider callees, and targetless sites remain distinct. Runtime reachability is unknown; use trace_native_values for recovered value dependencies.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli trace-native-ui-action <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli trace-native-ui-action /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `action` |
| **Optional** | `max_depth`, `max_nodes`, `max_edges` |

### 45. `observe_native_ui`

**Title**: Observe Native Ui

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Observe an already-running native app by PID and window ID, bound to the active Mach-O target. Captures a bounded accessibility tree and selected-window screenshot; OS permission denial fails without broad capture or target launch.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli observe-native-ui <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli observe-native-ui /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `pid`, `window_id` |
| **Optional** | `screenshot`, `accessibility`, `max_nodes` |

### 46. `capture_native_ui_scenario`

**Title**: Capture Native Ui Scenario

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Run selected-element press, increment/decrement scroll, AXValue text entry and bounded wait steps in one exact native app window. Returns ordered before/after captures and action/capture failures. Actions can change app data, network activity and persistent state; application state is left as-is and restoration is not attempted.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli capture-native-ui-scenario <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli capture-native-ui-scenario /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `pid`, `window_id`, `steps` |
| **Optional** | `screenshot`, `accessibility`, `max_nodes` |

### 47. `observe_native_calls`

**Title**: Observe Native Calls

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Launch the active Mach-O as an owned process under LLDB and record each entry into caller-selected functions or Objective-C methods: thread, module, symbol, load and file address, raw argument registers, selector, receiver class and optional caller frames. Every hit auto-continues. No expression is evaluated and no other process is attached. The process is killed when max_events or duration_ms is reached; exit status, captured stdout/stderr, unresolved breakpoints and limitations are returned inline. The process runs with the current user's permissions and may change files, show UI or use the network. A hardened-runtime target needs the get-task-allow entitlement.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli observe-native-calls <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli observe-native-calls /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `breakpoints` |
| **Optional** | `arguments`, `environment`, `working_directory`, `duration_ms`, `max_events`, `argument_registers`, `backtrace_frames` |

### 48. `inspect_binary_layout`

**Title**: Inspect Binary Layout

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Inspect an explicit local binary without launching it as a host process. Returns file-backed section/segment ranges, linked addresses, original symbol/REL/RELA table identities, complete encoded RELR tables and upstream-derived offsets with unknown per-word locations/addends, raw name bytes, dependency/interpreter names and static mitigation inferences inline with artifact SHA-256 Evidence. Initial profile: ELF64 x86-64 little-endian EXEC/DYN/REL on Linux x64 via caller-supplied Python with unchanged pwntools 4.15.0, pyelftools 0.33 and Unicorn 2.1.2. Runtime addresses/library paths, overall relocation inventory completeness and complete derived GOT/PLT coverage remain unknown. Zero executable entry values mean absence; relocatable entries are not applicable. Upstream can emulate PLT instructions with Unicorn for derived static maps. Uses bounded complete output and owned temporary files/processes; malformed, unsupported or oversized objects return no partial success. Select detail summary to retain the complete layout Evidence in this session and receive only its summary view, then inspect sections, symbols, mitigations or linkage with inspect_analysis_view.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-binary-layout <path>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-binary-layout /workspace/targets/libapp.so
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `path` |
| **Optional** | `detail` |

### 49. `open_binary`

**Title**: Open Binary

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Open a local executable, application bundle, archive, JavaScript, source map, plist, or analysis database after validation. format=dos-com explicitly interprets 1..65280 headerless bytes as a DOS COM analysis image. format=raw-binary interprets headerless bytes with a required architecture and entry_point; file offset 0 maps at that address. Omission preserves header-based detection. provider_id selects one deep provider or deterministic auto selection; the binding remains stable until close or an explicit switch, with no failure fallback. Reopening the same target and profile retains its active database and metadata edits. An optional analysis snapshot is imported atomically and must match the binary identity, concrete provider, and canonical analysis profile exactly; importing into a session with metadata mutations requires closing and reopening it first.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `open_binary` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `open_binary` on current target session"_ or call tool `open_binary()`.

> ⚠️ **Why no CLI command?**
> `open_binary` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `path` |
| **Optional** | `format`, `architecture`, `entry_point`, `provider_id`, `snapshot_path` |

### 50. `close_binary`

**Title**: Close Binary

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Drain earlier provider requests, optionally write a provider-neutral analysis snapshot atomically to the caller-supplied path, then close the active target and every provider resource started for it. Later provider requests wait until this lifecycle operation finishes. Existing files require explicit overwrite; a failed save leaves the session open so cached analysis is not lost. Metadata edits prevent immutable snapshot saves until the session is recreated; export_evidence_bundle preserves mutable observations before closing without a snapshot.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `close_binary` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `close_binary` on current target session"_ or call tool `close_binary()`.

> ⚠️ **Why no CLI command?**
> `close_binary` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `snapshot_path`, `overwrite` |

### 51. `binary_session`

**Title**: Binary Session

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Report the complete current target, provider, capability availability, client-feature, analysis, and server-identity status without starting analysis.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `binary_session` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `binary_session` on current target session"_ or call tool `binary_session()`.

> ⚠️ **Why no CLI command?**
> `binary_session` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `expected_package_version`, `expected_catalog_digest`, `expected_server_path` |

## <a id="evidence-diffing-reconstruction-verification"></a>Evidence, Diffing & Reconstruction Verification (41 Tools)

### 52. `inspect_address_context`

**Title**: Inspect Address Context

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Inspect one explicit reproducible address for its analyzed name, containing procedure, regular and inline comments, and matching bookmarks. Each unsupported facet returns a typed unavailable outcome; use xrefs, assembly, or pseudocode for those deeper views.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `inspect_address_context` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `inspect_address_context` on current target session"_ or call tool `inspect_address_context()`.

> ⚠️ **Why no CLI command?**
> `inspect_address_context` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `address` |
| **Optional** | `document` |

### 53. `current_document`

**Title**: Current Document

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Return the document currently selected by REA's Hopper bridge.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `current_document` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `current_document` on current target session"_ or call tool `current_document()`.

> ⚠️ **Why no CLI command?**
> `current_document` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | _None_ |

### 54. `list_documents`

**Title**: List Documents

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: List provider program or document identities. Hopper may expose several documents; a Ghidra headless session contains exactly its one imported Program.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `list_documents` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `list_documents` on current target session"_ or call tool `list_documents()`.

> ⚠️ **Why no CLI command?**
> `list_documents` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | _None_ |

### 55. `list_names`

**Title**: List Names

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: List every analyzed memory and external symbol as address/value pairs. Provider metadata distinguishes Ghidra primary, dynamic, external, type, and source facts when available.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `list_names` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `list_names` on current target session"_ or call tool `list_names()`.

> ⚠️ **Why no CLI command?**
> `list_names` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `document`, `address` |

### 56. `read_bytes`

**Title**: Read Bytes

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Read analyzed bytes from one provider-normalized virtual address. The hexadecimal payload reports the exact returned length; incomplete reads remain explicit and unsupported provider APIs return typed capability unavailability.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli read-bytes <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli read-bytes /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `address` |
| **Optional** | `length`, `document` |

### 57. `analyze_function`

**Title**: Analyze Function

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Build a dossier for one native function identified by symbol or provider-returned address. Returns identity with complete inclusive analyzed body ranges or explicit unknown, provider-specific pseudocode and assembly, comments, calls, references, referenced strings/names, local CFG blocks, and available native API boundary observations. Ghidra terminal-call assumptions that may cut the analyzed body are reported in limitations with available callee identities.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli analyze-function <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli analyze-function /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `procedure` |
| **Optional** | _None_ |

### 58. `trace_feature`

**Title**: Trace Feature

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Trace the complete literal query, preserving spaces, through every matching string and procedure, their xrefs, and truthful containing-procedure resolution. Returns observations, operation count, and residual unknowns without inferring reference kinds.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli trace-feature <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli trace-feature /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `query` |
| **Optional** | `case_sensitive` |

### 59. `trace_call_path`

**Title**: Trace Call Path

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Resolve start and optional goal symbols or addresses to canonical procedure entries, then trace direct callers or callees until the graph is exhausted or the goal is reached. Results use canonical addresses; Evidence preserves supplied selectors. Returns visited nodes, direct-call edges, a shortest traversal path, provider failures, and residual unknowns. A requested goal is unknown when unresolved expansions prevent proving it absent; unresolved indirect calls remain unknown.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `trace_call_path` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `trace_call_path` on current target session"_ or call tool `trace_call_path()`.

> ⚠️ **Why no CLI command?**
> `trace_call_path` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `start` |
| **Optional** | `goal`, `direction` |

### 60. `inspect_signature`

**Title**: Inspect Signature

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Inspect the active artifact's code-signing identity, hashes, authorities, requirements, entitlements, hardened-runtime state, and exact command provenance.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-signature
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-signature
```

_(Runs verification/inspection; requires no extra arguments)_

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | _None_ |

### 61. `list_architectures`

**Title**: List Architectures

**Tool Type**: 💻 **Direct CLI Command**

**Description**: List thin or universal Mach-O slices with offsets, sizes, alignment, explicit coverage, and native-tool provenance.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli list-architectures
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli list-architectures
```

_(Runs verification/inspection; requires no extra arguments)_

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | _None_ |

### 62. `inspect_artifact`

**Title**: Inspect Artifact

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Inspect an active archive or application package in one call. By default returns the complete content-addressed artifact graph once, as the typed nested inventory Evidence, with root and integrity observations, integrity contradictions, hypotheses, unexplored branches, limitations, and next probes inline. Optional detail summary retains the complete inspection and returns its derived summary view; read exact paths or inventory pages with inspect_analysis_view using parent_evidence_id. This changes delivery, not inventory coverage. Read-only DMG mounting is used automatically on supported macOS hosts. Integrity mismatches fail by default; record-and-continue keeps mismatches explicitly untrusted. It does not extract files; use extract_artifact to materialize its regular contents.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-artifact <path>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-artifact /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `integrity_policy`, `detail` |

### 63. `extract_artifact`

**Title**: Extract Artifact

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Extract all regular files from the active archive or application package into a fresh temporary directory chosen by REA. The result includes its location. Rejects traversal and symlink escapes, never overwrites, and verifies cleanup. Integrity mismatches fail by default; record-and-continue extracts the observed bytes and returns each mismatch as an explicitly untrusted integrity contradiction.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli extract-artifact <path> [--integrity-policy <policy>]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli extract-artifact /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `integrity_policy` |

### 64. `inspect_keyed_archive`

**Title**: Inspect Keyed Archive

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Inspect one Foundation NSKeyedArchiver plist in the active app bundle as original object-table nodes, class descriptors, named roots, and UID edges. Preserves shared and cyclic references without instantiating classes. The path is relative to the bundle; root selection and object pagination preserve original identities.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-keyed-archive
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-keyed-archive
```

_(Runs verification/inspection; requires no extra arguments)_

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `path`, `root`, `offset`, `limit` |

### 65. `inspect_analysis_view`

**Title**: Inspect Analysis View

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Inspect selected views of completed binary-layout, JavaScript application, native analyze_function, inspect_artifact, inventory_artifact, inspect_wasm_artifact, inspect_evm_interface, inspect_managed_artifact, inspect_android_package, inspect_dart_aot or inspect_web_network_capture Evidence without repeating analysis. Historical capture summaries return identity and counts without bodies or archive inventories. Capture views page retained records: view {kind: "capture", detail: "preview" | "complete", offset: 0, limit: 20}; preview selects recorded headline fields and binary descriptors, complete returns exact records with all sidecars. Offsets follow the selected parent record order, preserving original producer ordinals. Paging never reopens the source or reruns the decoder. For inspect_pcap_capture parents, kind pcap pages endpoints, dns-queries, tls-sni, protocols, http-uris or unattributed-addresses. Select an exact query for dns-addresses, or a tshark/capinfos stream for UTF-16 diagnostics text. Page totals count retained facts; source coverage remains explicit. Qlog summaries keep profile/scope and counts; kind qlog pages traces, streams, loss-declarations, incomplete-records, contributions, ranges or final-sizes. Except traces, select trace_index; stream-specific facets also require exact stream_id and direction. Facts retain all-recorded-events-before-selection scope, and interval overlap or endpoint loss declarations do not prove retransmission or network loss. The api-surface view groups retained HAR requests by method, origin and format-rule path template; templated segments are inferences. It reads no headers or bodies and reports no query values. For a retained record use source: {kind: "retained-evidence", evidence_id: "<parent_evidence_id>"}. Use normalized_result.parent_evidence_id from a summary receipt. Source kind is required. Portable source uses {kind: "inline", evidence: <complete Evidence>}. For layout, JavaScript, inventory, WASM, EVM, managed artifact, Android package and Dart AOT sources, request a summary with view: {kind: "summary"}; summary is a view kind and has no facet. The WASM summary gives validation, counts, WAT digest/length, tool profile and execution/network states without reading WAT text. Select a layout mitigations/linkage facet, one section/symbol/module, or a stable page. Module pages include assets, bundled and source modules; use node_id for ambiguous or unavailable paths. Inventory uses view: {kind: "inventory", collection: "occurrences", logical_paths: ["package.json"], offset: 0, limit: 64}. Inventory views page nodes, occurrences, edges or integrity contradictions; occurrence logical_paths matches exact recorded strings (omitted means all available, [] means none). source_complete distinguishes complete inventories from partial source records; page exhaustion does not prove absence in a partial source. WASM views use kind wasm and facet sections/imports/exports/candidates/glue/wat/headers/details/tool_profile; text facets use UTF-16 code units and source forms remain exact. EVM summary returns all inferred interface candidates, carrier/decoded identities and explicit unknowns without hex or duplicate stdout. EVM views use kind evm and facet functions/bytecode_hex/stdout/stderr; function pages preserve the original candidate rows, and text offsets/limits count UTF-16 code units (hex has two characters per decoded byte). Exhausting candidate pages does not establish global interface completeness. Managed artifact summaries preserve complete identity/classification, metadata status, module/MVID, frameworks, coverage and limitations without unrelated inventories. Managed pages use kind managed and collection references/resources/attributes, retaining source coverage and build-local token scope; page exhaustion does not establish complete metadata. Android package summaries retain all declarations, engine identity and counts without decoded manifest text. Android manifest pages use kind android, facet manifest, offset and limit in UTF-16 code units; source_status preserves partial decoded coverage even when the retained text page is exhausted. Dart AOT summary preserves target/ABI/library identity, snapshot headers and pool lower bounds. String pages use kind dart-aot, collection package_uris/dart_uris/class_like_tokens; source coverage remains partial when the producer says partial. Native function Evidence requires kind native: view: {kind: "native", facet: "procedure"}. Facets select procedure, pseudocode, assembly, basic blocks, comments, callers/callees, references, unresolved calls, referenced strings/names, native API and high-pcode. Use nonnegative offset and a positive caller-selected limit (defaults 0 and 64); pseudocode uses UTF-16 code units, other native pages use rows. Returns artifact identity, parent Evidence ID, a distinct view digest, coverage, limitations and unknowns. Actual serialized size determines MCP transport admission; choose a smaller page or export the complete retained Evidence if needed.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-analysis-view <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-analysis-view /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `source`, `view` |
| **Optional** | _None_ |

### 66. `inspect_pe_resources`

**Title**: Inspect Pe Resources

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Inspect one explicit local PE32/PE32+ image's complete bounded type/name/language resource tree without executing it or opening a disassembler. Returns numeric IDs versus original UTF-16 names, directory/data-entry file locations, payload RVA/file ranges, complete SHA-256 hashes and static RT_GROUP_ICON image-resource candidates. Language fallback, image decoding and actual shell/window loading remain unobserved. Reads a stable regular file; malformed or ambiguous mappings, non-identical overlapping ranges and exhausted budgets return no partial success. Portable on supported Node hosts; no Windows SDK or engine installation required.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-pe-resources <path>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-pe-resources /workspace/targets/binary.exe
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `path` |
| **Optional** | `max_file_bytes`, `max_entries` |

### 67. `inspect_sqlite_database`

**Title**: Inspect Sqlite Database

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Inspect an explicit local SQLite database snapshot and its existing sibling WAL without modifying source files or opening a native analysis provider. Requires Node.js 24.x >=24.15 or 26+ with native DatabaseSync.limits support, checked by the worker. Returns observed Evidence with database/WAL SHA-256 and a compact schema inventory. Selecting an exact ordinary table expands only its schema and samples rows (default 20, subject to byte and worker resource limits). Select exact columns in the requested order to avoid unrelated or large values; schema_scope=database explicitly expands the whole schema; returned rows retain 64-bit integers, text bytes and blobs with explicit truncation. No arbitrary SQL, view or virtual-table execution, extension loading, database repair, encryption support or live-snapshot atomicity claim. At most two inspections per provider are admitted; occupied capacity is retryable. An isolated temporary copy and owned worker enforce input, value/record, SQL-statement, JSON-reply, JavaScript-heap and deadline limits; overall native heap is not capped. Supply a quiescent snapshot for coherent database/WAL evidence.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-sqlite-database <path>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-sqlite-database /workspace/targets/app_data.db
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `path` |
| **Optional** | `table`, `columns`, `schema_scope`, `row_limit` |

### 68. `inspect_recorded_crash`

**Title**: Inspect Recorded Crash

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Inspect a supplied Linux ELF64 amd64 little-endian core without launching its target or attaching to any live PID. Returns all recorded segments, raw note owners/descriptors and source ranges, every Linux CORE PRSTATUS thread/register and SIGINFO fields inline with SHA-256 Evidence. Historical PID is recorded metadata; current process/file identity, note coverage and signal-thread associations stay unknown. Optionally add derived core-only GDB/pwndbg mapping candidates through explicit BYO configuration; zero map flags mean unknown permissions. Uses the same stable snapshot for both stages, bounded complete output and owned cleanup. Initial Linux x64 profile: unchanged pwntools 4.15.0/pyelftools 0.33/Unicorn 2.1.2; optional unchanged pwndbg 2026.09.15. No implicit executable/library pairing, GDB command language, host configuration changes or dependency installation.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-recorded-crash <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-recorded-crash /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `path` |
| **Optional** | `include_debugger_context` |

### 69. `list_browser_targets`

**Title**: List Browser Targets

**Tool Type**: 💻 **Direct CLI Command**

**Description**: List page targets exposed by the selected loopback Chrome DevTools Protocol endpoint. Optionally filter by exact origin. URLs preserve query values and fragments; only URL userinfo credentials are removed.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli list-browser-targets
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli list-browser-targets
*(Lists open page tabs in connected Chromium CDP instance)*
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `cdp_endpoint` |
| **Optional** | `allowed_origins` |

### 70. `capture_browser_scenario`

**Title**: Capture Browser Scenario

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Run a controlled browser scenario when passive observation cannot exercise the application. Launch the selected executable or connect to a loopback CDP target, provide a start URL and actions, and select storage or artifacts when needed. Environment, empty storage, and a URL-only final capture are defaults. capture.network selects request_body, response_body, and header_values independently; selected content is returned inline with transaction and event references, byte digests, and explicit unavailable states. Credentials and declared secrets are redacted. Agents can run their own local fixture servers to control application responses. Actions run until completion or cancellation unless timeout_ms is set. Results are returned inline.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli capture-browser-scenario <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli capture-browser-scenario /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `browser`, `start_url`, `actions` |
| **Optional** | `environment`, `storage`, `secrets`, `capture` |

### 71. `trace_application_feature`

**Title**: Trace Application Feature

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Trace a typed literal seed through every reachable part of an authenticated JavaScript Application Graph supplied as inline Evidence or exact same-session retained references. Original static, native, passive-runtime, inferred, and unknown authorities remain distinct; native addon handoffs never open a provider or execute the application.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli trace-application-feature <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli trace-application-feature /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `seed`, `application` |
| **Optional** | `native_observations`, `direction` |

### 72. `compare_application_versions`

**Title**: Compare Application Versions

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Compare two authenticated JavaScript Application Graph versions supplied as inline Evidence or exact same-session retained references. Uses unique-only exact digest, module source digest, source-map identity, structural fingerprint, and non-module semantic-key tiers. Reports added, removed, changed, ambiguous, and unknown entities plus the complete matching changed_from graph without fuzzy or module-ordinal pairing.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli compare-application-versions <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli compare-application-versions /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `left`, `right` |
| **Optional** | `left_native_observations`, `right_native_observations` |

### 73. `compare_source_to_bundle`

**Title**: Compare Source To Bundle

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Compare a cryptographically committed HistoricalSourceGraph with authenticated JavaScript Application Graph Evidence supplied inline or by exact same-session retained reference. Uses explicit exact-digest, source-map path, current-path, suffix, and basename signals with stable weights. Classifies unchanged, modified, removed, split, merged, duplicated, and unknown; incomplete coverage and ambiguous weak signals never become absence or forced matches.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli compare-source-to-bundle <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli compare-source-to-bundle /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `reference`, `application` |
| **Optional** | _None_ |

### 74. `build_reconstruction_obligation_ledger`

**Title**: Build Reconstruction Obligation Ledger

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Generate the complete deterministic ReconstructionObligationLedger from an authenticated Evidence bundle, reviewed obligations, and an explicit reconstruction manifest. Static candidates remain candidates; duplicate ownership, missing original or reconstruction cases, missing parser/type, weak verifier authority, unenumerated claims, contradictions, dependencies, and residual unknowns fail closed. The inline result carries the full-ledger closure digest and typed per-obligation diagnostics.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli build-reconstruction-obligation-ledger <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli build-reconstruction-obligation-ledger /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `evidence_bundle`, `reviewed_obligations`, `manifest` |
| **Optional** | _None_ |

### 75. `evaluate_reconstruction_coverage`

**Title**: Evaluate Reconstruction Coverage

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Evaluate inline evidence-backed reconstruction coverage against one named boundary. Missing ownership or inventory is partial; stale, weak, truncated, skipped, unresolved, or conflicting tied verifier proof is unknown; contradictions, failed proof, missing owners, and authority routing fail closed.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli evaluate-reconstruction-coverage <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli evaluate-reconstruction-coverage /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `coverage`, `boundary_id` |
| **Optional** | _None_ |

### 76. `project_harmony_application_graph`

**Title**: Project Harmony Application Graph

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Project authenticated HarmonyOS HAP, HSP, or App Pack inventory Evidence into an execution-free application inventory. Reports packaging-model hints (Stage module.json versus FA config.json), exact component paths and hashes (manifests, Ark bytecode, resources, native libraries, JavaScript, signing), App Pack child packages, runtime-family hints, and path-based N-API bridge hypotheses without decoding Ark bytecode, parsing manifest semantics, or claiming observed runtime calls.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli project-harmony-application-graph <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli project-harmony-application-graph /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `inventory_evidence` |
| **Optional** | _None_ |

### 77. `export_evidence_bundle`

**Title**: Export Evidence Bundle

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Atomically write the session's deterministic Evidence bundle to the requested local path. Existing files require overwrite: true; records and manifests use canonical byte-stable ordering.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `export_evidence_bundle` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `export_evidence_bundle` on current target session"_ or call tool `export_evidence_bundle()`.

> ⚠️ **Why no CLI command?**
> `export_evidence_bundle` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `path` |
| **Optional** | `overwrite` |

### 78. `import_evidence_bundle`

**Title**: Import Evidence Bundle

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Read the JSON bundle at the supplied local path, validate every Evidence ID and canonical manifest, then atomically merge it. Imported content is data only and is never executed.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `import_evidence_bundle` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `import_evidence_bundle` on current target session"_ or call tool `import_evidence_bundle()`.

> ⚠️ **Why no CLI command?**
> `import_evidence_bundle` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `path` |
| **Optional** | _None_ |

### 79. `get_evidence_bundle`

**Title**: Get Evidence Bundle

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Return every retained Evidence record and residual unknown as a complete canonical bundle by default. detail=summary discovers retained records without copying or transferring their payloads; optionally filter by exact Evidence ID, operation, target SHA-256, analysis-profile digest or canonical native procedure address. Metadata distinguishes complete record retention from native value-flow truncation or unavailable/unknown coverage. Use a discovered evidence_id with inspect_analysis_view without restarting a provider. Filters apply only to summary delivery.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `get_evidence_bundle` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `get_evidence_bundle` on current target session"_ or call tool `get_evidence_bundle()`.

> ⚠️ **Why no CLI command?**
> `get_evidence_bundle` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `detail`, `filters` |

### 80. `capture_process_scenario`

**Title**: Capture Process Scenario

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Run one caller-selected command under a PTY and return process capture Evidence with residual unknowns. The renderer admits at most 1,000,000 combined terminal cells, computed as columns × (rows + scrollback); every resize uses the selected scrollback and must fit the same budget. Supply a smaller terminal shape when that product is too large; dimensions are never clamped. A command name resolves through the inherited PATH; the working directory defaults to the caller's current directory; host environment variables are inherited with scenario overrides. Environment keys cannot contain '=' or NUL, and REA_PROCESS_RUN_ID is reserved for process ownership. Filesystem snapshots are opt-in through filesystem_observation_paths. A positive finalization_ms makes a timeout or idle deadline send SIGTERM to the captured root through its start identity, keep observing, and send SIGKILL once after the interval; exit.finalization records each attempt with its delivery result and the observed exit, and cancellation still ends the run at once. The target runs with the current user's permissions; this is not a security sandbox.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli capture-process-scenario <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli capture-process-scenario /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `executable` |
| **Optional** | `arguments`, `working_directory`, `environment`, `filesystem_observation_paths`, `terminal`, `events`, `timeout_ms`, `idle_timeout_ms`, `settle_ms`, `finalization_ms`, `limits`, `normalization` |

### 81. `compare_process_captures`

**Title**: Compare Process Captures

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Compare two compatible process capture observations across terminal, interaction, lifecycle, process, filesystem, command-shim, HTTP, and WebSocket evidence. Optional trace_spec validates exact events against an explicit partial order or finite trace language; concurrency is never inferred from timestamps or broad sorting. Missing, journal-free, or truncated observations are never treated as equivalent.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli compare-process-captures <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli compare-process-captures /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `left`, `right` |
| **Optional** | `trace_spec`, `max_capture_age_ms` |

### 82. `compare_artifacts`

**Title**: Compare Artifacts

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Compare complete artifact inventories by logical occurrence path, content identity, metadata, and graph relations. Pass the inventory Evidence nested in each inspect_artifact result as left and right. Every delta cites both inputs, and gaps yield truncated or unknown, never equivalence. Returns every change inline.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `compare_artifacts` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `compare_artifacts` on current target session"_ or call tool `compare_artifacts()`.

> ⚠️ **Why no CLI command?**
> `compare_artifacts` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `left`, `right` |
| **Optional** | _None_ |

### 83. `compare_functions`

**Title**: Compare Functions

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Compare two explicit sets of analyze_function Evidence across identity, exact provider text, calls, references, strings, and address-normalized CFG topology. Missing or provider-incompatible facets remain truncated or unknown; every conclusion cites both Evidence sets.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `compare_functions` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `compare_functions` on current target session"_ or call tool `compare_functions()`.

> ⚠️ **Why no CLI command?**
> `compare_functions` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `left`, `right` |
| **Optional** | _None_ |

### 84. `compare_bundles`

**Title**: Compare Bundles

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Compare two canonical Evidence bundles by exact record membership, explicit one-to-one observation pairs, and complete residual-unknown revision histories. Missing bundle members describe omission only, never behavioral equivalence; output is digest-anchored and returns every change inline.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli compare-bundles <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli compare-bundles /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `left_bundle_path`, `right_bundle_path` |
| **Optional** | `record_pairs` |

### 85. `find_changed_behavior`

**Title**: Find Changed Behavior

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Aggregate validated process and artifact comparison Evidence. Runtime observations remain distinct from static behavior candidates; missing or incomplete comparisons produce unresolved findings, never causal claims. Returns every finding inline.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `find_changed_behavior` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `find_changed_behavior` on current target session"_ or call tool `find_changed_behavior()`.

> ⚠️ **Why no CLI command?**
> `find_changed_behavior` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `comparisons` |
| **Optional** | _None_ |

### 86. `build_call_path`

**Title**: Build Call Path

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Build every shortest direct-callee path inline from complete analyze_function Evidence records using exact canonical addresses. Missing dossiers and provider mixing remain unknown; every node and edge cites source Evidence.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `build_call_path` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `build_call_path` on current target session"_ or call tool `build_call_path()`.

> ⚠️ **Why no CLI command?**
> `build_call_path` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `functions`, `start`, `goal` |
| **Optional** | _None_ |

### 87. `correlate_static_and_runtime`

**Title**: Correlate Static And Runtime

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Evaluate every explicit caller-declared hypothesis between exact static comparison findings and runtime comparison dimensions. Similar names or paths are never auto-matched, consistent cochange never proves causality, and unknown or truncated inputs remain unresolved. Returns all correlations and their complete Evidence closure inline.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `correlate_static_and_runtime` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `correlate_static_and_runtime` on current target session"_ or call tool `correlate_static_and_runtime()`.

> ⚠️ **Why no CLI command?**
> `correlate_static_and_runtime` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `static_comparisons`, `runtime_comparisons`, `mappings` |
| **Optional** | _None_ |

### 88. `verify_reconstruction`

**Title**: Verify Reconstruction

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Verify a finite typed behavioral and structural specification against a canonical Evidence bundle. Pass means every declared claim has complete comparable authority—not global source equivalence; changed claims fail and missing, limited, or unresolved evidence stays unknown.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `verify_reconstruction` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `verify_reconstruction` on current target session"_ or call tool `verify_reconstruction()`.

> ⚠️ **Why no CLI command?**
> `verify_reconstruction` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `specification` |
| **Optional** | _None_ |

### 89. `list_unknowns`

**Title**: List Unknowns

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: List current residual-unknown heads in deterministic ID order, with optional exact status, severity, and domain filters. Results are complete inline by default; supply offset and limit to page the filtered order. total is the matching-head count and next_offset is null when the page exhausts the result. This is read-only; unresolved, contradicted, and non-truth dispositions remain distinct.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `list_unknowns` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `list_unknowns` on current target session"_ or call tool `list_unknowns()`.

> ⚠️ **Why no CLI command?**
> `list_unknowns` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `status`, `severity`, `domain`, `offset`, `limit` |

### 90. `record_unknown`

**Title**: Record Unknown

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Create one deterministic residual unknown and immutable mutation evidence. Validates all evidence and relationship references, and rejects duplicate stable identity.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `record_unknown` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `record_unknown` on current target session"_ or call tool `record_unknown()`.

> ⚠️ **Why no CLI command?**
> `record_unknown` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `question`, `severity`, `domain`, `required_authority`, `required_confidence`, `required_environment`, `recommended_probes`, `relationships` |
| **Optional** | `comparison_conclusion_scope`, `supporting_evidence_ids`, `contradicting_evidence_ids` |

### 91. `update_unknown`

**Title**: Update Unknown

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Append one immutable full-state revision and mutation evidence. Requires exact expected_revision; stale concurrent writers fail instead of overwriting newer analysis.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `update_unknown` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `update_unknown` on current target session"_ or call tool `update_unknown()`.

> ⚠️ **Why no CLI command?**
> `update_unknown` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `unknown_id`, `expected_revision`, `status`, `severity`, `supporting_evidence_ids`, `contradicting_evidence_ids`, `required_authority`, `required_confidence`, `required_environment`, `recommended_probes`, `relationships`, `resolution` |
| **Optional** | _None_ |

### 92. `verify_unknown_resolution`

**Title**: Verify Unknown Resolution

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Revalidate the current residual-unknown head against live bundled evidence, exact authority/confidence/environment requirements, and revision integrity. Withdrawn and out-of-scope dispositions are not truth claims.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `verify_unknown_resolution` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `verify_unknown_resolution` on current target session"_ or call tool `verify_unknown_resolution()`.

> ⚠️ **Why no CLI command?**
> `verify_unknown_resolution` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `unknown_id` |
| **Optional** | _None_ |

## <a id="apple-ios-macos-mach-o-analysis"></a>Apple, iOS & macOS Mach-O Analysis (10 Tools)

### 93. `get_navigation_context`

**Title**: Get Navigation Context

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Return the selected document, current address, and containing/current procedure in one provider-neutral result. The result reflects sequential provider observations, not an atomic cursor snapshot; a cursor outside any procedure returns procedure: null.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `get_navigation_context` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `get_navigation_context` on current target session"_ or call tool `get_navigation_context()`.

> ⚠️ **Why no CLI command?**
> `get_navigation_context` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `document` |

### 94. `get_objc_classes`

**Title**: Get Objc Classes

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Discover and deduplicate Objective-C class labels, optionally filtering by literal substring.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `get_objc_classes` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `get_objc_classes` on current target session"_ or call tool `get_objc_classes()`.

> ⚠️ **Why no CLI command?**
> `get_objc_classes` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `pattern` |

### 95. `get_objc_protocols`

**Title**: Get Objc Protocols

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Discover and deduplicate Objective-C and Swift protocol labels.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `get_objc_protocols` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `get_objc_protocols` on current target session"_ or call tool `get_objc_protocols()`.

> ⚠️ **Why no CLI command?**
> `get_objc_protocols` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | _None_ |

### 96. `analyze_swift_types`

**Title**: Analyze Swift Types

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Categorize analyzed Swift procedure names using their manglings or same-address Swift symbol aliases. Decodes legacy and literal modern nominal contexts into classes, structs, enums, protocols, and extensions. Preserves provider names and supporting mangled_names; unresolved categories appear in other and in unclassified, which remains inline even under category filters. Returns deduplicated procedure-name counts, not unique source types, plus identification limitations. Optionally select one category and/or apply a case-sensitive literal filter to provider names or supporting manglings; for example, use {category: "structs", pattern: "Pair"}.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `analyze_swift_types` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `analyze_swift_types` on current target session"_ or call tool `analyze_swift_types()`.

> ⚠️ **Why no CLI command?**
> `analyze_swift_types` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `category`, `pattern` |

### 97. `inspect_macho`

**Title**: Inspect Macho

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Inspect Mach-O slices, load commands, imports, exports, dependencies, build metadata, segments, sections, permissions, and exact command provenance without launching Hopper.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-macho <path>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-macho /workspace/targets/AppBinary
```

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | _None_ |

### 98. `inspect_plist`

**Title**: Inspect Plist

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Parse Info.plist from the active artifact by default, or pass any local plist path. Returns normalized JSON rather than plutil text.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-plist <path>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-plist /workspace/targets/Info.plist
```

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `path` |

### 99. `demangle_swift`

**Title**: Demangle Swift

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Demangle an ordered list of single-line Swift symbols without requiring Hopper. Each input returns demangled, unchanged, or invalid status.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli demangle-swift <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli demangle-swift /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `symbols` |
| **Optional** | _None_ |

### 100. `decode_interface_builder`

**Title**: Decode Interface Builder

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Decode compiled storyboard and nib archives inside the active Apple app bundle, including keyed property lists and NIBArchive object tables, into a bounded object, hierarchy, and connection graph. This is static archive parsing; unrecognized archive classes and unresolved code handlers remain explicit unknowns.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli decode-interface-builder
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli decode-interface-builder
```

_(Runs verification/inspection; requires no extra arguments)_

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `max_documents`, `max_objects`, `max_connections` |

### 101. `inspect_asset_catalog`

**Title**: Inspect Asset Catalog

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Inspect compiled Assets.car metadata in an active Apple app bundle. Returns stable paginated catalog and rendition records with raw assetutil metadata and catalog digests; rendition bytes are not extracted.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-asset-catalog
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-asset-catalog
```

_(Runs verification/inspection; requires no extra arguments)_

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `offset`, `limit` |

### 102. `trace_dylib_resolution`

**Title**: Trace Dylib Resolution

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Trace how dyld would resolve each Mach-O dylib load for the active Mach-O, or for every executable in the active .app bundle (the main app, XPC services, extensions, login items, helpers). Expands @executable_path, @loader_path, and @rpath through each process's LC_RPATH stack in dependents-first load order, and reports every candidate path with its outcome, the resolved image and digest, weak, re-export, and upward flags, and derived findings such as unresolved required loads or absent earlier @rpath candidates. Pure header parsing: nothing is executed, and absolute or system paths outside the analyzed root stay undetermined. Select roots or one architecture to narrow large bundles.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli trace-dylib-resolution
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli trace-dylib-resolution
```

_(Runs verification/inspection; requires no extra arguments)_

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `roots`, `architecture` |

## <a id="managed-specialized-runtimes-net-wasm-evm-go-"></a>Managed & Specialized Runtimes (.NET, WASM, EVM, Go) (10 Tools)

### 103. `project_apple_application_graph`

**Title**: Project Apple Application Graph

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Project authenticated IPA, macOS .app directory, ZIP, or DMG inventory Evidence into an execution-free Apple application inventory. Reports application roots, nested bundles with path-convention roles (app extensions, XPC services, login items, privileged helpers, system extensions, frameworks), launchd plists, exact component paths and hashes, runtime-family hints, and path-based bridge hypotheses without parsing plist/CMS semantics or claiming observed runtime calls.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli project-apple-application-graph <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli project-apple-application-graph /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `inventory_evidence` |
| **Optional** | _None_ |

### 104. `inspect_managed_artifact`

**Title**: Inspect Managed Artifact

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Inspect an explicit PE/CLI path, or the selected managed target, without loading or executing target code. Omitted or complete detail returns complete metadata inventories with original coverage. Select detail: "summary" on the first call for complete identity, PE/CLI, classification with its evidence, module/MVID, assembly, frameworks, returned-collection counts, coverage/issues and limitations. It retains complete Evidence and returns a distinct linked inspect_analysis_view summary. Page original references/resources/attributes with view kind managed and normalized_result.parent_evidence_id. Counts cover producer-returned rows; partial, unavailable or malformed metadata remains explicit and tokens remain build-local.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-managed-artifact
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-managed-artifact
```

_(Runs verification/inspection; requires no extra arguments)_

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `path`, `detail` |

### 105. `inspect_managed_members`

**Title**: Inspect Managed Members

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Inspect PE/CLI metadata members, signatures, raw CIL hashes, decoded-instruction-tuple hashes, separately reported exception regions, call edges, and field-access anchors without loading or executing target code. Select type_names to decode only the members of those exact declaring types, which keeps large assemblies such as a base class library within the representation budget. Metadata tokens are reported as build-local coordinates bound to the artifact SHA-256 and MVID; the tuple hash does not resolve them or fully commit control flow.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-managed-members
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-managed-members
```

_(Runs verification/inspection; requires no extra arguments)_

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `path`, `type_names` |

### 106. `inspect_managed_native_boundaries`

**Title**: Inspect Managed Native Boundaries

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Inspect PE/CLI ModuleRef, ImplMap/PInvoke declarations, CLI native-header indicators, and non-IL method implementation flags without loading or executing target code. Results are managed declarations and degraded native-boundary observations, not verified native exports or addresses.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-managed-native-boundaries
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-managed-native-boundaries
```

_(Runs verification/inspection; requires no extra arguments)_

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `path` |

### 107. `compare_managed_members`

**Title**: Compare Managed Members

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Compare two authenticated inspect_managed_members Evidence records using unique-only tiers: exact CIL/signature, exact declared type, name, and raw signature (decoded or not), and decoded structural method shape. Names alone are never a matching basis; a member whose signature was not decoded, or whose same-named counterpart's was not, stays unknown rather than added or removed. Metadata tokens remain build-local coordinates bound to each artifact SHA-256 and MVID, and the tuple digest does not itself remap them.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli compare-managed-members <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli compare-managed-members /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `left`, `right` |
| **Optional** | _None_ |

### 108. `verify_managed_native_boundaries`

**Title**: Verify Managed Native Boundaries

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Verify managed P/Invoke/native-boundary declarations against authenticated native export or function Evidence without executing managed code or translating managed metadata tokens into native addresses. The workflow preserves declaration-only, verified, inferred, contradicted, and unresolved states.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli verify-managed-native-boundaries <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli verify-managed-native-boundaries /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `managed_boundaries`, `native_observations` |
| **Optional** | _None_ |

### 109. `import_managed_reconstruction`

**Title**: Import Managed Reconstruction

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Import decompiler-produced managed reconstruction against authenticated inspect_managed_members Evidence. The workflow locks each method to artifact SHA-256, MVID, metadata token, signature hash, and the limited decoded-IL tuple hash, records the decompiler identity and options, and marks C# or pseudocode as analyst inference rather than canonical byte observation.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli import-managed-reconstruction <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli import-managed-reconstruction /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `static_members`, `decompiler`, `methods` |
| **Optional** | `notes` |

### 110. `project_managed_application_graph`

**Title**: Project Managed Application Graph

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Project authenticated managed artifact, member, and native-boundary Evidence into the provider-neutral application graph without executing managed code, loading assemblies, or translating managed metadata tokens to native addresses. The graph preserves managed static observations as managed-specific nodes linked to source Evidence.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli project-managed-application-graph
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli project-managed-application-graph
```

_(Runs verification/inspection; requires no extra arguments)_

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `managed_artifact`, `managed_members`, `managed_native_boundaries` |

### 111. `inspect_go_binary`

**Title**: Inspect Go Binary

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Inspect embedded Go compiler version, main module, dependency/replacement versions and build settings in an explicit local ELF, PE or thin Mach-O image. Returns original artifact SHA-256, exact build-info source ranges, raw framed module bytes and unparsed module-text lines inline as observed Evidence. Supports inline and historical pointer encodings without installing Go, opening a disassembler, executing the target, writing temporary files or accessing the network. Missing metadata is reported as unknown, not proof that an image is not Go. Does not recover functions, source mappings, types or runtime behavior. Resource guards bound files to 256 MiB, aggregate embedded strings to 1 MiB, structural table decoding to 16 MiB and complete inline metadata to 8 MiB; malformed, unsupported and oversized inputs receive typed failures rather than partial success.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-go-binary <path>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-go-binary /workspace/targets/go_agent
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `path` |
| **Optional** | _None_ |

### 112. `inspect_wasm_artifact`

**Title**: Inspect Wasm Artifact

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Validate an explicit local WASM artifact with caller-supplied WABT 1.0.42. Omitted or complete detail returns exact byte SHA-256, sections, upstream import/export WAT forms and decoded WAT inline as Evidence. For counts, validation and WAT identity without WAT text, pass detail: "summary" on this first call; it retains the complete original Evidence and returns the same typed summary as inspect_analysis_view, avoiding oversized complete delivery. Read exact imports/exports or WAT pages with inspect_analysis_view using normalized_result.parent_evidence_id. Delivery selection does not change analysis, provider inputs or source identity. Optionally associate selected JavaScript glue literals with explicit local candidates while preserving ambiguous URL/basename matches. Configure absolute REA_WABT_BIN_DIRECTORY. No installation, implicit fetch, WASM execution or original-source claim.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-wasm-artifact <path>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-wasm-artifact /workspace/targets/module.wasm
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `path` |
| **Optional** | `glue_paths`, `candidate_paths`, `detail` |

## <a id="frida-dynamic-instrumentation"></a>Frida Dynamic Instrumentation (9 Tools)

### 113. `inspect_evm_interface`

**Title**: Inspect Evm Interface

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Inspect explicit local flat EVM bytecode without target execution or chain/RPC access. Select raw or hex encoding explicitly. Omitted or complete detail returns original carrier and decoded identities, full bytecode and all inferred interface candidates inline. For all inferred selectors/offsets/arguments/mutability and identities without bytecode hex or duplicated stdout, select detail: "summary" on this first call: it retains unchanged complete Evidence and returns a distinct linked inspect_analysis_view summary. Read original function rows or bytecode_hex/stdout/stderr text pages using view kind evm and normalized_result.parent_evidence_id; original complete Evidence remains accessible. Bytecode kind, hardfork, deployed authenticity and discovery completeness stay unknown; summary coverage covers only producer-returned candidates. Unchanged bundled EVMole 0.9.3/WASM in an owned bounded worker is initially real-verified on Linux x64; EOF-style EF00 containers are unsupported. No signature lookup, wallet action or transaction broadcast.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-evm-interface <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-evm-interface /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `path`, `encoding` |
| **Optional** | `detail` |

### 114. `list_frida_devices`

**Title**: List Frida Devices

**Tool Type**: 💻 **Direct CLI Command**

**Description**: List Frida devices currently available to this host, optionally connecting to the caller-selected remote Frida endpoint. Remote authentication options are used for this call only and are never returned or recorded.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli list-frida-devices
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli list-frida-devices
*(Lists local USB devices and remote endpoints attached to Frida)*
```

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `remote` |

### 115. `list_frida_processes`

**Title**: List Frida Processes

**Tool Type**: 💻 **Direct CLI Command**

**Description**: List processes observed on a selected Frida device or caller-supplied remote endpoint. A remote connection is closed after discovery; authentication values are never returned or recorded.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli list-frida-processes [--device-id <id>]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli list-frida-processes --device-id emulator-5554
```

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `device_id`, `remote` |

### 116. `start_frida_session`

**Title**: Start Frida Session

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Attach Frida to one selected process or spawn one selected target. Spawned targets remain paused until resume_frida_session, allowing scripts to load before execution. Closing a session detaches instrumentation; it does not kill the target.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `start_frida_session` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `start_frida_session` on current target session"_ or call tool `start_frida_session()`.

> ⚠️ **Why no CLI command?**
> `start_frida_session` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `mode` |
| **Optional** | `device_id`, `remote`, `pid`, `program`, `argv` |

### 117. `load_frida_script`

**Title**: Load Frida Script

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Load caller-supplied JavaScript into a Frida session. Scripts can read or change target memory and behavior and can access the target process's capabilities. Messages and script errors are returned inline as Evidence; source content is not persisted.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `load_frida_script` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `load_frida_script` on current target session"_ or call tool `load_frida_script()`.

> ⚠️ **Why no CLI command?**
> `load_frida_script` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `session_id`, `source_kind` |
| **Optional** | `source`, `path` |

### 118. `resume_frida_session`

**Title**: Resume Frida Session

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Resume the process created by a paused Frida spawn session. Attached processes are already running and cannot be resumed through this operation.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `resume_frida_session` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `resume_frida_session` on current target session"_ or call tool `resume_frida_session()`.

> ⚠️ **Why no CLI command?**
> `resume_frida_session` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `session_id` |
| **Optional** | _None_ |

### 119. `unload_frida_script`

**Title**: Unload Frida Script

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Unload one caller-selected Frida script from a live session. This removes that script's instrumentation from the target.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `unload_frida_script` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `unload_frida_script` on current target session"_ or call tool `unload_frida_script()`.

> ⚠️ **Why no CLI command?**
> `unload_frida_script` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `session_id`, `script_id` |
| **Optional** | _None_ |

### 120. `frida_session_status`

**Title**: Frida Session Status

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Return observed Frida session state and queued script messages. Message history is bounded by the provider capture budget and reports truncation.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `frida_session_status` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `frida_session_status` on current target session"_ or call tool `frida_session_status()`.

> ⚠️ **Why no CLI command?**
> `frida_session_status` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `session_id` |
| **Optional** | _None_ |

### 121. `close_frida_session`

**Title**: Close Frida Session

**Tool Type**: 🌐 **MCP Interactive Tool** _(Web GUI & AI Agent Session - No Standalone CLI)_

**Description**: Unload session scripts and detach REA's Frida session. If a spawned process is still paused, resume it before detaching so it is not left suspended. REA never kills the target; its final state is reported as unknown.

#### How to Use:

- **In Web GUI**: Open `http://localhost:6274` -> Go to **Tools** tab -> Select `close_frida_session` -> Click **Execute**.
- **With AI Agents (Cursor, Claude, Gemini)**: Ask in chat: _"Run `close_frida_session` on current target session"_ or call tool `close_frida_session()`.

> ⚠️ **Why no CLI command?**
> `close_frida_session` requires an active, connected disassembler or session state (like a cursor in Ghidra/Hopper/IDA). Terminal CLI commands run and exit immediately, so they have no persistent cursor to query.

| Parameter Type | Arguments |
| :--- |
| **Required** | `session_id` |
| **Optional** | _None_ |

## <a id="network-pcap-signal-analysis"></a>Network, PCAP & Signal Analysis (4 Tools)

### 122. `instrument_with_frida`

**Title**: Instrument With Frida

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Run one caller-authored Frida script against an explicitly selected process and detach when the observation window ends. The CLI and MCP share this ephemeral workflow; use MCP session operations for persistent sessions. Remote authentication is used only for this call and excluded from Evidence.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli instrument-with-frida <script_path> <process_id>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli instrument-with-frida /workspace/scripts/ssl_unpinning.js 1452
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `mode`, `source_kind` |
| **Optional** | `device_id`, `remote`, `pid`, `program`, `argv`, `source`, `path`, `duration_ms` |

### 123. `inspect_packet_capture`

**Title**: Inspect Packet Capture

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Inspect caller-selected fields in an existing local packet capture with TShark 4.x. Return 50 matching frames by default, with match_offset/match_limit paging and coverage counts; match_limit:null requests all remaining matches. Preserve repeated values, frame numbers, display filter, decode-as rules and pass mode in inline Evidence with source/tool identity and diagnostics. Optional packet_limit counts input packets before filtering; output paging does not shorten dissection or two-pass reassembly. Requires Linux, util-linux prlimit, and absolute REA_TSHARK_COMMAND. File-only analysis; no live capture or device communication. Missing fields or no matches do not establish absence of device traffic.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-packet-capture <path>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-packet-capture /workspace/targets/capture.pcap
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `path`, `fields` |
| **Optional** | `display_filter`, `decode_as`, `packet_limit`, `two_pass`, `match_offset`, `match_limit` |

### 124. `decode_signal_recording`

**Title**: Decode Signal Recording

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Decode an existing local logic/signal recording on Linux with sigrok-cli 0.7.2 and util-linux prlimit. Supply decoder stack, channels and options explicitly; optionally select input format and annotation classes. Return 50 literal output lines by default, with line_offset/line_limit paging; line_limit:null requests all remaining lines. Output windows count display lines, not annotations or samples, and do not shorten decoding. Preserve selected text, sample ranges, stderr, source/tool identity and coverage inline. Configure absolute REA_SIGROK_COMMAND. File-only analysis; no hardware acquisition or device communication. Empty output does not prove absence of traffic.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli decode-signal-recording <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli decode-signal-recording /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `path`, `decoders` |
| **Optional** | `input_format`, `annotations`, `line_offset`, `line_limit` |

### 125. `inspect_pcap_client`

**Title**: Inspect Pcap Client

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Inspect the caller-selected tshark and capinfos binaries: selected commands, selection sources, and versions. Both tools must be usable. Reads no capture file. REA never installs the Wireshark suite; select binaries with REA_TSHARK_COMMAND and REA_CAPINFOS_COMMAND (absolute) or from PATH.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-pcap-client
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-pcap-client
*(Validates local tshark and capinfos binary versions)*
```

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | _None_ |

## <a id="android-mobile-analysis"></a>Android & Mobile Analysis (12 Tools)

### 126. `inspect_pcap_capture`

**Title**: Inspect Pcap Capture

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Request detail summary for capture identity/counts, then page retained facts with inspect_analysis_view kind pcap. Default detail complete preserves inline delivery. Inspect one saved pcap or pcapng capture through an owned snapshot: metadata, exact packet count, SHA-256, IPv4/IPv6 address counts, DNS questions and address values from the same single-question response, TLS SNI, protocol distribution and HTTP URIs. All derived inventories are retained within declared resource budgets; unknown DNS attribution and excluded credentials remain explicit. Linux requires util-linux prlimit; Windows uses owned Job Objects. Requires caller-supplied capinfos and tshark; REA never captures traffic.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-pcap-capture <path>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-pcap-capture /workspace/targets/capture.pcap
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `path` |
| **Optional** | `detail` |

### 127. `inspect_android_package`

**Title**: Inspect Android Package

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Inspect a local APK's package, SDK and permission declarations, decoded manifest and class/resource counts. Omitted or complete detail preserves the complete result. Select detail: "summary" for all declarations, engine identity and counts without decoded manifest text or duplicate raw calls; retains the complete source and returns a distinct linked inspect_analysis_view summary. Read the exact retained manifest with view kind android, facet manifest, offset and limit (UTF-16 code units), using normalized_result.parent_evidence_id. Does not execute the APK or verify signatures. Requires a caller-supplied JADX MCP JAR and JDK; uses one worker in an isolated temporary workspace.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-android-package <path>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-android-package /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `path` |
| **Optional** | `detail` |

### 128. `search_android_classes`

**Title**: Search Android Classes

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Search complete decompiler class-name rows in an explicit local APK by case-sensitive substring. Empty query inventories all rows. Repeated names remain repeated and appear in duplicate_names; the provider accepts only class names for lookup, so these rows do not identify which same-name class node a later lookup selects. Retains artifact and engine identity; no APK execution.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli search-android-classes <path> <query>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli search-android-classes /workspace/targets/SMIS-Parents-app-v0.1.apk MainActivity
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `path`, `query` |
| **Optional** | _None_ |

### 129. `inspect_android_class`

**Title**: Inspect Android Class

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Inspect one exact Android class's parsed methods, fields and inner classes, including synthetic members. Returns display signatures and explicit unknown DEX descriptors without generating source. Overload indices remain consistent within the artifact and engine session.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-android-class <path> <className>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-android-class /workspace/targets/SMIS-Parents-app-v0.1.apk com.cspp_mobiles.MainActivity
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `path`, `class_name` |
| **Optional** | _None_ |

### 130. `inspect_android_method`

**Title**: Inspect Android Method

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Decompile one Android method with smali fallback. Requires explicit overload_index when multiple methods share a name. Reports representation, fallback markers and source truncation; never treats display signatures as exact DEX identities.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-android-method <path> <className> <methodName>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-android-method /workspace/targets/SMIS-Parents-app-v0.1.apk com.cspp_mobiles.MainActivity "<init>"
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `path`, `class_name`, `method_name` |
| **Optional** | `overload_index` |

### 131. `trace_android_references`

**Title**: Trace Android References

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Trace incoming static references to an exact Android class or unique method. Overloaded method reference queries are explicitly unsupported by the current engine. Source lines and DEX offsets remain unknown; no runtime calls are inferred.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli trace-android-references <path> <className>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli trace-android-references /workspace/targets/SMIS-Parents-app-v0.1.apk com.cspp_mobiles.MainActivity
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `path`, `class_name` |
| **Optional** | `method_name` |

### 132. `inspect_jeb_client`

**Title**: Inspect Jeb Client

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Inspect the running JEB client serving MCP: engine version, GUI or headless mode, and startup time. Does not open a target. Requires a caller-started JEB client reachable at REA_JEB_MCP_URL (default http://127.0.0.1:8425/mcp); REA never installs or launches JEB.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-jeb-client
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-jeb-client
```

_(Runs verification/inspection; requires no extra arguments)_

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | _None_ |

### 133. `open_jeb_project`

**Title**: Open Jeb Project

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Open or create a JEB project from an artifact file or existing .jdb2 database on the engine host. Returns the project's input-file digests and top-level units. The engine analyzes the target itself; REA does not read the file or execute it. Fails when a project is already open.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli open-jeb-project <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli open-jeb-project /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `path` |
| **Optional** | _None_ |

### 134. `list_jeb_units`

**Title**: List Jeb Units

**Tool Type**: 💻 **Direct CLI Command**

**Description**: List project units by stable unit path and type, with optional wildcard filter, parent restriction, and pagination. The engine caps pages at 100 units; a full page reports partial coverage because more units may exist. Read-only.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli list-jeb-units
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli list-jeb-units
```

_(Runs verification/inspection; requires no extra arguments)_

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `filter`, `parent_unit_path`, `index`, `count` |

### 135. `decompile_jeb_item`

**Title**: Decompile Jeb Item

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Decompile one type or method to engine pseudo-code using its decompiler (Dalvik, Java, or native). item_address comes from the engine's code item listing; unit_path defaults to the engine's first code unit and stays unknown when omitted. Read-only with respect to the target file.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli decompile-jeb-item <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli decompile-jeb-item /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `item_address`, `item_kind` |
| **Optional** | `unit_path` |

### 136. `inspect_apktool_client`

**Title**: Inspect Apktool Client

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Inspect the caller-selected apktool launcher: resolved command, selection source, and version. Decodes nothing. REA never installs Apktool or Java; select a launcher with REA_APKTOOL_COMMAND (absolute) or apktool on PATH.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-apktool-client
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-apktool-client
*(Checks if apktool is configured and reports version)*
```

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | _None_ |

### 137. `decode_android_resources`

**Title**: Decode Android Resources

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Decode one local APK's resources with `apktool d --no-src` in a provider-owned workspace that is removed after projection: the readable AndroidManifest.xml, apktool.yml version and SDK facts, the app's string resources (default or one locale, bounded to 2000 entries), available string locales, and the decoded file count. The target APK is digest with SHA-256 before decoding; smali is skipped because Java-source recovery belongs to the JADX family.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli decode-android-resources <path>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli decode-android-resources /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `path` |
| **Optional** | `include_strings`, `locale` |

## <a id="firmware-embedded-systems"></a>Firmware & Embedded Systems (2 Tools)

### 138. `project_android_application_graph`

**Title**: Project Android Application Graph

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Project authenticated APK inventory_artifact Evidence into an execution-free Android application inventory. Reports exact component paths and hashes, runtime-family hints, and path-based bridge hypotheses without decoding DEX, executing the APK, or claiming observed runtime calls.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli project-android-application-graph <path>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli project-android-application-graph /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `inventory_evidence` |
| **Optional** | _None_ |

### 139. `inspect_firmware_regions`

**Title**: Inspect Firmware Regions

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Inspect signature candidates in a local firmware file with Binwalk 3.1.x (verified with 3.1.0). Returns offsets, reported lengths, descriptions and raw confidence values. Length validation and runtime addresses remain unknown. No extraction or target execution. Linux, caller-supplied tool and util-linux prlimit required; 128 MiB input limit, one worker and 120-second deadline.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-firmware-regions <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-firmware-regions /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `path` |
| **Optional** | _None_ |

## <a id="web-javascript-electron-applications"></a>Web, JavaScript & Electron Applications (23 Tools)

### 140. `extract_firmware`

**Title**: Extract Firmware

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Extract caller-selected firmware bytes with Unblob 26.6.x (verified with 26.6.4) into an absent output directory. Returns verified child paths/digests, task derivations, unknown chunks and extraction diagnostics inline. Preserves the default sandbox; publishes regular files only. Linux, caller-supplied tool, format-specific extractors and util-linux prlimit required. No mounts or extracted-code execution. Select a returned native file with open_binary for Ghidra analysis; decompressed offsets are not original-file addresses.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli extract-firmware <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli extract-firmware /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `path`, `output_directory` |
| **Optional** | `range`, `max_depth`, `max_output_bytes`, `max_output_files` |

### 141. `trace_web_module_imports`

**Title**: Trace Web Module Imports

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Trace one exported website script's outgoing native ES imports/re-exports, using exact URL and optional selected import-map context. Reads a local export_web_scripts manifest and verifies the selected source's SHA-256/size; returns source positions, native resolved URLs or exact errors, every matching captured candidate and explicit unknown execution. Query/fragment identities are preserved. Computed imports and bundler IDs remain unknown. Select importer_url for unknown inline/document-base context. Caller-supplied Chromium executes only a trusted REA resolver stub in an owned context with page requests locally fulfilled/blocked; no captured application execution or asset refetch. Requires absolute REA_BROWSER_EXECUTABLE for literal imports. 32 MiB manifest, 16 MiB source, 4 MiB map and 20-second native deadline; cleanup may extend the deadline.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli trace-web-module-imports <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli trace-web-module-imports /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `manifest_path`, `script_index` |
| **Optional** | `importer_url`, `import_map` |

### 142. `trace_web_source_location`

**Title**: Trace Web Source Location

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Trace one generated position in an exported website script through an explicitly paired local source map. Verifies manifest, selected script and map SHA-256/byte identities; returns every equal-position mapping, reported source/root, resolved source URL, embedded sourcesContent and original position inline. One-based lines and zero-based UTF-16 columns; greatest generated position <= requested across lines. Duplicate sources and generated-only mappings remain distinct. Caller-selected pairing does not establish deployment authenticity or execution. Regular maps and inline indexed sections only; external section URLs are unsupported. No network access or application execution; uses the pinned upstream codec in an owned Node process with private temporary files, independent 192 MiB old-generation heap and 20-second deadline. 4 MiB map, 32 MiB reply; complete evidence or actionable resource failure. Cleanup may extend the deadline.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli trace-web-source-location <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli trace-web-source-location /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `manifest_path`, `script_index`, `source_map`, `generated_position` |
| **Optional** | _None_ |

### 143. `observe_web_execution`

**Title**: Observe Web Execution

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Instrument one selected CDP page for a finite, externally driven precise coverage window. Resets execution counters and prevents optimized execution until stopped. Returns complete nested UTF-16 ranges/counts, independently hashed script text and request initiator associations by session script ID. Does not navigate, click, evaluate selected code or close the externally owned page. Navigation ends document-scoped collection; workers and UI causality remain outside this claim. Emits an actual armed progress notification before external actions.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli observe-web-execution <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli observe-web-execution /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `cdp_endpoint`, `target_id` |
| **Optional** | `allowed_origins`, `observation_ms` |

### 144. `inspect_web_event_listeners`

**Title**: Inspect Web Event Listeners

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Inspect listeners registered directly on the first main-document CSS match in one selected CDP page. Returns event flags, native callback locations, source ownership and exact script text/digests inline. Does not dispatch events, evaluate JavaScript or invoke handlers. Delegated ancestor/framework listeners and execution history remain unknown. Releases REA's object group and transport, preserving the external page.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-web-event-listeners <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-web-event-listeners /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `cdp_endpoint`, `target_id`, `selector` |
| **Optional** | `allowed_origins` |

### 145. `inspect_web_network_capture`

**Title**: Inspect Web Network Capture

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Request detail summary for capture identity and counts; then page retained records with inspect_analysis_view kind capture (preview or complete), avoiding repeated decoding. Default detail complete preserves existing inline delivery. Inspect retained local HAR 1.2, native mitmproxy, Fiddler SAZ or aioquic 1.5.0 JSON qlog 0.3 events without contacting recorded URLs. Returns original ordinals, pointers/byte ranges/archive member names, preserved producer fields, precise numeric representations and exact exposed binary bytes inline. Excludes known transport credentials and explicitly marked values. Decodes every record before optional ordinal selection; malformed or oversized captures return no partial success. Duplicate JSON members are invalid; prototype-named members such as **proto** are preserved as ordinary own JSON members without prototype mutation. Qlog reports trace-scoped STREAM interval unions and endpoint loss declarations; it does not recover bodies, prove network loss or correlate PCAP. Other qlog layouts are unsupported. Uses pinned upstream parsers, owned temporary files and bounded offline processes. SAZ preserves HTTP fields, XML metadata and encoded body/message bytes without replay or HAR conversion; encrypted archives are unsupported. Native mitmproxy requires caller-supplied mitmdump 12.2.3 on Linux. Browser transaction IDs, runtime attribution and original bytes of HAR Unicode text remain unknown.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-web-network-capture <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-web-network-capture /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `capture_path`, `format` |
| **Optional** | `record_ordinals`, `sensitive_values`, `detail` |

### 146. `recover_javascript_sources`

**Title**: Recover Javascript Sources

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Recover readable modules from local UTF-8 JavaScript scripts/bundles into an absent directory, using caller-supplied Wakaru ^1.13.0 (verified with 1.14.0) on Linux x64. Use additional_paths for related chunks; each input retains its own snapshot and provenance. Returns original/derived digests, extraction byte ranges, emitted source maps, warnings and analysis_input inline. Structural splitting may fall back to one module; original names and runtime equivalence remain unknown. No application code execution. Requires util-linux prlimit; one worker, 1 GiB address-space ceiling, 120-second deadline, 64 MiB total input, 128 MiB output, 10000 entries and 8 MiB per diagnostic/report stream.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli recover-javascript-sources <bundle_path> <output_dir>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli recover-javascript-sources /workspace/targets/bundle.js /workspace/targets/decompiled_js/
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `path`, `output_directory` |
| **Optional** | `additional_paths`, `extraction_mode`, `rewrite_level` |

### 147. `export_web_scripts`

**Title**: Export Web Scripts

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Export JavaScript bytes already retained in one local inspect_web_page or capture_browser_scenario JSON capture (normalized result or complete Evidence). Writes scripts and a digest-verified manifest into an absent absolute output_directory. Returns all source URLs, script or transaction/event references, unavailable states, and an analysis_input for analyze_javascript_application when any bytes were exported. Include script sources in inspect_web_page or select capture.network.response_body in scenarios. No refetch or execution. Safe unambiguous URL layouts preserve relative module paths; versions, query variants, inline scripts, and path collisions are isolated with explicit resolution limitations.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli export-web-scripts <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli export-web-scripts /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `capture_path`, `output_directory` |
| **Optional** | _None_ |

### 148. `inspect_web_page`

**Title**: Inspect Web Page

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Passively inspect one selected page target through CDP without evaluating JavaScript, navigating, clicking, closing, or mutating the page. If no origin filter is supplied, capture is scoped to the target's current origin. Returns DOM structure, accessibility, scripts, resources, attach-window network and console metadata, workers, and redacted storage inventory as Evidence.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-web-page <url>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-web-page http://localhost:4173
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `cdp_endpoint`, `target_id` |
| **Optional** | `allowed_origins`, `observation_ms`, `include_accessibility_text`, `include_console_text`, `include_json_body_shapes`, `include_websocket_shapes`, `include_storage_keys`, `include_storage_fingerprints`, `include_script_sources` |

### 149. `analyze_web_bundle`

**Title**: Analyze Web Bundle

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Capture JavaScript source from one selected CDP page and statically derive a chunk graph, route and endpoint candidates, vendor fingerprints, page-declared WebMCP metadata, and optionally fetch source maps from the selected target origin or explicitly requested origins. JavaScript is parsed but never executed.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli analyze-web-bundle <entry_url>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli analyze-web-bundle http://localhost:4173/assets/index.js
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `cdp_endpoint`, `target_id` |
| **Optional** | `allowed_origins`, `observation_ms`, `include_accessibility_text`, `include_console_text`, `include_json_body_shapes`, `include_websocket_shapes`, `include_storage_keys`, `include_storage_fingerprints`, `include_script_sources`, `fetch_source_maps` |

### 150. `observe_web_session`

**Title**: Observe Web Session

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Arm a CDP observation window of the requested duration while the user operates the page. By default it follows the selected target's current origin; an explicit origin list controls which origins may be retained. Records navigation, redirect, lifecycle, and failure events.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli observe-web-session <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli observe-web-session /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `cdp_endpoint`, `target_id` |
| **Optional** | `allowed_origins`, `observation_ms` |

### 151. `discover_webmcp_tools`

**Title**: Discover Webmcp Tools

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Passively inventory every page-registered WebMCP tool and its complete structural input-schema summary using the experimental CDP WebMCP domain. Metadata is page-declared-untrusted; REA never registers or invokes discovered tools.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli discover-webmcp-tools <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli discover-webmcp-tools /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `cdp_endpoint`, `target_id` |
| **Optional** | `allowed_origins`, `observation_ms` |

### 152. `compare_web_captures`

**Title**: Compare Web Captures

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Compare passive web captures by providing before and after, each with the complete inspect_web_page normalized_result in inspection and an optional complete discover_webmcp_tools normalized_result in webmcp; or compare recorded scenarios by passing complete capture_browser_scenario normalized_result objects in before_scenario and after_scenario with an optional normalization policy. Use exactly one input group. Network comparison includes observed HTTP requests and WebSocket frame streams; same-URL connections are compared as an unordered collection of ordered streams, retaining connection counts without claiming stable identity between individual connections. Scenario comparison aligns exact step IDs, records deterministic literal normalization, and returns every artifact-level difference plus alignment failures inline. Missing or truncated evidence never proves equality.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli compare-web-captures
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli compare-web-captures
```

_(Runs verification/inspection; requires no extra arguments)_

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | `before`, `after`, `before_scenario`, `after_scenario`, `normalization` |

### 153. `capture_web_screenshot`

**Title**: Capture Web Screenshot

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Capture the current visible viewport of one configured page as an inline, content-addressed PNG artifact. The operation never scrolls, navigates, or evaluates page JavaScript.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli capture-web-screenshot <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli capture-web-screenshot /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `cdp_endpoint`, `target_id` |
| **Optional** | `allowed_origins` |

### 154. `compare_web_screenshots`

**Title**: Compare Web Screenshots

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Compare two self-verifying PNG screenshot artifacts with local pixel metrics. Returns exact changed-pixel ratios and channel deltas without OCR or external services.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli compare-web-screenshots <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli compare-web-screenshots /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `before`, `after` |
| **Optional** | `channel_threshold` |

### 155. `list_electron_targets`

**Title**: List Electron Targets

**Tool Type**: 💻 **Direct CLI Command**

**Description**: List every Electron file:// page target from a selected loopback CDP endpoint. Local file paths are canonicalized after symlink resolution. Selecting an endpoint exposes every eligible target and its local path metadata.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli list-electron-targets <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli list-electron-targets /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `cdp_endpoint` |
| **Optional** | _None_ |

### 156. `inspect_electron_page`

**Title**: Inspect Electron Page

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Passively inspect one Electron file page by supplying its loopback CDP endpoint and target ID. The provider rechecks that the target currently exists at that endpoint and is a local file page. Returns frames, DOM structure, resource paths, and scripts without evaluating renderer JavaScript or invoking Electron APIs. The selected endpoint exposes every local file page and its metadata to this tool.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-electron-page <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-electron-page /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `cdp_endpoint`, `target_id` |
| **Optional** | `observation_ms`, `include_script_sources` |

### 157. `analyze_javascript_application`

**Title**: Analyze Javascript Application

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Reconstruct one local ASAR or extracted JavaScript application as an inline application graph without executing it. Returns recovered graph nodes, edges, semantic relations, integrity contradictions, limitations, and coverage. Select source_paths to acquire and analyze only exact inventoried file paths; the complete artifact inventory and identity remain intact, and unselected sources remain explicit unknowns. Dependencies are not implicitly analyzed. Select detail summary to retain the complete analysis Evidence in this session and receive only its summary view, then inspect selected modules or pages with inspect_analysis_view. Summary detail reduces delivery, whereas source_paths bounds source analysis. Integrity mismatches fail by default; record-and-continue retains observed bytes as untrusted and marks graph coverage partial.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli analyze-javascript-application <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli analyze-javascript-application /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `input_path` |
| **Optional** | `format`, `integrity_policy`, `source_paths`, `max_semantic_nodes`, `max_semantic_nodes_per_file`, `max_heap_mb`, `analysis_timeout_ms`, `detail` |

### 158. `reconcile_javascript_runtime`

**Title**: Reconcile Javascript Runtime

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Reconcile verified static JavaScript application graphs with existing passive web/Electron CDP, passive V8 Inspector, or provider-owned active Electron Evidence. Active Electron captures contribute an explicitly partial target-only runtime record; they never invent renderer scripts, frames, workers, or execution claims. Exact captured-source digests take priority over caller-declared file/URL mappings; target, frame, script, and worker ambiguity remains explicit, and source-map authority stays separate.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli reconcile-javascript-runtime <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli reconcile-javascript-runtime /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `static_layers`, `runtime_observations` |
| **Optional** | _None_ |

### 159. `capture_electron_scenario`

**Title**: Capture Electron Scenario

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Use this for a provider-owned Electron run when passive CDP or Inspector observation cannot exercise application behavior. REA owns startup and teardown, accepts caller-defined click/wait actions plus window-targeted renderer reload/crash and synthetic open-url/second-instance delivery, and returns correlated window/WebContents/process/preload/session/navigation/shell/IPC evidence without retaining payload values. Actions wait for completion or request cancellation; a missing click target can keep the request pending. Results identify observed and unavailable event families, coverage status, action targets, and truncation. Cleanup failures retain collected observations with explicit cleanup uncertainty. External shell, navigation, permission, download, popup, updater, and OS-integration effects are blocked and recorded. Use passive Electron tools for observation-only work.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli capture-electron-scenario <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli capture-electron-scenario /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `executable_path`, `application_path` |
| **Optional** | `application_root`, `args`, `actions` |

### 160. `list_javascript_runtime_targets`

**Title**: List Javascript Runtime Targets

**Tool Type**: 💻 **Direct CLI Command**

**Description**: List every eligible Node/Electron V8 Inspector target from an explicit literal-loopback endpoint. Node discovery file locations that cannot be verified are preserved as unresolved reported URLs; they do not prove filesystem identity. Listing does not attach to targets.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli list-javascript-runtime-targets <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli list-javascript-runtime-targets /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `inspector_endpoint` |
| **Optional** | _None_ |

### 161. `observe_javascript_runtime`

**Title**: Observe Javascript Runtime

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Attach passively to one Node/Electron V8 Inspector target by supplying its loopback Inspector endpoint and target ID. The provider rechecks target presence and attachability; a Node discovery file location may remain unresolved. Loaded script locations are validated independently from Debugger.scriptParsed. Captures script and Runtime execution-context metadata. REA never evaluates, pauses, resumes, reads source, or instruments the target; require/import edges, EventEmitter activity, and Electron IPC remain explicit unknowns. Reconcile the result with static Application Graph Evidence using reconcile_javascript_runtime. The selected endpoint exposes every target it serves to this tool.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli observe-javascript-runtime <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli observe-javascript-runtime /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `inspector_endpoint`, `target_id` |
| **Optional** | `runtime_kind`, `observation_ms` |

### 162. `trace_javascript_semantics`

**Title**: Trace Javascript Semantics

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Trace static JavaScript data-flow, direct call/return, and closure relations from inline application Evidence or an exact same-session retained reference. Dynamic or unsupported semantics remain explicit unknowns; static reachability never claims runtime execution.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli trace-javascript-semantics <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli trace-javascript-semantics /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `application`, `query` |
| **Optional** | _None_ |

## <a id="android-debug-bridge-adb-dynamic-controls"></a>Android Debug Bridge (ADB) Dynamic Controls (24 Tools)

### 163. `compare_javascript_export_shapes`

**Title**: Compare Javascript Export Shapes

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Compare static return shapes for one exact module/export selector on each authenticated JavaScript Application Graph supplied as inline Evidence or exact same-session retained references. Variants pair only by reciprocal unique literal discriminants. Each retained variant lists observed return-property names even when values stay unknown. Presence (present, absent, or unknown-coverage) is separate from value resolution: a name present on only one paired shape is added or removed when parent-property coverage is complete on both sides, including when the static value is unresolved. Dynamic values, incomplete parent coverage, and unpaired variants remain unknown. Reports JSON Pointer changes without executing JavaScript; runtime behavior requires a separate agent-run probe.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli compare-javascript-export-shapes <target_file> [options]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli compare-javascript-export-shapes /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `left_module_path`, `left_export_name`, `right_module_path`, `right_export_name`, `left`, `right` |
| **Optional** | _None_ |

### 164. `inspect_adb_client`

**Title**: Inspect Adb Client

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Inspect the caller-selected adb client: resolved binary, version, and install path. Never contacts devices and never starts the adb server. REA never installs platform tools; select a binary with REA_ADB_PATH (absolute) or adb on PATH.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-adb-client
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-adb-client
*(Verifies host ADB server connectivity and version)*
```

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | _None_ |

### 165. `list_adb_devices`

**Title**: List Adb Devices

**Tool Type**: 💻 **Direct CLI Command**

**Description**: List attached devices exactly as `adb devices -l` reports them: serial, state, transport, model metadata, and an inferred emulator/physical kind with its evidence basis. Emulators and USB or network devices appear alike; REA neither starts nor manages them. May start the local adb server on first use.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli list-adb-devices
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli list-adb-devices
*(Lists all connected hardware phones and emulators with serial numbers)*
```

| Parameter Type | Arguments |
| :--- |
| **Required** | _None (This command requires no arguments)_ |
| **Optional** | _None_ |

### 166. `inspect_adb_device`

**Title**: Inspect Adb Device

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Inspect one device's build identity through a fixed `getprop` whitelist: Android and SDK versions, security patch, fingerprint, product identity, CPU ABIs, and debuggable flag, plus the observed emulator indicator ro.kernel.qemu. Read-only with respect to the device.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-adb-device <serial>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-adb-device emulator-5554
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `serial` |
| **Optional** | _None_ |

### 167. `list_adb_packages`

**Title**: List Adb Packages

**Tool Type**: 💻 **Direct CLI Command**

**Description**: List installed packages on one device with each base APK's device path, optionally scoped to third-party or system packages. Paths are device filesystem paths, not host-local. Read-only.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli list-adb-packages <serial>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli list-adb-packages emulator-5554
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `serial` |
| **Optional** | `scope` |

### 168. `pull_adb_package`

**Title**: Pull Adb Package

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Pull one installed package's complete APK set (base plus every split, as `pm path` reports) from the device into a caller-selected output directory, creating a package-named subdirectory that must not already exist. Every pulled file is digested with SHA-256; partial pulls keep successful artifacts and per-file failure reasons. The device keeps the originals.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli pull-adb-package <serial> <package> <output_dir>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli pull-adb-package emulator-5554 com.cspp_mobiles /workspace/targets/
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `serial`, `package`, `output_directory` |
| **Optional** | _None_ |

### 169. `read_adb_logcat`

**Title**: Read Adb Logcat

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Read a bounded dump of the device log (`logcat -d -t`) for one buffer, optionally restricted to a process id. No streaming, no clearing; the newest lines are kept when the count cap trims. Read-only.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli read-adb-logcat <serial> [--buffer <main|events|radio>]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli read-adb-logcat emulator-5554 --buffer main
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `serial` |
| **Optional** | `count`, `buffer`, `pid` |

### 170. `inspect_adb_package`

**Title**: Inspect Adb Package

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Inspect one installed package through `dumpsys package`: version name/code, install and update times, installer, user id, flags, and the requested-permission count. A fixed projection of version-dependent output; unknown sections are ignored rather than guessed. Read-only.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-adb-package <serial> <package>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-adb-package emulator-5554 com.cspp_mobiles
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `serial`, `package` |
| **Optional** | _None_ |

### 171. `pull_adb_file`

**Title**: Pull Adb File

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Pull one absolute device path (a database, shared-preferences XML, or any readable file) into a caller-selected output directory, digesting it with SHA-256. The local copy must not already exist. Read-only with respect to the device.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli pull-adb-file <serial> <device_path> <local_path>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli pull-adb-file emulator-5554 /data/local/tmp/app.apk /workspace/targets/pulled.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `serial`, `device_path`, `output_directory` |
| **Optional** | _None_ |

### 172. `push_adb_file`

**Title**: Push Adb File

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Push one local file to an absolute device path. The only device-mutating ADB tool: existing device files are refused unless overwrite is explicitly requested, and the transfer is verified by comparing the local digest with the device's own sha256sum when the device provides one.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli push-adb-file <serial> <local_path> <device_path>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli push-adb-file emulator-5554 /workspace/targets/SMIS-Parents-app-v0.1.apk /data/local/tmp/app.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `serial`, `local_path`, `device_path` |
| **Optional** | `overwrite` |

### 173. `capture_adb_screen`

**Title**: Capture Adb Screen

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Capture one frame of the device screen as a PNG (`screencap -p` through exec-out, no device-side file) into a caller-selected output directory, digesting it and reporting its dimensions. No recording or interaction.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli capture-adb-screen <serial> [--output-directory <dir>]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli capture-adb-screen emulator-5554 --output-directory /workspace/targets/
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `serial`, `output_directory` |
| **Optional** | _None_ |

### 174. `list_adb_processes`

**Title**: List Adb Processes

**Tool Type**: 💻 **Direct CLI Command**

**Description**: List running processes exactly as `ps -A` reports them: user, pid, ppid, rss, state, and name. Useful for pairing with instrumentation lanes. Read-only.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli list-adb-processes <serial>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli list-adb-processes emulator-5554
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `serial` |
| **Optional** | _None_ |

### 175. `list_adb_directory`

**Title**: List Adb Directory

**Tool Type**: 💻 **Direct CLI Command**

**Description**: List the immediate children of one absolute device directory, including hidden entries: names, kinds, permissions, owner, group, sizes, dates, and symlink targets. Names and targets preserve embedded newlines. Recognizes the standard errors for absent paths and denied reads. Read-only.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli list-adb-directory <serial> <path>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli list-adb-directory emulator-5554 /data/local/tmp/
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `serial`, `device_path` |
| **Optional** | _None_ |

### 176. `list_adb_features`

**Title**: List Adb Features

**Tool Type**: 💻 **Direct CLI Command**

**Description**: List the device's declared hardware and software features (`pm list features`) for device fingerprinting. Read-only.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli list-adb-features <serial>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli list-adb-features emulator-5554
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `serial` |
| **Optional** | _None_ |

### 177. `list_adb_services`

**Title**: List Adb Services

**Tool Type**: 💻 **Direct CLI Command**

**Description**: List the device's binder services with their interfaces (`service list`). Read-only.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli list-adb-services <serial>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli list-adb-services emulator-5554
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `serial` |
| **Optional** | _None_ |

### 178. `inspect_adb_display`

**Title**: Inspect Adb Display

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Report the display's physical and any overridden size (`wm size`) and density (`wm density`) as the device declares them. Read-only; setting values is not exposed.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-adb-display <serial>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-adb-display emulator-5554
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `serial` |
| **Optional** | _None_ |

### 179. `inspect_adb_window`

**Title**: Inspect Adb Window

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Report the window manager's current focus declarations (`dumpsys window windows`: mCurrentFocus and mFocusedApp) — what is on screen at read time without any interaction. Read-only.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-adb-window <serial>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-adb-window emulator-5554
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `serial` |
| **Optional** | _None_ |

### 180. `read_adb_setting`

**Title**: Read Adb Setting

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Read one settings value (`settings get`) from the system, secure, or global namespace. Absent keys report the device's own null observation. Read-only; writing settings is not exposed.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli read-adb-setting <serial> <namespace> <key>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli read-adb-setting emulator-5554 global airplane_mode_on
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `serial`, `namespace`, `key` |
| **Optional** | _None_ |

### 181. `collect_adb_bugreport`

**Title**: Collect Adb Bugreport

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Collect one device-generated bugreport archive (`adb bugreport`) into a caller-selected output directory, digesting the zip. The archive contains the device's own dumpstate, dumpsys, and logcat report; collection can take minutes. Read-only with respect to configuration.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli collect-adb-bugreport <serial> <output_dir>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli collect-adb-bugreport emulator-5554 /workspace/targets/
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `serial`, `output_directory` |
| **Optional** | _None_ |

### 182. `resolve_adb_packages`

**Title**: Resolve Adb Packages

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Find installed packages by case-insensitive substring of the package name (e.g. `whatsapp` → `com.whatsapp`), returning each match's base APK device path. The first step of an easy get: resolve, then pull_adb_package the exact name. Read-only.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli resolve-adb-packages <serial> <filter>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli resolve-adb-packages emulator-5554 smis
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `serial`, `query` |
| **Optional** | _None_ |

### 183. `install_adb_package`

**Title**: Install Adb Package

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Install one local APK on the device (`adb install [-r]`), recording the APK's host digest and byte size. A device-mutating tool: `replace` re-installs over an existing package while keeping its data; the device's own Success/Failure verdict is preserved with its reason.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli install-adb-package <path> [--serial <id>] [--replace]
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli install-adb-package /workspace/targets/SMIS-Parents-app-v0.1.apk --serial emulator-5554
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `serial`, `apk_path` |
| **Optional** | `replace` |

### 184. `uninstall_adb_package`

**Title**: Uninstall Adb Package

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Uninstall one package from the device (`adb uninstall`), removing its data for user 0. A device-mutating tool; absent packages report the device's own refusal reason.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli uninstall-adb-package <serial> <package>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli uninstall-adb-package emulator-5554 com.cspp_mobiles
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `serial`, `package` |
| **Optional** | _None_ |

### 185. `start_adb_app`

**Title**: Start Adb App

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Start one installed app's resolved launcher activity with `am start -W -n`. A device-mutating tool for dynamic analysis. The full wait report determines success; failures retain launch-attempt facts and raw output. Pair with `read_adb_logcat` (pid filter) and `list_adb_processes` to observe the app, and `stop_adb_app` to end the run.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli start-adb-app <serial> <package>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli start-adb-app emulator-5554 com.cspp_mobiles
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `serial`, `package` |
| **Optional** | _None_ |

### 186. `start_adb_activity`

**Title**: Start Adb Activity

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Start an intent with `am start -W`: one action, optional data URI, optional explicit component, and up to 16 typed extras (string, boolean, int, long, float). A device-mutating tool; the full wait report determines success, with failed-attempt facts and raw output retained.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli start-adb-activity <serial> <component>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli start-adb-activity emulator-5554 com.cspp_mobiles/.MainActivity
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `serial`, `action` |
| **Optional** | `data_uri`, `component`, `extras` |

## <a id="flutter-dart-reverse-engineering"></a>Flutter & Dart Reverse Engineering (2 Tools)

### 187. `stop_adb_app`

**Title**: Stop Adb App

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Force-stop every process of one package (`am force-stop`), ending a dynamic-analysis run. A device-mutating tool; it succeeds whether or not the package had running processes.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli stop-adb-app <serial> <package>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli stop-adb-app emulator-5554 com.cspp_mobiles
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `serial`, `package` |
| **Optional** | _None_ |

### 188. `identify_flutter_build`

**Title**: Identify Flutter Build

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Identify a Flutter app's build facts by pure parsing: the Dart VM snapshot hash from every lib/<abi>/libapp.so AOT section (vm and isolate, cross-checked), per-ABI library digests, the engine library's GNU build-id, and any labeled Dart version or toolchain strings libflutter.so carries. The snapshot hash is the artifact that maps to a Dart SDK release through an external dataset; REA performs no lookup. No engine, no execution, no external tools.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli identify-flutter-build <path>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli identify-flutter-build /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `path` |
| **Optional** | _None_ |

### 189. `inspect_dart_aot`

**Title**: Inspect Dart Aot

**Tool Type**: 💻 **Direct CLI Command**

**Description**: Inspect one ABI's Dart AOT snapshot inside an APK: the four snapshot symbols located through the ELF dynamic symbol table with their offsets, sizes, and section headers (magic, kind, length), the snapshot hash, and a bounded string-pool projection from the isolate data section (package: source URIs, dart: SDK URIs, identifier-like tokens) exposing the app's dependency structure. String-pool entries are byte-pattern observations, not deserialized cluster semantics; typed class and function recovery needs an SDK-specific parser. Omitted or complete detail returns the full observation. Select detail: "summary" for target/ABI/library identity, all snapshot headers, coverage and original lower-bound counts without string lists. The complete source stays retained; read returned strings via inspect_analysis_view with parent_evidence_id and kind dart-aot, collection package_uris/dart_uris/class_like_tokens, offset and limit. Exhausting pages does not imply complete pool coverage. No engine, no execution.

**CLI Syntax (Template)**:

```bash
./deploy/deploy.sh cli inspect-dart-aot <path>
```

**Real-World Example**:

```bash
./deploy/deploy.sh cli inspect-dart-aot /workspace/targets/SMIS-Parents-app-v0.1.apk
```

| Parameter Type | Arguments |
| :--- |
| **Required** | `path` |
| **Optional** | `abi`, `detail` |
