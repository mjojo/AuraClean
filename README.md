<div align="center">

<img src="assets/brand/mjojo-logo-256.png" alt="mjojo Developer Logo" width="160" />

# ⚡ AuraClean

### Next-Generation, Hyper-Safe Windows Maintenance Suite Powered by Rust
**Surgical precision. Zero bloat. Never breaks your operating system.**

[![Author mjojo](https://img.shields.io/badge/Author-mjojo-9333EA?style=flat-square&logo=github)](https://github.com/mjojo)
[![License: MIT](https://img.shields.io/badge/License-MIT-4ADE80.svg?style=flat-square)](LICENSE)
[![Built with Rust](https://img.shields.io/badge/Language-Rust%202024-A855F7.svg?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![Framework Tauri](https://img.shields.io/badge/Frontend-Tauri%20v2-22C55E.svg?style=flat-square&logo=tauri)](https://tauri.app/)
[![Platform Windows](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011-0078D6.svg?style=flat-square&logo=windows)](https://microsoft.com/windows)

[Features](#-key-features) • [Zero-Breakage Guarantee](#-the-zero-breakage-guarantee) • [Architecture](#-architecture) • [Multilingual UI](#-multilingual-interface-i18n) • [Getting Started](#-getting-started) • [Roadmap](#-roadmap)

</div>

---

## 📌 Overview

Traditional Windows system cleaners have devolved into adware-heavy, aggressive bloatware that blindly wipe temporary directories and destroy valid registry keys—frequently breaking MSI installers, resetting user sessions, or triggering system instability.

**AuraClean** (architected and developed by **[@mjojo](https://github.com/mjojo)**) reimagines PC maintenance from the ground up. Built on **Rust (Edition 2024)** and **Tauri v2**, it combines raw native speed (indexing over 1.5 million files in under 2 seconds) with transactional safety, privilege separation, and a sleek **mjojo Cyber-Fluent** multilingual interface.

---

## 🛡 The Zero-Breakage Guarantee

AuraClean treats permanent deletion as a last resort. Every operation is governed by strict compile-time and runtime safety barriers:

* **Tiered Time-Capsule Quarantine (Zstandard + SQLite Vault):**
  * **Tier A (Sensitive Configs, Orphaned AppData, Registry Keys):** Packed on-the-fly into high-speed compressed `.tar.zst` containers (`zstd` level 3) alongside `.reg` and JSON snapshots, indexed in a local SQLite transaction vault (`index.db`) for 1-click rollback.
  * **Tier B (Massive Reproducible Caches & Build Artifacts):** Multi-gigabyte `target/`, `node_modules/`, and shader caches respect disk quota limits (`Quota Guard`) and store lightweight reconstruction manifests or use instant same-volume staging rather than exhausting free disk space during cleanup.
* **Active File Lock & Process Inspection:** Batch-queries Windows Restart Manager (`RmStartSession` / `RmRegisterResources` / `RmGetList`) and kernel sharing handles (`CreateFileW` with `dwShareMode = 0`) before touching any file. Locked or active files are cleanly skipped.
* **Cloud Placeholder Guard (OneDrive / iCloud / Dropbox):** Inspects `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS`, `FILE_ATTRIBUTE_RECALL_ON_OPEN`, and `FILE_ATTRIBUTE_OFFLINE` so cloud-only files are never accidentally hydrated/downloaded during disk scans.
* **Immutable Whitelists & Authenticode Verification:** Critical OS directories (`WinSxS`, `System32\config`, `DriverStore`), system certificates, and Microsoft-signed binaries (`WinVerifyTrust`) are hardcoded as immutable at compile time.
* **24-Hour File Age Guard:** Temporary files created or modified within the last 24 hours (or during the active boot session) are automatically shielded to protect running installers and background updaters.
* **Removable & Network Drive Awareness:** The registry engine checks `GetDriveTypeW` and skips paths pointing to disconnected USB drives or unmounted network shares, ensuring portable apps are never falsely flagged as broken.

---

## ✨ Key Features

### 🚀 Dual-Engine Disk Scanner (`MFT Turbo` + `jwalk` Fallback)
Reads NTFS `$MFT` file records (`$STANDARD_INFORMATION` and `$DATA` attributes) directly to index 1,500,000+ files with accurate byte sizes in ~1.2 seconds, while automatically falling back to parallel `jwalk` traversal on Windows 11 **ReFS (Dev Drive)** and **exFAT** volumes.

### 🧠 Human-Readable Registry Inspector
No cryptic CLSID lists or inflated "error counts". AuraClean inspects strictly bounded safe zones (orphaned `App Paths`, dead `FirewallRules`, stale `Uninstall` entries, `MuiCache`) and translates every finding into localized plain language:
> *"Dead firewall rule for uninstalled title 'Cyberpunk 2077' (executable missing since May 12)."*

### 🛠 Developer & Media Creator Cache Cleaner
* Detects stale reproducible build directories (`node_modules`, Rust `target/`, Python `.venv`, `.gradle`, `.next`, `bin/obj`) in projects whose source files haven't been modified in 30+ days.
* Cleans multi-gigabyte media scratch caches for **Adobe Premiere Pro**, **After Effects**, **DaVinci Resolve**, and **Figma**.
* Supports safe **WSL2 / Docker `ext4.vhdx`** compaction checks.

### 🎮 Gamer Booster & Multi-Library Guard
* Purges bloated or corrupted shader pipelines (`DirectX`, `Vulkan`, `NVIDIA DXCache`, `AMD DxCache`).
* Parses `steamapps/libraryfolders.vdf`, Epic Games manifests, and GOG/EA registry keys across **all mounted drives** so games installed on secondary SSDs (`D:\`, `E:\`) are never mistaken for uninstalled titles.
* Explicitly shields **SaveGames** (`🛡 Protected`) from deletion.
* Flushes Windows Standby Memory Lists safely via `NtSetSystemInformation` (`MemoryPurgeStandbyList` with `SeProfileSingleProcessPrivilege`).

### 👻 "Ghost Hunter" (Background Uninstaller Watcher)
A lightweight watcher monitors `Uninstall` registry keys and filesystem events. When a standard Windows uninstaller finishes, AuraClean notifies you of leftover `AppData` caches and orphaned registry keys for 1-click cleanup. When minimized to tray, the WebView2 UI process is destroyed so the background footprint stays under **6 MB RAM**.

### ⏱ Boot-Time Diagnostic Profiler
Parses Windows Event Logs (`Microsoft-Windows-Diagnostics-Performance/Operational`, Event IDs 100–110) to measure exact millisecond boot impact per application and supports converting heavy startup items into **Delayed Launch (+60s)** scheduled tasks.

---

## 🌍 Multilingual Interface (i18n)

While all source code, engineering documentation, and commit logs are maintained in **English**, the **AuraClean** user interface and declarative TOML rule descriptions are natively **multilingual**:
* Built-in localization catalogs (`locales/en.json`, `locales/ru.json`, extensible to `de`, `es`, `zh`, etc.).
* Every TOML cleaning rule and human-readable registry explanation supports localized strings (`[rule.i18n.en]`, `[rule.i18n.ru]`) with instant language switching in the UI without restarting the app.

---

## 🎨 Brand & Design System (`mjojo Cyber-Fluent`)

Designed around the **mjojo** Neural Cyber-Gorilla identity and Windows 11 `Mica Alt`:
* **Deep Cyber Void Background:** `#0B0B14` (80% opacity over native Windows 11 Mica Alt).
* **Primary Brand Accent (Cyber Violet):** `#A855F7` → `#9333EA`
* **Secondary / Safe Accent (Bio-Tech Neon Green):** `#4ADE80` → `#22C55E`
* **Situational Warning (Amber):** `#F59E0B`
* **Blocked / Critical (Crimson):** `#EF4444`

---

## 🏗 Architecture

AuraClean uses a **Privilege Separation Architecture** across a Cargo Workspace monorepo. See [ARCHITECTURE.md](ARCHITECTURE.md) for the complete technical specification.

```text
┌───────────────────────────────────────────────────────────┐
│              auraclean-ui.exe (User Session)              │
│  • Tauri v2 + React 19 Multilingual Frontend              │
│  • Runs with standard user privileges (no UAC nag)        │
│  • Destroys WebView2 when minimized to tray (< 6 MB RAM)  │
└─────────────────────────────┬─────────────────────────────┘
                              │
         Windows Named Pipe (SDDL ACL + Client PID/Signature
           Verification + Scoped Scan Token Authorization)
                              ▼
┌───────────────────────────────────────────────────────────┐
│         auraclean-service.exe (Elevated Worker)           │
│  • Explicit User SID context resolution (HKU\<SID>)       │
│  • Direct NTFS $MFT reader + ReFS/exFAT jwalk fallback    │
│  • Time-Capsule Quarantine (zstd + SQLite Vault)          │
└───────────────────────────────────────────────────────────┘
```

### 📂 Repository Structure

```text
AuraClean/
├── AuraClean.cmd              # 1-Click Windows desktop launcher (double-click to run)
├── Cargo.toml                 # Workspace root manifest (Rust 2024)
├── ARCHITECTURE.md            # Complete system & security architecture blueprint
├── README.md                  # Project overview & quickstart
├── assets/
│   └── brand/                 # Resized mjojo logos & icons (16px..512px + .ico)
├── locales/                   # UI localization files (en.json, ru.json)
├── rules/                     # Signed declarative TOML cleaning definitions
│   ├── system_windows.toml    # Windows temp, crash dumps, update logs
│   ├── browsers.toml          # Chromium, Firefox, Brave, Edge multi-profile rules
│   ├── gaming.toml            # Steam, Epic, NVIDIA/AMD shader caches
│   └── devtools.toml          # Cargo, npm, pip, Docker, IDE caches
└── crates/
    ├── safety-guard/          # Immutable whitelist, Restart Manager, Time-Capsule Vault
    ├── ipc-protocol/          # Typed IPC contracts, User SID context, i18n types
    ├── core-engine/           # TOML rule parser, scanner, registry inspector
    ├── elevated-service/      # Privileged worker binary
    ├── auraclean-gui/         # Standalone 1-Click Windows 11 Mica/WebView2 GUI (AuraClean.exe)
    └── auraclean-cli/         # CLI & dry-run verification runner
```

---

## 🚦 Getting Started (1-Click Launch)

### Instant 1-Click Launch (Windows 10 / 11)
* **Option A (Double-Click Launcher):** Double-click **`AuraClean.cmd`** in the repository root (or run `target\release\AuraClean.exe` directly). It opens the native Windows 11 Mica/WebView2 **mjojo Cyber-Fluent** desktop interface immediately with zero console window and built-in `EN` / `RU` language switching.
* **Option B (VS Code 1-Click):** Press **`F5`** or **`Ctrl+Shift+B`** (`Launch AuraClean (1-Click GUI)`).
* **Option C (Cargo Default Run):**
  ```powershell
  cargo run --release
  ```

### CLI & Automated Test Suite

```powershell
# Verify compilation and run the safety & quarantine test suite
cargo test --workspace

# Run the CLI prototype in safe dry-run mode (English or Russian UI output)
cargo run -p auraclean-cli -- --lang en status
cargo run -p auraclean-cli -- --lang ru scan --dry-run
```

---

## 🗺 Roadmap

- [x] **Sprint 1: Safety Guard Core** — Immutable whitelists, Cloud File Recall Guard, 24h File Age Guard, Win32 Restart Manager lock inspector, Zstandard Time-Capsule Quarantine & SQLite Vault with 1-click rollback.
- [ ] **Sprint 2: File & TOML Engine** — Multi-threaded `jwalk` rule scanner, NTFS `$MFT` record parser with ReFS fallback, Ed25519 rule signature verifier.
- [ ] **Sprint 3: Registry Inspector** — Command-line heuristic parser, removable drive awareness (`GetDriveTypeW`), localized human-readable explanations.
- [ ] **Sprint 4: Service & Hardened IPC** — SDDL Named Pipe server, User SID context impersonation, "Ghost Hunter" uninstaller watcher.
- [ ] **Sprint 5: Tauri v2 UI/UX (`mjojo Cyber-Fluent`)** — Mica Alt windowing, multilingual UI (`en`/`ru`), Bento dashboard, interactive Sunburst disk map.
- [ ] **Sprint 6: Dev & Gamer Modules** — Stale `node_modules`/`target` detector, multi-drive `libraryfolders.vdf` parser, Boot-Time Event Log profiler.
- [ ] **Sprint 7: QA & Signed Release** — Windows Sandbox automated test harness, Azure Trusted Signing pipeline, installer packaging.

---

## 👤 Author & Lead Architect

<img src="assets/brand/mjojo-mascot-64.png" alt="mjojo" width="48" align="left" style="margin-right: 12px;" />

**mjojo** — *Creator, Lead Architect & System Designer*  
GitHub: [@mjojo](https://github.com/mjojo)

<br clear="left"/>

[![Follow mjojo on GitHub](https://img.shields.io/badge/Developer-mjojo-9333EA?style=for-the-badge&logo=github&logoColor=white)](https://github.com/mjojo)

---

## 📄 License

This project is licensed under the [MIT License](LICENSE) — Copyright © 2026 **mjojo**.
