<div align="center">

<img src="assets/brand/mjojo-logo-256.png" alt="mjojo Developer Logo" width="160" />

# ⚡ AuraClean

### Next-Generation, Hyper-Safe Windows Maintenance Suite Powered by Rust
**Surgical precision. Zero bloat. Never breaks your operating system.**

[![Author mjojo](https://img.shields.io/badge/Author-mjojo-9333EA?style=flat-square&logo=github)](https://github.com/mjojo)
[![Version v0.1.1](https://img.shields.io/badge/Release-v0.1.1-4ADE80?style=flat-square)](https://github.com/mjojo/AuraClean/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-4ADE80.svg?style=flat-square)](LICENSE)
[![Built with Rust](https://img.shields.io/badge/Language-Rust%202024-A855F7.svg?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![UI Engine](https://img.shields.io/badge/UI-Windows%2011%20Mica%20%2B%20WebView2-22C55E.svg?style=flat-square)](https://microsoft.com/windows)
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

* **Selective Time-Capsule Quarantine vs. Direct Delete:**
  * **Quarantine Vault (`ArchiveToVault`):** Reserved strictly for sensitive system changes, registry snapshots (`.reg` and JSON), crash dumps, startup state changes, and **Ghost Hunter** `AppData` remnants—stream-compressed via `zstd` (level 3) into `vault_{uuid}.tar.zst` and indexed in SQLite (`index.db`) for 1-click rollback.
  * **Direct Delete (`DirectDelete`):** Temporary files (`%TEMP%`), browser caches, GPU shader caches (`NVIDIA`/`AMD`/`DirectX`), and reproducible developer build artifacts (`target/`, `node_modules/`, `.venv`, `.gradle`) are deleted directly without wasting disk space in the quarantine vault.
* **Explicit User Permission & Per-Item Cleanup:** AuraClean never deletes anything automatically. Users can either review and authorize a batch cleanup via the **Safety Authorization Modal** or clean any individual rule, dev artifact, Ghost folder, or registry key one by one.
* **Custom Exclusions Whitelist (`exclusions.json`):** Users can add custom folder paths (including Cyrillic paths), file masks, or domains directly from the **Settings & Exclusions** tab to permanently shield them from all scans.
* **Full Hidden Folder (`AppData`) & Cyrillic (`UTF-16`) Path Support:** Resolves relocated or localized Windows Known Folders (`Documents` / `Мои документы`, hidden `AppData\Local`, `LocalLow`, `Roaming`, `ProgramData`) via Win32 `SHGetKnownFolderPath` (`UTF-16`) with full Unicode case-folding and intermediate wildcard expansion.
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

### ⏱ Boot & Startup Manager + 1-Click Report Export
* Inspects `HKCU` and `HKLM` `Run` startup entries with millisecond boot-impact estimates, allowing 1-click **Disable / Enable** or **Delay +60s** (automatically backed up in the Time-Capsule Vault).
* Includes a **Space Lens Category Distribution Chart**, live search/filter across all 8 tabs, **RAM Boost** (`GlobalMemoryStatusEx`), and 1-click **HTML & JSON Diagnostic Report Export**.

---

## 🌍 Multilingual Interface (6 Languages Built-In)

While all source code, engineering documentation, and commit logs are maintained in **English**, the **AuraClean** user interface is natively **multilingual** with instant 1-click switching across **6 languages**:
* **English (`EN`)**, **Russian (`RU`)**, **Ukrainian (`UA` / `UK`)**, **German (`DE`)**, **Spanish (`ES`)**, and **Simplified Chinese (`中文` / `ZH`)** (`locales/*.json`).
* Clean, distraction-free typography with zero emojis in the application UI and a pure CSS/vector **Cyber-Pulse Reactor** indicator.

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
├── Cargo.toml                 # Workspace root manifest (Rust 2024, v0.1.1)
├── ARCHITECTURE.md            # Complete system & security architecture blueprint
├── README.md                  # Project overview & quickstart
├── .github/workflows/ci.yml   # Automated Windows x86_64 Clippy, Test & Release CI
├── assets/
│   └── brand/                 # Resized mjojo logos & icons (16px..512px + .ico)
├── dist/
│   └── AuraClean-v0.1.1-win64.zip # Ready-to-distribute portable Windows x64 release
├── locales/                   # UI localization catalogs (en, ru, uk, de, es, zh)
├── rules/                     # 19 declarative TOML cleaning definitions
│   ├── system_windows.toml    # Windows temp, WER reports, Explorer thumbcache, crash dumps
│   ├── browsers.toml          # Chrome, Edge, Brave, Yandex, Firefox, Discord, Telegram
│   ├── gaming.toml            # Steam, NVIDIA/AMD/Direct3D shaders, My Games logs (SaveGames shielded)
│   └── devtools.toml          # npm, pip, VS Code V8/VSIX, Adobe Media Cache & Figma
└── crates/
    ├── safety-guard/          # Immutable whitelist, Restart Manager, Time-Capsule Vault
    ├── ipc-protocol/          # Typed IPC contracts, User SID context, 6-language Locale
    ├── core-engine/           # KnownFolders UTF-16 resolver, jwalk scanner, Registry & Deep scanners
    ├── elevated-service/      # Privileged worker binary
    ├── auraclean-gui/         # Standalone 1-Click Windows 11 Mica/WebView2 GUI (AuraClean.exe)
    └── auraclean-cli/         # CLI & dry-run verification runner
```

---

## 🚦 Getting Started (1-Click Launch)

### Instant 1-Click Launch (Windows 10 / 11)
* **Option A (Double-Click Launcher):** Double-click **`AuraClean.cmd`** in the repository root (or run `target\release\AuraClean.exe` or extract `dist\AuraClean-v0.1.1-win64.zip`). It opens the native Windows 11 Mica/WebView2 **mjojo Cyber-Fluent** desktop interface immediately with zero console window and built-in `EN` / `RU` / `UA` / `DE` / `ES` / `中文` language switching.
* **Option B (VS Code 1-Click):** Press **`F5`** or **`Ctrl+Shift+B`** (`Launch AuraClean (1-Click GUI)`).
* **Option C (Cargo Default Run):**
  ```powershell
  cargo run --release
  ```

### CLI & Automated Test Suite

```powershell
# Verify compilation and run the safety & quarantine test suite
cargo test --workspace

# Run the CLI prototype in safe dry-run mode (English, Russian, or Ukrainian output)
cargo run -p auraclean-cli -- --lang en status
cargo run -p auraclean-cli -- --lang ru scan --dry-run
cargo run -p auraclean-cli -- --lang uk status
```

---

## 🗺 Roadmap (v0.1.1 Complete)

- [x] **Sprint 1: Safety Guard Core** — Immutable whitelists, Cloud File Recall Guard, 24h File Age Guard, Win32 Restart Manager lock inspector, Zstandard Time-Capsule Quarantine & SQLite Vault with 1-click rollback.
- [x] **Sprint 2: File & TOML Engine** — Multi-threaded `jwalk` rule scanner, UTF-16 `SHGetKnownFolderPath` resolver for hidden `AppData` and Cyrillic `Documents` (`Мои документы`), 19 built-in rules.
- [x] **Sprint 3: Registry Inspector** — Command-line heuristic parser, removable drive awareness (`GetDriveTypeW`), localized human-readable explanations.
- [x] **Sprint 4: Service & Ghost Hunter** — Privileged service handler, Steam multi-drive `libraryfolders.vdf` resolver, and "Ghost Hunter" uninstalled app remnant detector.
- [x] **Sprint 5: `mjojo Cyber-Fluent` 1-Click UI** — Windows 11 Mica/Acrylic windowing, pure CSS/vector Cyber-Pulse Reactor, 6 languages (`EN`/`RU`/`UA`/`DE`/`ES`/`ZH`), Space Lens category distribution chart, live search filter, and Custom Exclusions Whitelist.
- [x] **Sprint 6: Dev, Gamer & Startup Modules** — Stale `node_modules`/`target`/`.venv` detector (`DirectDelete`), SaveGame shield, RAM Boost, and interactive Startup manager (`Disable` / `Delay +60s`).
- [x] **Sprint 7: CI/CD, Diagnostic Export & Portable Release** — 1-click HTML/JSON report export, GitHub Actions CI workflow, and portable `dist/AuraClean-v0.1.1-win64.zip` bundle.

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
