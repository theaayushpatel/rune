# Rune

> A local-first, universal authenticator runtime for Linux and Windows.

Rune is a fast, secure, local-first runtime layer between existing authenticator data sources and the desktop experience. Unlike traditional authenticator apps, Rune does not require migrating secrets into a proprietary vault or creating cloud accounts. It reads your existing data read-only and generates OTP codes instantly.

---

## Workspace Architecture

```text
rune/
├── rune-core/               # Shared models (OtpAccount), RFC 6238/4226 engine, fuzzy search, Source trait
├── rune-adapters/
│   ├── uri/                 # otpauth:// URI parser and multiline collection file loader
│   └── aegis/               # Aegis parser (plain JSON and AES-256-GCM + Scrypt encrypted backups)
├── rune-cli/                # Interactive command-line binary (list, search, get, copy, watch, decrypt)
├── rune-desktop/            # 100% Pure Native Rust Desktop App (egui/eframe, zero webview/container)
└── examples/                # Test fixtures (sample.uri, aegis_plain.json, aegis_encrypted.json)
```

---

## Installation (Desktop App & CLI in a Single Package)

Each release package contains **both** the Raycast-style desktop app (`rune-desktop`) and the terminal CLI (`rune`) with the official launcher icon:

### 🐧 Linux
- **Debian / Ubuntu / Pop!_OS (`.deb`)**:
  Download `rune_<version>_linux_amd64.deb` from GitHub Releases and install:
  ```bash
  sudo apt install ./rune_0.1.0_linux_amd64.deb
  ```
  *Installs both `rune-desktop` and `rune` CLI, adds the desktop launcher icon, and makes `rune` available in your terminal.*
- **Universal Linux (`.tar.gz`)**:
  Download `rune-linux-x86_64.tar.gz`, extract, and run the included installer:
  ```bash
  tar -xvf rune-linux-x86_64.tar.gz
  sudo ./install.sh
  ```

### 🪟 Windows
- **Unified Setup Installer (`.exe`)**:
  Download `rune-windows-x86_64-installer.exe` from GitHub Releases and run it.
  - Installs `rune-desktop.exe` and `rune.exe` into `C:\Program Files\Rune`.
  - Automatically adds Rune to your Windows `PATH` (run `rune` from PowerShell or CMD).
  - Creates Start Menu and Desktop shortcuts with `rune.ico`.
- **Portable ZIP**:
  Download `rune-windows-x86_64.zip` if you prefer a zero-install portable folder.

### 🍏 macOS (Apple Silicon & Intel)
- **Unified Disk Image (`.dmg`)**:
  Download `rune-macos-arm64.dmg` (M1/M2/M3/M4) or `rune-macos-x86_64.dmg` (Intel) from GitHub Releases:
  1. Open the `.dmg` and drag **Rune.app** into `/Applications`.
  2. Double-click **`Install CLI Command.command`** inside the DMG to install the `rune` terminal command to `/usr/local/bin/rune`.

---

## Quick Start

### 1. Build and Run Tests
Ensure Rust 1.80+ is installed.
```bash
cargo test --workspace
```

### 2. CLI Usage (`rune-cli`)

Compile or run the CLI directly with Cargo:

```bash
# List accounts with live countdown progress bars
cargo run -p rune-cli -- list --source examples/sample.uri

# List accounts from an encrypted Aegis vault (prompts securely for password if omitted)
cargo run -p rune-cli -- list --source examples/aegis_encrypted.json --password test

# Instant in-memory fuzzy search
cargo run -p rune-cli -- search air --source examples/aegis_encrypted.json --password test

# Output only the raw OTP code (for terminal pipes, scripts, and automation)
cargo run -p rune-cli -- get deno --source examples/aegis_encrypted.json --password test

# Generate and copy the current OTP code directly to clipboard
cargo run -p rune-cli -- copy github --source examples/sample.uri

# Launch interactive terminal watch mode (updates live every second with countdown bars)
cargo run -p rune-cli -- watch --source examples/sample.uri

# Decrypt an encrypted Aegis backup into standardized JSON
cargo run -p rune-cli -- decrypt examples/aegis_encrypted.json --password test
```

### 3. Native Desktop Application (`rune-desktop`)

Rune Desktop is a **100% Pure Native Rust GUI** (built with `eframe`/`egui`). It has **no webview**, **no browser container**, **no node_modules**, and **no localhost servers**. It compiles directly to native machine code with hardware-accelerated rendering and a Raycast-inspired floating window.

- **Run Native Desktop**:
  ```bash
  cargo run -p rune-desktop
  ```
  or run the binary directly:
  ```bash
  ./target/debug/rune-desktop
  ```

- **Raycast-Style Shortcuts**:
  - **Search**: Auto-focused on launch — type to filter accounts instantly.
  - **`↑` / `↓`**: Navigate accounts.
  - **`Enter`**: Copy the active OTP code to system clipboard.
  - **`Esc`**: Clear search query, or close the launcher if search is empty.
  - **Click `📁 Source`**: Switch between vaults and URI collections.

---

## Supported Sources (MVP)

1. **`otpauth://` URIs & Collections**:
   - Standard single URIs: `otpauth://totp/GitHub:user?secret=...&issuer=GitHub`
   - Collection files (`.uri`, `.txt`): line-delimited collections of URIs with comment support (`#`).
2. **Aegis Authenticator**:
   - Plain JSON exports (`db.entries`).
   - Encrypted backups: encrypted with **AES-256-GCM** using keys derived via **Scrypt**. Secure password prompt and zeroization of sensitive memory.

---

## Security Guarantees

- **Read-Only**: Rune never writes to or modifies your source files.
- **Local-Only**: No telemetry, no background networking, no analytics.
- **Memory Safety**: Raw secrets are decrypted strictly in-memory and cleared from memory using `zeroize`.
