# Rune

> A local-first, universal authenticator runtime for Linux, macOS, and Windows.

Rune is a fast, secure, local-first runtime layer between existing authenticator data sources and the desktop experience. Unlike traditional authenticator apps, Rune does not require migrating secrets into a proprietary vault or creating cloud accounts. It reads your existing data read-only and generates OTP codes instantly.

---

## Workspace Architecture

```text
rune/
├── rune-core/               # Shared models (OtpAccount), RFC 6238/4226 engine, fuzzy search, Source trait
├── rune-adapters/
│   ├── uri/                 # otpauth:// URI parser and multiline collection file loader
│   ├── aegis/               # Aegis parser (plain JSON and AES-256-GCM + Scrypt encrypted backups)
│   ├── twofas/              # 2FAS parser (plain .2fas / JSON and AES-256-GCM + PBKDF2 encrypted backups)
│   └── kdbx/                # KeePassXC / KeePass (.kdbx) database reader for TOTP codes
├── rune-cli/                # Interactive command-line binary (list, search, get, copy, watch, decrypt)
├── rune-desktop/            # 100% Pure Native Rust Desktop App (egui/eframe, zero webview/container)
└── examples/                # Test fixtures (keepass_vault.kdbx, 2fas_plain.2fas, aegis_plain.json, sample.uri)
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
# List accounts with live countdown progress bars from KeePassXC database (.kdbx)
cargo run -p rune-cli -- list --source examples/keepass_vault.kdbx --password password123

# List accounts using keyfile or composite credentials
cargo run -p rune-cli -- list --source vault.kdbx --keyfile vault.key
cargo run -p rune-cli -- list --source vault.kdbx --password mypassword --keyfile vault.key

# List accounts from an URI collection file
cargo run -p rune-cli -- list --source examples/sample.uri

# List accounts from a 2FAS backup (.2fas or .json)
cargo run -p rune-cli -- list --source examples/2fas_plain.2fas

# List accounts from an encrypted 2FAS backup (prompts for password if omitted)
cargo run -p rune-cli -- list --source examples/2fas_encrypted.2fas --password example.com

# List accounts from an encrypted Aegis vault (prompts securely for password if omitted)
cargo run -p rune-cli -- list --source examples/aegis_encrypted.json --password test

# Instant in-memory fuzzy search
cargo run -p rune-cli -- search cloudflare --source examples/keepass_vault.kdbx --password password123

# Output only the raw OTP code (for terminal pipes, scripts, and automation)
cargo run -p rune-cli -- get octocat --source examples/keepass_vault.kdbx --password password123

# Generate and copy the current OTP code directly to clipboard
cargo run -p rune-cli -- copy github --source examples/sample.uri

# Launch interactive terminal watch mode (updates live every second with countdown bars)
cargo run -p rune-cli -- watch --source examples/keepass_vault.kdbx --password password123

# Decrypt a KeePassXC (.kdbx), Aegis, or 2FAS backup into standardized JSON
cargo run -p rune-cli -- decrypt examples/keepass_vault.kdbx --password password123
cargo run -p rune-cli -- decrypt examples/2fas_encrypted.2fas --password example.com
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
  - **Click `📁 Source`**: Switch between vaults, KeePassXC databases, and URI collections.

---

## Supported Sources (MVP)

1. **KeePass / KeePassXC (`.kdbx`) Databases**:
   - **Supported Versions**: KDBX 3.1, KDBX 4.0, and KDBX 4.1 databases.
   - **Authentication**: Master Password, Keyfile (`.key` / `.keyx`), or composite Master Password + Keyfile authentication.
   - **KeePassXC Native OTP**: Native `otp` field supporting `otpauth://` URIs, RFC 6238 key-value query strings (e.g. `key=...&step=30&size=6&algorithm=SHA1`), and raw Base32/Hex secret strings.
   - **KeePass2 Plugins & Community Formats**:
     - **TrayTOTP Plugin**: `TimeOtp-Secret-Base32`, `TimeOtp-Secret-Hex`, `TimeOtp-Period`, `TimeOtp-Length`, `TimeOtp-Algorithm` (`HMAC-SHA-1`, `HMAC-SHA-256`, `HMAC-SHA-512`), `HmacOTP-Secret-Base32`, and `HmacOTP-Counter`.
     - **KeeOTP / KeePassOTP**: `TOTP Seed` / `totpSeed` attributes with `TOTP Settings` / `totpSettings` syntax (e.g. `30;6`, `30;8;256`, `60;6;512`, `30;6;1`).
     - **KeePass2Android**: `kp2a_totp` custom string attributes.
     - **URL & Notes Fallback**: Embedded `otpauth://` URIs inside the entry's `URL` field or multi-line `Notes`.
   - **Hierarchy & Safety**: Recursive group traversal with automatic exclusion of `Recycle Bin` / `Trash` folders, and preservation of group breadcrumbs (`[Group/Subgroup]`).
   - **Sync Folder Auto-Detection**: Dynamic resolution (`find_latest_kdbx_file`) to automatically discover and read the newest `.kdbx` file in a synced folder (e.g., Nextcloud, Syncthing, Dropbox).

2. **2FAS Authenticator**:
   - Plain `.2fas` and `.json` backup files (supporting standard schemas and direct service exports).
   - Encrypted backups: encrypted with **AES-256-GCM** using keys derived via **PBKDF2-HMAC-SHA256** (10,000 iterations).
   - Sync folder auto-detection (`find_latest_2fas_backup`) to seamlessly detect and load the newest backup file.
   - Comprehensive token support: TOTP, HOTP (with counter), STEAM, and SHA1/SHA256/SHA512 algorithms.

3. **Aegis Authenticator**:
   - Plain JSON exports (`db.entries`).
   - Encrypted backups: encrypted with **AES-256-GCM** using keys derived via **Scrypt**. Secure password prompt and zeroization of sensitive memory.
   - Sync folder auto-detection (`find_latest_aegis_backup`).

4. **`otpauth://` URIs & Collections**:
   - Standard single URIs: `otpauth://totp/GitHub:user?secret=...&issuer=GitHub`
   - Collection files (`.uri`, `.txt`): line-delimited collections of URIs with comment support (`#`).

---

## Security Guarantees

- **Read-Only**: Rune never writes to or modifies your source files.
- **Local-Only**: No telemetry, no background networking, no analytics.
- **Memory Safety**: Raw secrets are decrypted strictly in-memory and cleared from memory using `zeroize`.
