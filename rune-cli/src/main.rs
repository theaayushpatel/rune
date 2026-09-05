use arboard::Clipboard;
use clap::{Parser, Subcommand};
use colored::Colorize;
use crossterm::cursor::{Hide, MoveTo, Show};
use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, Clear, ClearType, EnterAlternateScreen,
    LeaveAlternateScreen,
};
use rune_adapter_aegis::AegisSource;
use rune_adapter_kdbx::KdbxSource;
use rune_adapter_twofas::TwoFasSource;
use rune_adapter_uri::UriSource;
use rune_core::models::OtpAccount;
use rune_core::otp::generate_account_code;
use rune_core::search::AccountSearcher;
use rune_core::source::Source;
use std::io::{stdout, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Parser, Debug)]
#[command(
    name = "rune",
    about = "Rune — A local-first, universal authenticator runtime",
    version = "0.1.0"
)]
struct Cli {
    /// Path to the authenticator source file (.kdbx for KeePassXC, .2fas for 2FAS, .json for Aegis, .uri/.txt for URIs)
    #[arg(short, long, global = true)]
    source: Option<PathBuf>,

    /// Decryption password for encrypted vaults (will prompt if required and not provided)
    #[arg(short, long, global = true)]
    password: Option<String>,

    /// Optional keyfile path for KeePassXC database decryption (.key / .keyx)
    #[arg(short = 'k', long, global = true)]
    keyfile: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List all accounts with current OTP codes and countdown timers
    List,
    /// Search accounts using fast in-memory fuzzy matching
    Search {
        /// Search query (matches issuer, username, or notes)
        query: String,
    },
    /// Output raw OTP code for automated scripting and terminal pipes
    Get {
        /// Account name or issuer to query
        query: String,
    },
    /// Generate and copy the OTP code to system clipboard
    Copy {
        /// Account name or issuer to query
        query: String,
    },
    /// Live terminal dashboard with auto-refreshing countdowns
    Watch,
    /// Decrypt an Aegis or 2FAS backup file and dump the JSON payload
    Decrypt {
        /// Path to the encrypted Aegis or 2FAS backup file
        file: PathBuf,
        /// Optional output file path (defaults to stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn is_kdbx_path(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    if ext == "kdbx" {
        return true;
    }
    if path.is_dir() {
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e.eq_ignore_ascii_case("kdbx"))
                    .unwrap_or(false)
                {
                    return true;
                }
            }
        }
    }
    false
}

fn is_twofas_path(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    if ext == "2fas" {
        return true;
    }
    if path.is_dir() {
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e.eq_ignore_ascii_case("2fas"))
                    .unwrap_or(false)
                {
                    return true;
                }
            }
        }
    }
    if ext == "json" {
        if let Ok(content) = std::fs::read_to_string(path) {
            if content.contains("servicesEncrypted")
                || (content.contains("schemaVersion") && content.contains("services"))
            {
                return true;
            }
        }
    }
    false
}

fn is_aegis_path(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    if ext == "enc" {
        return true;
    }
    if ext == "json" {
        return true;
    }
    if path.is_dir() {
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e.eq_ignore_ascii_case("json") || e.eq_ignore_ascii_case("enc"))
                    .unwrap_or(false)
                {
                    return true;
                }
            }
        }
    }
    false
}

/// Detect and load accounts from a source path, prompting for password if necessary.
fn load_accounts(
    source_path: Option<&Path>,
    cli_password: Option<&str>,
    cli_keyfile: Option<&Path>,
) -> Result<Vec<OtpAccount>, Box<dyn std::error::Error>> {
    let path = match source_path {
        Some(p) => p.to_path_buf(),
        None => {
            // Default discovery locations
            let candidates = [
                PathBuf::from("examples/sample.uri"),
                PathBuf::from("examples/keepass_vault.kdbx"),
                PathBuf::from("examples/2fas_plain.2fas"),
                PathBuf::from("examples/2fas_encrypted.2fas"),
                PathBuf::from("examples/aegis_plain.json"),
                PathBuf::from("examples/aegis_encrypted.json"),
            ];
            candidates
                .into_iter()
                .find(|p| p.exists())
                .ok_or("No source specified. Use --source <file> (e.g. --source examples/keepass_vault.kdbx)")?
        }
    };

    if !path.exists() {
        return Err(format!("Source file not found: {}", path.display()).into());
    }

    let is_dir = path.is_dir();

    if is_kdbx_path(&path) {
        let mut kdbx = KdbxSource::from_file(&path);
        if is_dir {
            let resolved = kdbx.resolve_file()?;
            eprintln!(
                "📁 Detected KeePassXC database folder: {}",
                path.display()
            );
            eprintln!(
                "   -> Auto-detected latest database: {}",
                resolved.file_name().unwrap_or_default().to_string_lossy()
            );
        }

        if let Some(kf) = cli_keyfile {
            kdbx = kdbx.with_keyfile(kf);
        }

        let password = match cli_password {
            Some(p) => Some(p.to_string()),
            None => {
                if cli_keyfile.is_some() {
                    let p = rpassword::prompt_password(format!(
                        "🔐 Enter password for KeePassXC database ({}) [press Enter if keyfile-only]: ",
                        path.display()
                    ))?;
                    if p.is_empty() {
                        None
                    } else {
                        Some(p)
                    }
                } else {
                    Some(rpassword::prompt_password(format!(
                        "🔐 Enter password for KeePassXC database ({}): ",
                        path.display()
                    ))?)
                }
            }
        };

        if let Some(pwd) = password {
            kdbx = kdbx.with_password(pwd);
        }

        let accounts = kdbx.load()?;
        Ok(accounts)
    } else if is_twofas_path(&path) {
        let mut twofas = TwoFasSource::from_file(&path);
        if is_dir {
            let resolved = twofas.resolve_file()?;
            eprintln!(
                "📁 Detected 2FAS backup folder: {}",
                path.display()
            );
            eprintln!(
                "   -> Auto-detected latest backup: {}",
                resolved.file_name().unwrap_or_default().to_string_lossy()
            );
        }

        if twofas.is_encrypted()? {
            let password = match cli_password {
                Some(p) => p.to_string(),
                None => rpassword::prompt_password(format!(
                    "🔐 Enter password for 2FAS backup ({}): ",
                    path.display()
                ))?,
            };
            twofas = twofas.with_password(password);
        }
        let accounts = twofas.load()?;
        Ok(accounts)
    } else if is_aegis_path(&path) {
        let mut aegis = AegisSource::from_file(&path);
        if is_dir {
            let resolved = aegis.resolve_file()?;
            eprintln!(
                "📁 Detected Aegis backup folder: {}",
                path.display()
            );
            eprintln!(
                "   -> Auto-detected latest backup: {}",
                resolved.file_name().unwrap_or_default().to_string_lossy()
            );
        }

        if aegis.is_encrypted()? {
            let password = match cli_password {
                Some(p) => p.to_string(),
                None => rpassword::prompt_password(format!(
                    "🔐 Enter password for Aegis vault ({}): ",
                    path.display()
                ))?,
            };
            aegis = aegis.with_password(password);
        }
        let accounts = aegis.load()?;
        Ok(accounts)
    } else {
        let uri_source = UriSource::from_file(&path);
        let accounts = uri_source.load()?;
        Ok(accounts)
    }
}

/// Render a clean ASCII progress bar for OTP remaining seconds.
fn render_progress_bar(remaining: u32, period: u32, width: usize) -> String {
    if period == 0 {
        return "".to_string();
    }
    let fraction = remaining as f64 / period as f64;
    let filled_len = (fraction * width as f64).round() as usize;
    let empty_len = width.saturating_sub(filled_len);

    let filled = "█".repeat(filled_len);
    let empty = "░".repeat(empty_len);

    if remaining <= 5 {
        format!("{filled}{empty}").red().to_string()
    } else if remaining <= 10 {
        format!("{filled}{empty}").yellow().to_string()
    } else {
        format!("{filled}{empty}").cyan().to_string()
    }
}

/// Format 6-digit or 8-digit OTP with visual grouping (e.g. "123 456").
fn format_otp_code(code: &str) -> String {
    if code.len() == 6 {
        format!("{} {}", &code[..3], &code[3..])
    } else if code.len() == 8 {
        format!("{} {}", &code[..4], &code[4..])
    } else {
        code.to_string()
    }
}

fn print_account_row(account: &OtpAccount, timestamp: u64) {
    let remaining = account.remaining_seconds(timestamp);
    let code_raw = generate_account_code(account, Some(timestamp))
        .unwrap_or_else(|e| format!("ERR: {e}"));
    let formatted_code = format_otp_code(&code_raw);

    let issuer = account.issuer_name().bold();
    let name = format!("({})", account.name).dimmed();
    let bar = render_progress_bar(remaining, account.period, 10);
    let sec_label = format!("{:2}s", remaining);

    let time_colored = if remaining <= 5 {
        sec_label.red()
    } else if remaining <= 10 {
        sec_label.yellow()
    } else {
        sec_label.green()
    };

    println!(
        "  {:18} {:22} {:>9}  {} {}",
        issuer,
        name,
        formatted_code.bold().green(),
        bar,
        time_colored
    );
}

fn run_watch_mode(accounts: Vec<OtpAccount>) -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen, Hide)?;

    let searcher = AccountSearcher::new();
    let mut query = String::new();
    let mut last_tick = Instant::now();

    loop {
        // Redraw
        execute!(stdout, MoveTo(0, 0), Clear(ClearType::All))?;

        let ts = now_secs();
        writeln!(
            stdout,
            "{}  {}",
            "⚡ RUNE AUTHENTICATOR".bold().cyan(),
            format!("(Total accounts: {})", accounts.len()).dimmed()
        )?;
        writeln!(
            stdout,
            "{}: {}_ (Press {} to exit, type to search)",
            "Search".bold(),
            query.yellow(),
            "Esc/q".dimmed()
        )?;
        writeln!(
            stdout,
            "{}",
            "─".repeat(65).dimmed()
        )?;

        let filtered = searcher.search(&accounts, &query);
        if filtered.is_empty() {
            writeln!(stdout, "  {}", "No matching accounts found.".dimmed())?;
        } else {
            for res in filtered.iter().take(15) {
                let acc = res.account;
                let remaining = acc.remaining_seconds(ts);
                let code_raw = generate_account_code(acc, Some(ts))
                    .unwrap_or_else(|e| format!("ERR: {e}"));
                let formatted_code = format_otp_code(&code_raw);

                let issuer = acc.issuer_name();
                let name = format!("({})", acc.name);
                let bar = render_progress_bar(remaining, acc.period, 10);
                let sec_label = format!("{:2}s", remaining);

                let time_colored = if remaining <= 5 {
                    sec_label.red()
                } else if remaining <= 10 {
                    sec_label.yellow()
                } else {
                    sec_label.green()
                };

                writeln!(
                    stdout,
                    "  {:16} {:20} {:>9}  {} {}",
                    issuer.bold(),
                    name.dimmed(),
                    formatted_code.bold().green(),
                    bar,
                    time_colored
                )?;
            }
        }

        stdout.flush()?;

        // Wait for event or 1-second timeout
        let timeout = Duration::from_millis(500)
            .checked_sub(last_tick.elapsed())
            .unwrap_or(Duration::from_millis(100));

        if event::poll(timeout)? {
            if let Event::Key(key_event) = event::read()? {
                match key_event.code {
                    KeyCode::Esc => break,
                    KeyCode::Char('q') if query.is_empty() => break,
                    KeyCode::Char('c')
                        if key_event.modifiers.contains(crossterm::event::KeyModifiers::CONTROL) =>
                    {
                        break;
                    }
                    KeyCode::Backspace => {
                        query.pop();
                    }
                    KeyCode::Char(c) => {
                        query.push(c);
                    }
                    _ => {}
                }
            }
        }

        if last_tick.elapsed() >= Duration::from_millis(500) {
            last_tick = Instant::now();
        }
    }

    execute!(stdout, Show, LeaveAlternateScreen)?;
    disable_raw_mode()?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command.unwrap_or(Commands::List) {
        Commands::List => {
            let accounts = load_accounts(
                cli.source.as_deref(),
                cli.password.as_deref(),
                cli.keyfile.as_deref(),
            )?;
            let ts = now_secs();

            println!();
            println!(
                "{}",
                format!("  Rune Authenticator — {} accounts", accounts.len())
                    .bold()
                    .cyan()
            );
            println!("  {}", "─".repeat(60).dimmed());

            for account in &accounts {
                print_account_row(account, ts);
            }
            println!();
        }

        Commands::Search { query } => {
            let accounts = load_accounts(
                cli.source.as_deref(),
                cli.password.as_deref(),
                cli.keyfile.as_deref(),
            )?;
            let searcher = AccountSearcher::new();
            let matches = searcher.search(&accounts, &query);

            let ts = now_secs();
            println!();
            println!(
                "{}",
                format!(
                    "  Search results for '{}' ({} found):",
                    query,
                    matches.len()
                )
                .bold()
                .cyan()
            );
            println!("  {}", "─".repeat(60).dimmed());

            for m in matches {
                print_account_row(m.account, ts);
            }
            println!();
        }

        Commands::Get { query } => {
            let accounts = load_accounts(
                cli.source.as_deref(),
                cli.password.as_deref(),
                cli.keyfile.as_deref(),
            )?;
            let searcher = AccountSearcher::new();
            let matches = searcher.search(&accounts, &query);

            if let Some(top_match) = matches.first() {
                let code = generate_account_code(top_match.account, None)?;
                println!("{code}");
            } else {
                eprintln!("Error: No account matching '{query}' found.");
                std::process::exit(1);
            }
        }

        Commands::Copy { query } => {
            let accounts = load_accounts(
                cli.source.as_deref(),
                cli.password.as_deref(),
                cli.keyfile.as_deref(),
            )?;
            let searcher = AccountSearcher::new();
            let matches = searcher.search(&accounts, &query);

            if let Some(top_match) = matches.first() {
                let code = generate_account_code(top_match.account, None)?;
                
                // On Linux/Wayland, wl-copy is preferred to avoid clipboard drop issues
                let mut copied = false;
                if std::env::var_os("WAYLAND_DISPLAY").is_some() {
                    if let Ok(mut child) = std::process::Command::new("wl-copy")
                        .stdin(std::process::Stdio::piped())
                        .spawn()
                    {
                        if let Some(mut stdin) = child.stdin.take() {
                            let _ = stdin.write_all(code.as_bytes());
                            let _ = stdin.flush();
                            drop(stdin);
                            let _ = child.wait();
                            copied = true;
                        }
                    }
                }

                if !copied {
                    if let Ok(mut clipboard) = Clipboard::new() {
                        let _ = clipboard.set_text(&code);
                    }
                }

                println!(
                    "{} Copied OTP {} for {} to clipboard",
                    "✓".bold().green(),
                    code.bold().green(),
                    top_match.account.display_label().bold()
                );
            } else {
                eprintln!("Error: No account matching '{query}' found.");
                std::process::exit(1);
            }
        }

        Commands::Watch => {
            let accounts = load_accounts(
                cli.source.as_deref(),
                cli.password.as_deref(),
                cli.keyfile.as_deref(),
            )?;
            run_watch_mode(accounts)?;
        }

        Commands::Decrypt { file, output } => {
            let accounts = if is_kdbx_path(&file) {
                let mut kdbx = KdbxSource::from_file(&file);
                if let Some(kf) = cli.keyfile.as_deref() {
                    kdbx = kdbx.with_keyfile(kf);
                }
                let password = match cli.password.as_deref() {
                    Some(p) => Some(p.to_string()),
                    None => {
                        if cli.keyfile.is_some() {
                            let p = rpassword::prompt_password(format!(
                                "🔐 Enter password for KeePassXC database ({}) [press Enter if keyfile-only]: ",
                                file.display()
                            ))?;
                            if p.is_empty() {
                                None
                            } else {
                                Some(p)
                            }
                        } else {
                            Some(rpassword::prompt_password(format!(
                                "🔐 Enter password for KeePassXC database ({}): ",
                                file.display()
                            ))?)
                        }
                    }
                };
                if let Some(pwd) = password {
                    kdbx = kdbx.with_password(pwd);
                }
                kdbx.load()?
            } else if is_twofas_path(&file) {
                let mut twofas = TwoFasSource::from_file(&file);
                if twofas.is_encrypted()? {
                    let password = match cli.password {
                        Some(p) => p,
                        None => rpassword::prompt_password(format!(
                            "🔐 Enter password for 2FAS backup ({}): ",
                            file.display()
                        ))?,
                    };
                    twofas = twofas.with_password(password);
                }
                twofas.load()?
            } else {
                let mut aegis = AegisSource::from_file(&file);
                if aegis.is_encrypted()? {
                    let password = match cli.password {
                        Some(p) => p,
                        None => rpassword::prompt_password(format!(
                            "🔐 Enter password for Aegis vault ({}): ",
                            file.display()
                        ))?,
                    };
                    aegis = aegis.with_password(password);
                }
                aegis.load()?
            };

            let json_out = serde_json::to_string_pretty(&accounts)?;

            if let Some(out_path) = output {
                std::fs::write(&out_path, json_out)?;
                println!(
                    "{} Decrypted {} accounts saved to {}",
                    "✓".bold().green(),
                    accounts.len(),
                    out_path.display()
                );
            } else {
                println!("{json_out}");
            }
        }
    }

    Ok(())
}
