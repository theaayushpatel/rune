use arboard::Clipboard;
use eframe::egui::{
    self, Color32, CornerRadius, FontId, Frame, Key, Margin, Pos2, RichText, Sense,
    Stroke, Vec2,
};
use rune_adapter_aegis::AegisSource;
use rune_adapter_kdbx::KdbxSource;
use rune_adapter_twofas::TwoFasSource;
use rune_adapter_uri::UriSource;
use rune_core::models::OtpAccount;
use rune_core::otp::generate_account_code;
use rune_core::search::AccountSearcher;
use rune_core::source::Source;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn copy_to_clipboard(text: &str) {
    let mut copied = false;
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        if let Ok(mut child) = std::process::Command::new("wl-copy")
            .stdin(std::process::Stdio::piped())
            .spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
                let _ = stdin.flush();
                drop(stdin);
                let _ = child.wait();
                copied = true;
            }
        }
    }

    if !copied {
        if let Ok(mut clipboard) = Clipboard::new() {
            let _ = clipboard.set_text(text);
        }
    }
}

fn format_otp(code: &str) -> String {
    if code.len() == 6 {
        format!("{} {}", &code[..3], &code[3..])
    } else if code.len() == 8 {
        format!("{} {}", &code[..4], &code[4..])
    } else {
        code.to_string()
    }
}

/// Path to persistent config file (~/.config/rune/sources.json or rune-sources.json)
fn get_config_path() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        let mut path = PathBuf::from(home);
        path.push(".config");
        path.push("rune");
        let _ = std::fs::create_dir_all(&path);
        path.push("sources.json");
        path
    } else {
        PathBuf::from("rune-sources.json")
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SourceConfig {
    pub name: String,
    pub path: PathBuf,
    pub password: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct AppConfig {
    pub sources: Vec<SourceConfig>,
    pub active_index: usize,
}

impl AppConfig {
    fn load() -> Self {
        let path = get_config_path();
        if path.exists() {
            if let Ok(data) = std::fs::read_to_string(&path) {
                if let Ok(cfg) = serde_json::from_str::<AppConfig>(&data) {
                    if !cfg.sources.is_empty() {
                        return cfg;
                    }
                }
            }
        }

        // Default seeds
        let mut defaults = Vec::new();
        let candidates = [
            ("Sample URIs", "examples/sample.uri", None),
            ("KeePassXC", "examples/keepass_vault.kdbx", Some("password123")),
            ("2FAS (Plain)", "examples/2fas_plain.2fas", None),
            ("2FAS (Encrypted)", "examples/2fas_encrypted.2fas", Some("example.com")),
            ("Aegis (Plain)", "examples/aegis_plain.json", None),
            ("Aegis (Encrypted)", "examples/aegis_encrypted.json", Some("test")),
        ];

        for (name, p_str, pwd) in candidates {
            let p = PathBuf::from(p_str);
            if p.exists() {
                defaults.push(SourceConfig {
                    name: name.to_string(),
                    path: p,
                    password: pwd.map(String::from),
                });
            }
        }

        let cfg = AppConfig {
            sources: defaults,
            active_index: 0,
        };
        cfg.save();
        cfg
    }

    fn save(&self) {
        let path = get_config_path();
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(path, json);
        }
    }
}

/// Draw a vector magnifying glass search icon aligned with the 28px search input
fn draw_search_icon(ui: &mut egui::Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(18.0, 28.0), Sense::hover());
    let p = ui.painter();
    let center = rect.center() + Vec2::new(-1.0, 0.0);
    let radius = 5.0;
    p.circle_stroke(center, radius, Stroke::new(1.6_f32, color));
    p.line_segment(
        [center + Vec2::new(3.5, 3.5), center + Vec2::new(7.0, 7.0)],
        Stroke::new(1.8_f32, color),
    );
}

/// Draw a vector close button aligned with the 28px header controls
fn draw_close_button(ui: &mut egui::Ui, text_muted: Color32, text_primary: Color32) -> bool {
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(18.0, 28.0), Sense::click());
    let color = if resp.hovered() { text_primary } else { text_muted };
    let p = ui.painter();
    let d = 4.0;
    p.line_segment(
        [rect.center() + Vec2::new(-d, -d), rect.center() + Vec2::new(d, d)],
        Stroke::new(1.5_f32, color),
    );
    p.line_segment(
        [rect.center() + Vec2::new(-d, d), rect.center() + Vec2::new(d, -d)],
        Stroke::new(1.5_f32, color),
    );
    resp.clicked()
}

/// Draw a vector gear icon for opening Settings
fn draw_gear_button(ui: &mut egui::Ui, text_muted: Color32, text_primary: Color32, active: bool) -> bool {
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(20.0, 28.0), Sense::click());
    let color = if active {
        Color32::from_rgb(16, 185, 129)
    } else if resp.hovered() {
        text_primary
    } else {
        text_muted
    };

    let p = ui.painter();
    let center = rect.center();

    // Gear body
    p.circle_stroke(center, 4.5_f32, Stroke::new(1.4_f32, color));
    p.circle_filled(center, 1.8_f32, color);

    // 4 teeth cogs
    for i in 0..4 {
        let angle = (i as f32) * std::f32::consts::PI / 2.0 + (std::f32::consts::PI / 4.0);
        let dir = Vec2::new(angle.cos(), angle.sin());
        p.line_segment([center + dir * 4.0, center + dir * 6.8], Stroke::new(1.6_f32, color));
    }

    resp.clicked()
}

/// Draw a keyboard shortcut keycap badge for RTL footer layout
fn draw_keycap_rtl(ui: &mut egui::Ui, key: &str, action: &str) {
    let keycap_bg = Color32::from_rgb(24, 30, 42);
    let keycap_border = Color32::from_rgb(45, 55, 72);
    let text_sec = Color32::from_rgb(148, 163, 184);
    let text_muted = Color32::from_rgb(100, 116, 139);

    ui.label(RichText::new(action).size(11.0).color(text_muted));
    ui.add_space(3.0);
    let frame = Frame::NONE
        .fill(keycap_bg)
        .stroke(Stroke::new(1.0_f32, keycap_border))
        .corner_radius(CornerRadius::same(4))
        .inner_margin(Margin::symmetric(5, 2));

    frame.show(ui, |ui| {
        ui.label(RichText::new(key).size(10.0).monospace().color(text_sec).strong());
    });
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SourceKind {
    Kdbx,
    TwoFas,
    Aegis,
    Uri,
}

fn detect_source_kind(path: &std::path::Path) -> SourceKind {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    if ext == "kdbx" {
        return SourceKind::Kdbx;
    }
    if ext == "2fas" {
        return SourceKind::TwoFas;
    }
    if path.is_dir() {
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let p = entry.path();
                if let Some(e) = p.extension().and_then(|e| e.to_str()) {
                    if e.eq_ignore_ascii_case("kdbx") {
                        return SourceKind::Kdbx;
                    }
                    if e.eq_ignore_ascii_case("2fas") {
                        return SourceKind::TwoFas;
                    }
                    if e.eq_ignore_ascii_case("json") || e.eq_ignore_ascii_case("enc") {
                        return SourceKind::Aegis;
                    }
                }
            }
        }
    }
    if ext == "json" {
        if let Ok(content) = std::fs::read_to_string(path) {
            if content.contains("servicesEncrypted")
                || (content.contains("schemaVersion") && content.contains("services"))
            {
                return SourceKind::TwoFas;
            }
        }
        return SourceKind::Aegis;
    }
    if ext == "enc" {
        return SourceKind::Aegis;
    }
    if path.is_dir() {
        return SourceKind::Aegis;
    }
    SourceKind::Uri
}

#[derive(Clone, Debug)]
struct SourceOption {
    name: String,
    path: PathBuf,
    is_dir: bool,
    kind: SourceKind,
    is_encrypted: bool,
    cached_password: Option<String>,
}

impl SourceOption {
    fn latest_file_name(&self) -> Option<String> {
        if self.is_dir {
            match self.kind {
                SourceKind::Kdbx => rune_adapter_kdbx::find_latest_kdbx_file(&self.path)
                    .ok()
                    .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string())),
                SourceKind::TwoFas => rune_adapter_twofas::find_latest_2fas_backup(&self.path)
                    .ok()
                    .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string())),
                SourceKind::Aegis => rune_adapter_aegis::find_latest_aegis_backup(&self.path)
                    .ok()
                    .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string())),
                SourceKind::Uri => None,
            }
        } else {
            self.path.file_name().map(|n| n.to_string_lossy().to_string())
        }
    }
}

#[derive(PartialEq, Eq, Copy, Clone, Debug)]
enum ViewMode {
    Launcher,
    Settings,
}

struct RuneApp {
    accounts: Vec<OtpAccount>,
    query: String,
    selected_index: usize,
    sources: Vec<SourceOption>,
    active_source_idx: usize,
    toast_message: Option<(String, Instant)>,
    pending_vault_path: Option<PathBuf>,
    password_input: String,
    password_error: Option<String>,
    show_source_picker: bool,
    first_frame: bool,
    view_mode: ViewMode,
    // Settings state
    new_src_name: String,
    new_src_path: String,
    new_src_password: String,
    new_src_status: Option<(bool, String)>,
    editing_pwd_idx: Option<usize>,
    editing_pwd_input: String,
    editing_pwd_error: Option<String>,
}

impl RuneApp {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let cfg = AppConfig::load();
        let mut sources = Vec::new();

        for s in cfg.sources {
            let is_dir = s.path.is_dir();
            let kind = detect_source_kind(&s.path);
            let is_enc = if s.path.exists() {
                match kind {
                    SourceKind::Kdbx => true,
                    SourceKind::TwoFas => TwoFasSource::from_file(&s.path).is_encrypted().unwrap_or(false),
                    SourceKind::Aegis => AegisSource::from_file(&s.path).is_encrypted().unwrap_or(false),
                    SourceKind::Uri => false,
                }
            } else {
                false
            };

            sources.push(SourceOption {
                name: s.name,
                path: s.path,
                is_dir,
                kind,
                is_encrypted: is_enc,
                cached_password: s.password,
            });
        }

        let active_idx = if cfg.active_index < sources.len() {
            cfg.active_index
        } else {
            0
        };

        let mut app = Self {
            accounts: Vec::new(),
            query: String::new(),
            selected_index: 0,
            sources,
            active_source_idx: active_idx,
            toast_message: None,
            pending_vault_path: None,
            password_input: String::new(),
            password_error: None,
            show_source_picker: false,
            first_frame: true,
            view_mode: ViewMode::Launcher,
            new_src_name: String::new(),
            new_src_path: String::new(),
            new_src_password: String::new(),
            new_src_status: None,
            editing_pwd_idx: None,
            editing_pwd_input: String::new(),
            editing_pwd_error: None,
        };

        if !app.sources.is_empty() {
            let pwd = app.sources[app.active_source_idx].cached_password.clone();
            app.load_active_source(pwd.as_deref(), false);
        }

        app
    }

    fn persist_sources(&self) {
        let configs = self
            .sources
            .iter()
            .map(|s| SourceConfig {
                name: s.name.clone(),
                path: s.path.clone(),
                password: s.cached_password.clone(),
            })
            .collect();

        let cfg = AppConfig {
            sources: configs,
            active_index: self.active_source_idx,
        };
        cfg.save();
    }

    fn load_active_source(&mut self, password: Option<&str>, notify: bool) {
        if self.sources.is_empty() {
            return;
        }

        let src = &self.sources[self.active_source_idx];
        let path = src.path.clone();

        match src.kind {
            SourceKind::Kdbx => {
                let mut kdbx = KdbxSource::from_file(&path);
                let effective_pwd = password.or(src.cached_password.as_deref());
                match effective_pwd {
                    Some(pwd) => {
                        kdbx = kdbx.with_password(pwd);
                        match kdbx.load() {
                            Ok(accs) => {
                                self.accounts = accs;
                                self.pending_vault_path = None;
                                self.password_error = None;
                                self.password_input.clear();
                                if notify {
                                    if src.is_dir {
                                        let rname = kdbx.resolve_file().ok().and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string())).unwrap_or_else(|| src.name.clone());
                                        self.set_toast(format!("Loaded latest: {rname}"));
                                    } else {
                                        self.set_toast(format!("Loaded {}", src.name));
                                    }
                                }
                            }
                            Err(e) => {
                                self.pending_vault_path = Some(path);
                                self.password_error = Some(e.to_string());
                            }
                        }
                    }
                    None => {
                        self.pending_vault_path = Some(path);
                        self.password_error = None;
                        self.password_input.clear();
                    }
                }
            }
            SourceKind::TwoFas => {
                let mut twofas = TwoFasSource::from_file(&path);
                let is_enc = twofas.is_encrypted().unwrap_or(false);

                if is_enc {
                    let effective_pwd = password.or(src.cached_password.as_deref());
                    match effective_pwd {
                        Some(pwd) => {
                            twofas = twofas.with_password(pwd);
                            match twofas.load() {
                                Ok(accs) => {
                                    self.accounts = accs;
                                    self.pending_vault_path = None;
                                    self.password_error = None;
                                    self.password_input.clear();
                                    if notify {
                                        if src.is_dir {
                                            let rname = twofas.resolve_file().ok().and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string())).unwrap_or_else(|| src.name.clone());
                                            self.set_toast(format!("Loaded latest: {rname}"));
                                        } else {
                                            self.set_toast(format!("Loaded {}", src.name));
                                        }
                                    }
                                }
                                Err(e) => {
                                    self.pending_vault_path = Some(path);
                                    self.password_error = Some(e.to_string());
                                }
                            }
                        }
                        None => {
                            self.pending_vault_path = Some(path);
                            self.password_error = None;
                            self.password_input.clear();
                        }
                    }
                } else if let Ok(accs) = twofas.load() {
                    self.accounts = accs;
                    if notify {
                        if src.is_dir {
                            let rname = twofas.resolve_file().ok().and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string())).unwrap_or_else(|| src.name.clone());
                            self.set_toast(format!("Loaded latest: {rname}"));
                        } else {
                            self.set_toast(format!("Loaded {}", src.name));
                        }
                    }
                }
            }
            SourceKind::Aegis => {
                let mut aegis = AegisSource::from_file(&path);
                let is_enc = aegis.is_encrypted().unwrap_or(false);

                if is_enc {
                    let effective_pwd = password.or(src.cached_password.as_deref());
                    match effective_pwd {
                        Some(pwd) => {
                            aegis = aegis.with_password(pwd);
                            match aegis.load() {
                                Ok(accs) => {
                                    self.accounts = accs;
                                    self.pending_vault_path = None;
                                    self.password_error = None;
                                    self.password_input.clear();
                                    if notify {
                                        if src.is_dir {
                                            let rname = aegis.resolve_file().ok().and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string())).unwrap_or_else(|| src.name.clone());
                                            self.set_toast(format!("Loaded latest: {rname}"));
                                        } else {
                                            self.set_toast(format!("Loaded {}", src.name));
                                        }
                                    }
                                }
                                Err(e) => {
                                    self.pending_vault_path = Some(path);
                                    self.password_error = Some(e.to_string());
                                }
                            }
                        }
                        None => {
                            self.pending_vault_path = Some(path);
                            self.password_error = None;
                            self.password_input.clear();
                        }
                    }
                } else if let Ok(accs) = aegis.load() {
                    self.accounts = accs;
                    if notify {
                        if src.is_dir {
                            let rname = aegis.resolve_file().ok().and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string())).unwrap_or_else(|| src.name.clone());
                            self.set_toast(format!("Loaded latest: {rname}"));
                        } else {
                            self.set_toast(format!("Loaded {}", src.name));
                        }
                    }
                }
            }
            SourceKind::Uri => {
                let uri_src = UriSource::from_file(&path);
                if let Ok(accs) = uri_src.load() {
                    self.accounts = accs;
                    if notify {
                        self.set_toast(format!("Loaded {}", src.name));
                    }
                }
            }
        }
        self.selected_index = 0;
    }

    fn set_toast(&mut self, msg: impl Into<String>) {
        self.toast_message = Some((msg.into(), Instant::now()));
    }

    fn trigger_copy(&mut self, account: &OtpAccount) {
        if let Ok(code) = generate_account_code(account, None) {
            copy_to_clipboard(&code);
            let label = account.issuer_name();
            self.set_toast(format!("Copied {} ({label}) to clipboard", format_otp(&code)));
        }
    }
}

impl eframe::App for RuneApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.request_repaint_after(Duration::from_millis(500));

        let ts = now_secs();

        // 1. Keyboard shortcuts
        let mut enter_pressed = false;
        let mut arrow_up_pressed = false;
        let mut arrow_down_pressed = false;
        let mut escape_pressed = false;
        let mut tab_pressed = false;
        let mut settings_toggle = false;

        ctx.input(|i| {
            if i.key_pressed(Key::Enter) {
                enter_pressed = true;
            }
            if i.key_pressed(Key::ArrowUp) {
                arrow_up_pressed = true;
            }
            if i.key_pressed(Key::ArrowDown) {
                arrow_down_pressed = true;
            }
            if i.key_pressed(Key::Escape) {
                escape_pressed = true;
            }
            if i.key_pressed(Key::Tab) {
                tab_pressed = true;
            }
            if i.modifiers.command && i.key_pressed(Key::Comma) {
                settings_toggle = true;
            }
        });

        if settings_toggle {
            self.view_mode = match self.view_mode {
                ViewMode::Launcher => ViewMode::Settings,
                ViewMode::Settings => ViewMode::Launcher,
            };
            self.show_source_picker = false;
        }

        // Tab cycles sources in Launcher mode
        if tab_pressed && self.view_mode == ViewMode::Launcher && !self.sources.is_empty() && self.pending_vault_path.is_none() {
            self.active_source_idx = (self.active_source_idx + 1) % self.sources.len();
            self.show_source_picker = false;
            let pwd = self.sources[self.active_source_idx].cached_password.clone();
            self.load_active_source(pwd.as_deref(), true);
            self.persist_sources();
        }

        // Search filtering
        let searcher = AccountSearcher::new();
        let matches: Vec<OtpAccount> = searcher
            .search(&self.accounts, &self.query)
            .into_iter()
            .map(|r| r.account.clone())
            .collect();

        // Navigation
        if self.view_mode == ViewMode::Launcher && !matches.is_empty() {
            if arrow_down_pressed {
                self.selected_index = (self.selected_index + 1) % matches.len();
            }
            if arrow_up_pressed {
                self.selected_index = (self.selected_index + matches.len() - 1) % matches.len();
            }
        }

        if escape_pressed {
            if self.show_source_picker {
                self.show_source_picker = false;
            } else if self.view_mode == ViewMode::Settings {
                self.view_mode = ViewMode::Launcher;
            } else if self.pending_vault_path.is_some() {
                self.pending_vault_path = None;
            } else if !self.query.is_empty() {
                self.query.clear();
                self.selected_index = 0;
            } else {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }

        let mut to_copy: Option<OtpAccount> = None;
        if enter_pressed && self.view_mode == ViewMode::Launcher && self.pending_vault_path.is_none() && !self.show_source_picker {
            if let Some(selected) = matches.get(self.selected_index) {
                to_copy = Some(selected.clone());
            }
        }

        // Theme Colors
        let bg_canvas = Color32::from_rgb(15, 18, 24);
        let border_subtle = Color32::from_rgb(36, 44, 58);
        let accent_emerald = Color32::from_rgb(16, 185, 129);
        let text_primary = Color32::from_rgb(248, 250, 252);
        let text_muted = Color32::from_rgb(100, 116, 139);

        // Global 30s progress
        let period = 30u32;
        let remaining = period - (ts % (period as u64)) as u32;
        let fraction = (remaining as f32 / period as f32).clamp(0.0, 1.0);

        let progress_color = if remaining <= 5 {
            Color32::from_rgb(244, 63, 94)
        } else if remaining <= 10 {
            Color32::from_rgb(245, 158, 11)
        } else {
            accent_emerald
        };

        let frame = Frame::NONE
            .fill(bg_canvas)
            .stroke(Stroke::new(1.0_f32, border_subtle))
            .corner_radius(CornerRadius::same(12));

        let mut switch_to_idx = None;
        let mut button_rect_opt = None;

        egui::CentralPanel::default().frame(frame).show(ctx, |ui| {
            match self.view_mode {
                ViewMode::Launcher => {
                    // Header: Draggable Top Bar with Aligned Search & Controls
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.add_space(12.0);

                        // Magnifying glass icon: 28px height aligned with input
                        draw_search_icon(ui, Color32::from_rgb(120, 136, 158));
                        ui.add_space(6.0);

                        // Borderless search input
                        let search_box = ui.add_sized(
                            Vec2::new(ui.available_width() - 230.0, 28.0),
                            egui::TextEdit::singleline(&mut self.query)
                                .hint_text("Search accounts or issuers...")
                                .text_color(text_primary)
                                .font(FontId::proportional(15.5))
                                .frame(false)
                                .margin(Margin::symmetric(0, 4)),
                        );

                        if self.first_frame {
                            search_box.request_focus();
                            self.first_frame = false;
                        }

                        // Right header controls
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.add_space(10.0);

                            // Close button
                            if draw_close_button(ui, text_muted, text_primary) {
                                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                            }

                            ui.add_space(4.0);

                            // Settings Gear Icon
                            if draw_gear_button(ui, text_muted, text_primary, false) {
                                self.view_mode = ViewMode::Settings;
                                self.show_source_picker = false;
                            }

                            ui.add_space(6.0);

                            // Aesthetic Source Button with Vector Chevron (no ASCII 'v')
                            let active_name = self
                                .sources
                                .get(self.active_source_idx)
                                .map(|s| s.name.as_str())
                                .unwrap_or("Source");

                            let btn_frame = Frame::NONE
                                .fill(Color32::from_rgb(24, 30, 42))
                                .stroke(Stroke::new(1.0_f32, Color32::from_rgb(45, 55, 75)))
                                .corner_radius(CornerRadius::same(5))
                                .inner_margin(Margin::symmetric(9, 5));

                            let btn_resp = btn_frame.show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label(
                                        RichText::new(active_name)
                                            .size(11.5)
                                            .color(Color32::from_rgb(175, 190, 210))
                                            .strong(),
                                    );
                                    ui.add_space(3.0);

                                    // Vector chevron
                                    let (c_rect, _) = ui.allocate_exact_size(Vec2::new(8.0, 10.0), Sense::hover());
                                    let p = ui.painter();
                                    let center = c_rect.center();
                                    let w = 3.0_f32;
                                    let h = if self.show_source_picker { -1.5_f32 } else { 1.5_f32 };
                                    let stroke = Stroke::new(1.4_f32, Color32::from_rgb(130, 145, 170));
                                    p.line_segment([center + Vec2::new(-w, -h), center + Vec2::new(0.0, h)], stroke);
                                    p.line_segment([center + Vec2::new(0.0, h), center + Vec2::new(w, -h)], stroke);
                                });
                            }).response;

                            button_rect_opt = Some(btn_resp.rect);

                            if btn_resp.interact(Sense::click()).clicked() {
                                self.show_source_picker = !self.show_source_picker;
                            }
                        });
                    });

                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(2.0);

                    // Password Prompt for Encrypted Vault (if opened without cached password)
                    let mut submit_password = false;
                    let mut cancel_password = false;
                    if let Some(vault_path) = self.pending_vault_path.clone() {
                        ui.group(|ui| {
                            let prompt_title = match self.sources.get(self.active_source_idx).map(|s| s.kind) {
                                Some(SourceKind::Kdbx) => "KeePassXC Database Password Required",
                                Some(SourceKind::TwoFas) => "Encrypted 2FAS Backup Password Required",
                                _ => "Encrypted Aegis Vault Password Required",
                            };
                            ui.label(
                                RichText::new(prompt_title)
                                    .strong()
                                    .color(Color32::from_rgb(245, 158, 11)),
                            );
                            ui.label(
                                RichText::new(format!("File: {}", vault_path.display()))
                                    .size(11.0)
                                    .color(text_muted),
                            );

                            if let Some(err) = &self.password_error {
                                ui.label(RichText::new(err).color(Color32::from_rgb(244, 63, 94)).size(11.0));
                            }

                            ui.horizontal(|ui| {
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.password_input)
                                        .password(true)
                                        .hint_text("Enter vault password..."),
                                );

                                if ui.button("Unlock & Cache").clicked() || enter_pressed {
                                    submit_password = true;
                                }

                                if ui.button("Cancel").clicked() {
                                    cancel_password = true;
                                }
                            });
                        });
                        ui.add_space(6.0);
                    }
                    if submit_password {
                        let pwd = self.password_input.clone();
                        if let Some(src) = self.sources.get_mut(self.active_source_idx) {
                            src.cached_password = Some(pwd.clone());
                        }
                        self.load_active_source(Some(&pwd), true);
                        self.persist_sources();
                    }
                    if cancel_password {
                        self.pending_vault_path = None;
                    }

                    // Account List
                    egui::ScrollArea::vertical()
                        .auto_shrink([false; 2])
                        .max_height(335.0)
                        .show(ui, |ui| {
                            if matches.is_empty() {
                                ui.vertical_centered(|ui| {
                                    ui.add_space(60.0);
                                    ui.label(RichText::new("🛡").size(28.0));
                                    ui.label(
                                        RichText::new(if self.query.is_empty() {
                                            "No accounts loaded"
                                        } else {
                                            "No matching accounts found"
                                        })
                                        .color(text_muted)
                                        .size(13.0),
                                    );
                                });
                            } else {
                                for (idx, account) in matches.iter().enumerate() {
                                    let is_selected = idx == self.selected_index;
                                    let code_raw = generate_account_code(account, Some(ts))
                                        .unwrap_or_else(|e| format!("ERR: {e}"));
                                    let formatted_code = format_otp(&code_raw);

                                    let row_bg = if is_selected {
                                        Color32::from_rgb(26, 36, 50)
                                    } else {
                                        Color32::TRANSPARENT
                                    };

                                    let row_frame = Frame::NONE
                                        .fill(row_bg)
                                        .stroke(if is_selected {
                                            Stroke::new(1.0_f32, accent_emerald)
                                        } else {
                                            Stroke::NONE
                                        })
                                        .corner_radius(CornerRadius::same(6))
                                        .inner_margin(Margin::symmetric(12, 8));

                                    let response = row_frame.show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.vertical(|ui| {
                                                ui.horizontal(|ui| {
                                                    ui.label(
                                                        RichText::new(account.issuer_name())
                                                            .strong()
                                                            .color(text_primary)
                                                            .size(13.5),
                                                    );

                                                    let tag_frame = Frame::NONE
                                                        .fill(Color32::from_rgb(24, 30, 42))
                                                        .corner_radius(CornerRadius::same(3))
                                                        .inner_margin(Margin::symmetric(4, 1));
                                                    tag_frame.show(ui, |ui| {
                                                        ui.label(
                                                            RichText::new(account.otp_type.to_string().to_uppercase())
                                                                .size(8.5)
                                                                .color(Color32::from_rgb(120, 136, 158)),
                                                        );
                                                    });
                                                });

                                                ui.label(
                                                    RichText::new(&account.name)
                                                        .color(text_muted)
                                                        .size(11.5),
                                                );
                                            });

                                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                ui.add_space(4.0);
                                                ui.label(
                                                    RichText::new(&formatted_code)
                                                        .color(accent_emerald)
                                                        .size(19.0)
                                                        .monospace()
                                                        .strong(),
                                                );
                                            });
                                        });
                                    });

                                    if response.response.interact(Sense::click()).clicked() {
                                        self.selected_index = idx;
                                        to_copy = Some(account.clone());
                                    }
                                }
                            }
                        });

                    // Progress Bar
                    ui.add_space(4.0);
                    let bar_width = ui.available_width();
                    let (bar_rect, _) = ui.allocate_exact_size(Vec2::new(bar_width, 3.0), Sense::hover());
                    let painter = ui.painter();
                    painter.rect_filled(bar_rect, CornerRadius::same(2), Color32::from_rgb(24, 30, 42));
                    let mut filled_rect = bar_rect;
                    filled_rect.max.x = bar_rect.min.x + (bar_rect.width() * fraction);
                    painter.rect_filled(filled_rect, CornerRadius::same(2), progress_color);

                    ui.add_space(4.0);

                    // Footer Bar: spacious layout that never overlaps
                    ui.horizontal(|ui| {
                        ui.add_space(6.0);
                        let count_label = format!("{} accounts", self.accounts.len());
                        ui.label(RichText::new(count_label).size(11.0).color(text_muted));
                        ui.label(RichText::new("•").size(10.0).color(Color32::from_rgb(50, 60, 80)));

                        let timer_text = format!("{remaining:02}s");
                        ui.label(
                            RichText::new(timer_text)
                                .size(11.0)
                                .color(progress_color)
                                .monospace()
                                .strong(),
                        );

                        if let Some((msg, time)) = &self.toast_message {
                            if time.elapsed() < Duration::from_secs(3) {
                                ui.label(RichText::new("•").size(10.0).color(Color32::from_rgb(50, 60, 80)));
                                ui.label(RichText::new(msg).color(accent_emerald).size(11.0).strong());
                            } else {
                                self.toast_message = None;
                            }
                        }

                        // Right-aligned Keycaps with plenty of breathing room
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.add_space(6.0);
                            draw_keycap_rtl(ui, "Esc", "Close");
                            ui.add_space(8.0);
                            ui.label(RichText::new("•").size(10.0).color(Color32::from_rgb(50, 60, 80)));
                            ui.add_space(8.0);
                            draw_keycap_rtl(ui, "Tab", "Source");
                            ui.add_space(8.0);
                            ui.label(RichText::new("•").size(10.0).color(Color32::from_rgb(50, 60, 80)));
                            ui.add_space(8.0);
                            draw_keycap_rtl(ui, "Enter", "Copy");
                        });
                    });
                }

                ViewMode::Settings => {
                    // Settings Page Header
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        ui.add_space(12.0);

                        let back_btn = egui::Button::new(
                            RichText::new("<- Back")
                                .size(11.5)
                                .color(Color32::from_rgb(175, 190, 210))
                                .strong(),
                        )
                        .fill(Color32::from_rgb(24, 30, 42))
                        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(45, 55, 75)))
                        .corner_radius(CornerRadius::same(5));

                        if ui.add(back_btn).clicked() {
                            self.view_mode = ViewMode::Launcher;
                        }

                        ui.add_space(8.0);
                        ui.label(
                            RichText::new("Settings: Sources & Vault Passwords")
                                .size(14.5)
                                .color(text_primary)
                                .strong(),
                        );

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.add_space(12.0);
                            ui.label(
                                RichText::new(format!("{} sources configured", self.sources.len()))
                                    .size(11.0)
                                    .color(text_muted),
                            );
                        });
                    });

                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(4.0);

                    // Settings Body (Scrollable)
                    egui::ScrollArea::vertical()
                        .max_height(355.0)
                        .show(ui, |ui| {
                            // SECTION 1: Configured Sources & Passwords
                            ui.horizontal(|ui| {
                                ui.add_space(12.0);
                                ui.label(
                                    RichText::new("CONFIGURED SOURCES")
                                        .size(10.0)
                                        .color(Color32::from_rgb(110, 125, 145))
                                        .strong(),
                                );
                            });
                            ui.add_space(4.0);

                            let mut remove_idx = None;
                            let mut select_idx = None;
                            let mut test_save_pwd = None;

                            for (idx, s) in self.sources.iter().enumerate() {
                                let is_active = idx == self.active_source_idx;
                                let card_frame = Frame::NONE
                                    .fill(Color32::from_rgb(20, 24, 34))
                                    .stroke(Stroke::new(
                                        1.0_f32,
                                        if is_active { Color32::from_rgb(16, 185, 129) } else { Color32::from_rgb(36, 44, 60) },
                                    ))
                                    .corner_radius(CornerRadius::same(6))
                                    .inner_margin(Margin::symmetric(12, 10));

                                ui.horizontal(|ui| {
                                    ui.add_space(12.0);
                                    let full_w = ui.available_width() - 12.0;

                                    ui.allocate_ui_with_layout(
                                        Vec2::new(full_w, 0.0),
                                        egui::Layout::top_down(egui::Align::Min),
                                        |ui| {
                                            card_frame.show(ui, |ui| {
                                                ui.horizontal(|ui| {
                                                    // Source Title & Status
                                                    ui.vertical(|ui| {
                                                        ui.horizontal(|ui| {
                                                            ui.label(RichText::new(&s.name).size(13.0).strong().color(text_primary));
                                                            if is_active {
                                                                ui.label(RichText::new("(Active)").size(11.0).color(accent_emerald).strong());
                                                            }
                                                            let type_label = match s.kind {
                                                                SourceKind::Kdbx => {
                                                                    if s.is_dir {
                                                                        "KeePassXC Folder (.kdbx)"
                                                                    } else {
                                                                        "KeePassXC KDBX"
                                                                    }
                                                                }
                                                                SourceKind::TwoFas => {
                                                                    if s.is_dir {
                                                                        if s.is_encrypted { "2FAS Sync Folder (Encrypted)" } else { "2FAS Sync Folder (Plain)" }
                                                                    } else if s.is_encrypted {
                                                                        "2FAS AES-256-GCM"
                                                                    } else {
                                                                        "2FAS Plain JSON"
                                                                    }
                                                                }
                                                                SourceKind::Aegis => {
                                                                    if s.is_dir {
                                                                        if s.is_encrypted { "Aegis Sync Folder (Encrypted)" } else { "Aegis Sync Folder (Plain)" }
                                                                    } else if s.is_encrypted {
                                                                        "Aegis AES-256-GCM"
                                                                    } else {
                                                                        "Aegis Plain JSON"
                                                                    }
                                                                }
                                                                SourceKind::Uri => "URI Collection",
                                                            };
                                                            ui.label(RichText::new(type_label).size(10.0).color(text_muted));
                                                        });

                                                        let path_display = if s.is_dir {
                                                            if let Some(rname) = s.latest_file_name() {
                                                                format!("{}  (Latest: {})", s.path.display(), rname)
                                                            } else {
                                                                format!("{}  (Directory)", s.path.display())
                                                            }
                                                        } else {
                                                            format!("{}", s.path.display())
                                                        };

                                                        ui.label(
                                                            RichText::new(path_display)
                                                                .size(10.5)
                                                                .color(Color32::from_rgb(120, 136, 158)),
                                                        );
                                                    });

                                                    // Actions
                                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                        if self.sources.len() > 1
                                                            && ui.button(RichText::new("Delete").size(10.5).color(Color32::from_rgb(244, 63, 94))).clicked() {
                                                            remove_idx = Some(idx);
                                                        }

                                                        if !is_active
                                                            && ui.button(RichText::new("Use").size(10.5)).clicked() {
                                                            select_idx = Some(idx);
                                                        }
                                                    });
                                                });

                                                // Password management for encrypted sources
                                                if s.is_encrypted {
                                                    ui.add_space(6.0);
                                                    ui.separator();
                                                    ui.add_space(4.0);

                                                    if self.editing_pwd_idx == Some(idx) {
                                                        ui.horizontal(|ui| {
                                                            ui.label(RichText::new("Set Password:").size(11.0).color(text_primary));
                                                            ui.add(
                                                                egui::TextEdit::singleline(&mut self.editing_pwd_input)
                                                                    .password(true)
                                                                    .hint_text("Enter vault password..."),
                                                            );

                                                            if ui.button("Save & Test").clicked() {
                                                                test_save_pwd = Some((idx, self.editing_pwd_input.clone()));
                                                            }

                                                            if ui.button("Cancel").clicked() {
                                                                self.editing_pwd_idx = None;
                                                                self.editing_pwd_error = None;
                                                            }
                                                        });

                                                        if let Some(err) = &self.editing_pwd_error {
                                                            ui.label(RichText::new(err).size(10.5).color(Color32::from_rgb(244, 63, 94)));
                                                        }
                                                    } else {
                                                        ui.horizontal(|ui| {
                                                            if s.cached_password.is_some() {
                                                                ui.label(RichText::new("Vault Password: Saved & Cached").size(11.0).color(accent_emerald));
                                                                if ui.button(RichText::new("Change").size(10.0)).clicked() {
                                                                    self.editing_pwd_idx = Some(idx);
                                                                    self.editing_pwd_input = s.cached_password.clone().unwrap_or_default();
                                                                    self.editing_pwd_error = None;
                                                                }
                                                                if ui.button(RichText::new("Clear").size(10.0)).clicked() {
                                                                    test_save_pwd = Some((idx, String::new()));
                                                                }
                                                            } else {
                                                                ui.label(RichText::new("Vault Password: Not set (Prompts on load)").size(11.0).color(Color32::from_rgb(245, 158, 11)));
                                                                if ui.button(RichText::new("Set Password").size(10.5).color(accent_emerald)).clicked() {
                                                                    self.editing_pwd_idx = Some(idx);
                                                                    self.editing_pwd_input.clear();
                                                                    self.editing_pwd_error = None;
                                                                }
                                                            }
                                                        });
                                                    }
                                                }
                                            });
                                        },
                                    );
                                });
                                ui.add_space(6.0);
                            }

                            if let Some(idx) = remove_idx {
                                self.sources.remove(idx);
                                if self.active_source_idx >= self.sources.len() {
                                    self.active_source_idx = 0;
                                }
                                self.persist_sources();
                                if !self.sources.is_empty() {
                                    let pwd = self.sources[self.active_source_idx].cached_password.clone();
                                    self.load_active_source(pwd.as_deref(), true);
                                }
                            }

                            if let Some(idx) = select_idx {
                                self.active_source_idx = idx;
                                self.persist_sources();
                                let pwd = self.sources[self.active_source_idx].cached_password.clone();
                                self.load_active_source(pwd.as_deref(), true);
                            }

                            if let Some((idx, pwd_to_test)) = test_save_pwd {
                                if pwd_to_test.is_empty() {
                                    if let Some(s) = self.sources.get_mut(idx) {
                                        s.cached_password = None;
                                    }
                                    self.editing_pwd_idx = None;
                                    self.persist_sources();
                                    self.set_toast("Password cleared");
                                } else {
                                    let path = self.sources[idx].path.clone();
                                    let load_res = match self.sources[idx].kind {
                                        SourceKind::Kdbx => KdbxSource::from_file(&path).with_password(&pwd_to_test).load(),
                                        SourceKind::TwoFas => TwoFasSource::from_file(&path).with_password(&pwd_to_test).load(),
                                        SourceKind::Aegis => AegisSource::from_file(&path).with_password(&pwd_to_test).load(),
                                        SourceKind::Uri => UriSource::from_file(&path).load(),
                                    };
                                    match load_res {
                                        Ok(accs) => {
                                            if let Some(s) = self.sources.get_mut(idx) {
                                                s.cached_password = Some(pwd_to_test.clone());
                                            }
                                            self.editing_pwd_idx = None;
                                            self.editing_pwd_error = None;
                                            self.persist_sources();
                                            if idx == self.active_source_idx {
                                                self.accounts = accs;
                                            }
                                            self.set_toast("Password verified and saved!");
                                        }
                                        Err(e) => {
                                            self.editing_pwd_error = Some(format!("Invalid password: {e}"));
                                        }
                                    }
                                }
                            }

                            ui.add_space(10.0);

                            // SECTION 2: Add New Source
                            ui.horizontal(|ui| {
                                ui.add_space(12.0);
                                ui.label(
                                    RichText::new("ADD NEW SOURCE")
                                        .size(10.0)
                                        .color(Color32::from_rgb(110, 125, 145))
                                        .strong(),
                                );
                            });
                            ui.add_space(4.0);

                            let add_frame = Frame::NONE
                                .fill(Color32::from_rgb(20, 24, 34))
                                .stroke(Stroke::new(1.0_f32, Color32::from_rgb(36, 44, 60)))
                                .corner_radius(CornerRadius::same(6))
                                .inner_margin(Margin::symmetric(12, 10));

                            let mut add_new_action = false;

                            ui.horizontal(|ui| {
                                ui.add_space(12.0);
                                let full_w = ui.available_width() - 12.0;

                                ui.allocate_ui_with_layout(
                                    Vec2::new(full_w, 0.0),
                                    egui::Layout::top_down(egui::Align::Min),
                                    |ui| {
                                        add_frame.show(ui, |ui| {
                                            ui.horizontal(|ui| {
                                                ui.label(RichText::new("Source Name:").size(11.5).color(text_primary));
                                                ui.add(
                                                    egui::TextEdit::singleline(&mut self.new_src_name)
                                                        .hint_text("e.g. Work Aegis or Personal 2FA"),
                                                );
                                            });
                                            ui.add_space(4.0);

                                            ui.horizontal(|ui| {
                                                ui.label(RichText::new("File Path:").size(11.5).color(text_primary));
                                                ui.add_sized(
                                                    Vec2::new(ui.available_width() - 10.0, 24.0),
                                                    egui::TextEdit::singleline(&mut self.new_src_path)
                                                        .hint_text("/path/to/vault.2fas, .json, or .uri"),
                                                );
                                            });

                                            let p = PathBuf::from(self.new_src_path.trim());
                                            let is_dir = p.is_dir();
                                            let mut latest_backup_detected = None;
                                            let detected_kind = if p.exists() { Some(detect_source_kind(&p)) } else { None };

                                            let is_encrypted = if is_dir {
                                                match detected_kind {
                                                    Some(SourceKind::Kdbx) => {
                                                        if let Ok(latest) = rune_adapter_kdbx::find_latest_kdbx_file(&p) {
                                                            latest_backup_detected = Some((latest, true, "KeePassXC"));
                                                            true
                                                        } else {
                                                            false
                                                        }
                                                    }
                                                    Some(SourceKind::TwoFas) => {
                                                        if let Ok(latest) = rune_adapter_twofas::find_latest_2fas_backup(&p) {
                                                            let is_enc = TwoFasSource::from_file(&latest).is_encrypted().unwrap_or(false);
                                                            latest_backup_detected = Some((latest, is_enc, "2FAS"));
                                                            is_enc
                                                        } else {
                                                            false
                                                        }
                                                    }
                                                    _ => {
                                                        if let Ok(latest) = rune_adapter_aegis::find_latest_aegis_backup(&p) {
                                                            let is_enc = AegisSource::from_file(&latest).is_encrypted().unwrap_or(false);
                                                            latest_backup_detected = Some((latest, is_enc, "Aegis"));
                                                            is_enc
                                                        } else {
                                                            false
                                                        }
                                                    }
                                                }
                                            } else if p.is_file() {
                                                match detected_kind {
                                                    Some(SourceKind::Kdbx) => true,
                                                    Some(SourceKind::TwoFas) => TwoFasSource::from_file(&p).is_encrypted().unwrap_or(false),
                                                    Some(SourceKind::Aegis) => AegisSource::from_file(&p).is_encrypted().unwrap_or(false),
                                                    _ => false,
                                                }
                                            } else {
                                                false
                                            };

                                            if let Some((latest, is_enc, flavor)) = &latest_backup_detected {
                                                ui.add_space(2.0);
                                                let enc_text = if *is_enc { " (Encrypted AES-GCM)" } else { " (Plain)" };
                                                let label = format!(
                                                    "-> Detected {flavor} Backup Folder! Latest: {}{}",
                                                    latest.file_name().unwrap_or_default().to_string_lossy(),
                                                    enc_text
                                                );
                                                ui.label(RichText::new(label).size(11.0).color(accent_emerald));
                                            }

                                            if is_encrypted {
                                                ui.add_space(4.0);
                                                ui.horizontal(|ui| {
                                                    ui.label(RichText::new("Vault Password:").size(11.5).color(Color32::from_rgb(245, 158, 11)));
                                                    ui.add(
                                                        egui::TextEdit::singleline(&mut self.new_src_password)
                                                            .password(true)
                                                            .hint_text("Enter vault password..."),
                                                    );
                                                });
                                            }

                                            if let Some((is_err, msg)) = &self.new_src_status {
                                                ui.add_space(4.0);
                                                let col = if *is_err { Color32::from_rgb(244, 63, 94) } else { accent_emerald };
                                                ui.label(RichText::new(msg).size(11.0).color(col));
                                            }

                                            ui.add_space(8.0);
                                            ui.horizontal(|ui| {
                                                if ui.button(RichText::new("Add Source").size(11.5).strong().color(accent_emerald)).clicked() {
                                                    add_new_action = true;
                                                }

                                                ui.add_space(10.0);
                                                ui.label(RichText::new("Quick presets:").size(10.5).color(text_muted));

                                                if ui.button(RichText::new("+ KeePassXC (.kdbx)").size(10.0)).clicked() {
                                                    self.new_src_name = "KeePassXC".to_string();
                                                    self.new_src_path = "examples/keepass_vault.kdbx".to_string();
                                                    self.new_src_password = "password123".to_string();
                                                }

                                                if ui.button(RichText::new("+ 2FAS (Plain)").size(10.0)).clicked() {
                                                    self.new_src_name = "2FAS (Plain)".to_string();
                                                    self.new_src_path = "examples/2fas_plain.2fas".to_string();
                                                    self.new_src_password.clear();
                                                }

                                                if ui.button(RichText::new("+ 2FAS (Encrypted)").size(10.0)).clicked() {
                                                    self.new_src_name = "2FAS (Encrypted)".to_string();
                                                    self.new_src_path = "examples/2fas_encrypted.2fas".to_string();
                                                    self.new_src_password = "example.com".to_string();
                                                }

                                                if ui.button(RichText::new("+ Aegis Sync").size(10.0)).clicked() {
                                                    self.new_src_name = "Aegis Sync Backups".to_string();
                                                    self.new_src_path = "examples/aegis_sync".to_string();
                                                    self.new_src_password = "test".to_string();
                                                }

                                                if ui.button(RichText::new("+ Encrypted Aegis").size(10.0)).clicked() {
                                                    self.new_src_name = "Aegis (Encrypted)".to_string();
                                                    self.new_src_path = "examples/aegis_encrypted.json".to_string();
                                                    self.new_src_password = "test".to_string();
                                                }

                                                if ui.button(RichText::new("+ Sample URI").size(10.0)).clicked() {
                                                    self.new_src_name = "Sample URIs".to_string();
                                                    self.new_src_path = "examples/sample.uri".to_string();
                                                    self.new_src_password.clear();
                                                }
                                            });
                                        });
                                    },
                                );
                            });

                            if add_new_action {
                                let path = PathBuf::from(self.new_src_path.trim());
                                if !path.exists() {
                                    self.new_src_status = Some((true, "Path does not exist".to_string()));
                                } else {
                                    let is_dir = path.is_dir();
                                    let kind = detect_source_kind(&path);
                                    let name = if self.new_src_name.trim().is_empty() {
                                        path.file_name().and_then(|n| n.to_str()).unwrap_or("Source").to_string()
                                    } else {
                                        self.new_src_name.trim().to_string()
                                    };

                                    match kind {
                                        SourceKind::Kdbx => {
                                            let mut kdbx = KdbxSource::from_file(&path);
                                            let pwd = self.new_src_password.clone();
                                            if !pwd.is_empty() {
                                                kdbx = kdbx.with_password(&pwd);
                                            }
                                            match kdbx.load() {
                                                Ok(accs) => {
                                                    self.sources.push(SourceOption {
                                                        name: name.clone(),
                                                        path: path.clone(),
                                                        is_dir,
                                                        kind,
                                                        is_encrypted: true,
                                                        cached_password: if pwd.is_empty() { None } else { Some(pwd) },
                                                    });
                                                    self.active_source_idx = self.sources.len() - 1;
                                                    self.accounts = accs;
                                                    self.persist_sources();
                                                    self.new_src_status = Some((false, format!("Added {name} (verified)!")));
                                                    self.new_src_name.clear();
                                                    self.new_src_path.clear();
                                                    self.new_src_password.clear();
                                                }
                                                Err(e) => {
                                                    self.new_src_status = Some((true, format!("KDBX decryption failed: {e}")));
                                                }
                                            }
                                        }
                                        SourceKind::TwoFas => {
                                            let mut twofas = TwoFasSource::from_file(&path);
                                            let is_enc = twofas.is_encrypted().unwrap_or(false);
                                            if is_enc {
                                                let pwd = self.new_src_password.clone();
                                                twofas = twofas.with_password(&pwd);
                                                match twofas.load() {
                                                    Ok(accs) => {
                                                        self.sources.push(SourceOption {
                                                            name: name.clone(),
                                                            path: path.clone(),
                                                            is_dir,
                                                            kind,
                                                            is_encrypted: true,
                                                            cached_password: if pwd.is_empty() { None } else { Some(pwd) },
                                                        });
                                                        self.active_source_idx = self.sources.len() - 1;
                                                        self.accounts = accs;
                                                        self.persist_sources();
                                                        self.new_src_status = Some((false, format!("Added {name} (verified)!")));
                                                        self.new_src_name.clear();
                                                        self.new_src_path.clear();
                                                        self.new_src_password.clear();
                                                    }
                                                    Err(e) => {
                                                        self.new_src_status = Some((true, format!("Decryption failed: {e}")));
                                                    }
                                                }
                                            } else {
                                                match twofas.load() {
                                                    Ok(accs) => {
                                                        self.sources.push(SourceOption {
                                                            name: name.clone(),
                                                            path: path.clone(),
                                                            is_dir,
                                                            kind,
                                                            is_encrypted: false,
                                                            cached_password: None,
                                                        });
                                                        self.active_source_idx = self.sources.len() - 1;
                                                        self.accounts = accs;
                                                        self.persist_sources();
                                                        self.new_src_status = Some((false, format!("Added {name}!")));
                                                        self.new_src_name.clear();
                                                        self.new_src_path.clear();
                                                    }
                                                    Err(e) => {
                                                        self.new_src_status = Some((true, format!("Failed to parse: {e}")));
                                                    }
                                                }
                                            }
                                        }
                                        SourceKind::Aegis => {
                                            let mut aegis = AegisSource::from_file(&path);
                                            let is_enc = aegis.is_encrypted().unwrap_or(false);
                                            if is_enc {
                                                let pwd = self.new_src_password.clone();
                                                aegis = aegis.with_password(&pwd);
                                                match aegis.load() {
                                                    Ok(accs) => {
                                                        self.sources.push(SourceOption {
                                                            name: name.clone(),
                                                            path: path.clone(),
                                                            is_dir,
                                                            kind,
                                                            is_encrypted: true,
                                                            cached_password: if pwd.is_empty() { None } else { Some(pwd) },
                                                        });
                                                        self.active_source_idx = self.sources.len() - 1;
                                                        self.accounts = accs;
                                                        self.persist_sources();
                                                        self.new_src_status = Some((false, format!("Added {name} (verified)!")));
                                                        self.new_src_name.clear();
                                                        self.new_src_path.clear();
                                                        self.new_src_password.clear();
                                                    }
                                                    Err(e) => {
                                                        self.new_src_status = Some((true, format!("Decryption failed: {e}")));
                                                    }
                                                }
                                            } else {
                                                match aegis.load() {
                                                    Ok(accs) => {
                                                        self.sources.push(SourceOption {
                                                            name: name.clone(),
                                                            path: path.clone(),
                                                            is_dir,
                                                            kind,
                                                            is_encrypted: false,
                                                            cached_password: None,
                                                        });
                                                        self.active_source_idx = self.sources.len() - 1;
                                                        self.accounts = accs;
                                                        self.persist_sources();
                                                        self.new_src_status = Some((false, format!("Added {name}!")));
                                                        self.new_src_name.clear();
                                                        self.new_src_path.clear();
                                                    }
                                                    Err(e) => {
                                                        self.new_src_status = Some((true, format!("Failed to parse: {e}")));
                                                    }
                                                }
                                            }
                                        }
                                        SourceKind::Uri => {
                                            let uri_src = UriSource::from_file(&path);
                                            match uri_src.load() {
                                                Ok(accs) => {
                                                    self.sources.push(SourceOption {
                                                        name: name.clone(),
                                                        path: path.clone(),
                                                        is_dir: false,
                                                        kind,
                                                        is_encrypted: false,
                                                        cached_password: None,
                                                    });
                                                    self.active_source_idx = self.sources.len() - 1;
                                                    self.accounts = accs;
                                                    self.persist_sources();
                                                    self.new_src_status = Some((false, format!("Added {name}!")));
                                                    self.new_src_name.clear();
                                                    self.new_src_path.clear();
                                                }
                                                Err(e) => {
                                                    self.new_src_status = Some((true, format!("Failed to load URI file: {e}")));
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            ui.add_space(20.0);
                        });

                    // Settings Footer Bar
                    ui.separator();
                    ui.add_space(3.0);
                    ui.horizontal(|ui| {
                        ui.add_space(4.0);
                        ui.label(RichText::new("Sources and cached passwords are saved to ~/.config/rune/sources.json").size(10.5).color(text_muted));

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.add_space(4.0);
                            draw_keycap_rtl(ui, "Esc", "Back");
                        });
                    });
                }
            }
        });

        // Floating Source Selector Menu (when in Launcher mode)
        if self.view_mode == ViewMode::Launcher && self.show_source_picker {
            if let Some(btn_rect) = button_rect_opt {
                let popup_pos = Pos2::new(btn_rect.min.x - 70.0, btn_rect.max.y + 6.0);
                egui::Area::new(egui::Id::new("source_floating_menu"))
                    .order(egui::Order::Foreground)
                    .fixed_pos(popup_pos)
                    .show(ctx, |ui| {
                        let popup_frame = Frame::NONE
                            .fill(Color32::from_rgb(20, 25, 34))
                            .stroke(Stroke::new(1.0_f32, Color32::from_rgb(48, 58, 76)))
                            .corner_radius(CornerRadius::same(8))
                            .inner_margin(Margin::symmetric(8, 6));

                        popup_frame.show(ui, |ui| {
                            ui.set_width(210.0);
                            ui.label(
                                RichText::new("SELECT SOURCE (OR PRESS TAB)")
                                    .size(9.0)
                                    .color(Color32::from_rgb(110, 125, 145))
                                    .strong(),
                            );
                            ui.add_space(4.0);

                            for (idx, s) in self.sources.iter().enumerate() {
                                let is_active = idx == self.active_source_idx;
                                let row_bg = if is_active {
                                    Color32::from_rgb(28, 36, 48)
                                } else {
                                    Color32::TRANSPARENT
                                };

                                let item_frame = Frame::NONE
                                    .fill(row_bg)
                                    .corner_radius(CornerRadius::same(5))
                                    .inner_margin(Margin::symmetric(8, 6));

                                let resp = item_frame.show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        let dot_color = if is_active {
                                            accent_emerald
                                        } else {
                                            Color32::from_rgb(55, 65, 82)
                                        };
                                        let (dot_rect, _) =
                                            ui.allocate_exact_size(Vec2::splat(6.0), Sense::hover());
                                        ui.painter().circle_filled(dot_rect.center(), 3.0, dot_color);
                                        ui.add_space(4.0);

                                        ui.vertical(|ui| {
                                            ui.label(
                                                RichText::new(&s.name)
                                                    .size(12.0)
                                                    .color(if is_active { text_primary } else { text_muted })
                                                    .strong(),
                                            );
                                            let sub = if s.is_dir {
                                                let rname = s.latest_file_name().unwrap_or_else(|| "none".to_string());
                                                format!("Sync Folder • Latest: {rname}")
                                            } else if s.is_encrypted {
                                                if s.cached_password.is_some() {
                                                    "Encrypted (Password saved)".to_string()
                                                } else {
                                                    "Encrypted (Locked)".to_string()
                                                }
                                            } else {
                                                "Plain text".to_string()
                                            };
                                            ui.label(RichText::new(sub).size(9.5).color(Color32::from_rgb(90, 105, 125)));
                                        });
                                    });
                                });

                                if resp.response.interact(Sense::click()).clicked() {
                                    switch_to_idx = Some(idx);
                                }
                            }

                            ui.add_space(6.0);
                            ui.separator();
                            ui.add_space(4.0);

                            // Manage Sources & Passwords button in menu
                            if ui
                                .button(RichText::new("Manage Sources & Passwords...").size(11.0).color(accent_emerald))
                                .clicked()
                            {
                                self.view_mode = ViewMode::Settings;
                                self.show_source_picker = false;
                            }
                        });
                    });
            }
        }

        if let Some(idx) = switch_to_idx {
            self.active_source_idx = idx;
            self.show_source_picker = false;
            let pwd = self.sources[self.active_source_idx].cached_password.clone();
            self.load_active_source(pwd.as_deref(), true);
            self.persist_sources();
        }

        if let Some(acc) = to_copy {
            self.trigger_copy(&acc);
        }
    }
}

fn load_app_icon() -> Option<egui::IconData> {
    let icon_bytes = include_bytes!("../../assets/rune.png");
    let img = image::load_from_memory(icon_bytes).ok()?.to_rgba8();
    let (width, height) = img.dimensions();
    Some(egui::IconData {
        rgba: img.into_raw(),
        width,
        height,
    })
}

fn main() -> eframe::Result<()> {
    let mut viewport = egui::ViewportBuilder::default()
        .with_title("Rune")
        .with_inner_size([700.0, 460.0])
        .with_resizable(false)
        .with_decorations(false)
        .with_transparent(true)
        .with_always_on_top();

    if let Some(icon) = load_app_icon() {
        viewport = viewport.with_icon(icon);
    }

    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    eframe::run_native(
        "Rune",
        options,
        Box::new(|cc| Ok(Box::new(RuneApp::new(cc)))),
    )
}
