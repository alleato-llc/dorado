//! A small, polished iced GUI to demo dorado. It is the password tool in a
//! window: pick encrypt/decrypt, a source (typed text or a file), enter a
//! password, optionally tune the cipher/KDF options, and go. The cryptographic
//! work (the same authenticated container the CLI writes) lives in `engine` and
//! runs on a background thread so the window stays responsive.
//!
//! The look is built on `rime`, the house iced component kit (a sibling repo),
//! plus `dorado-gui-kit`'s composites over it; see `rust/CLAUDE.md`.
//!
//! Educational and unaudited. The cryptographic work lives in the
//! `dorado-engine` crate.

#![forbid(unsafe_code)]

use std::time::Duration;

use iced::alignment::Horizontal;
use iced::futures::channel::oneshot;
use iced::widget::{column, container, scrollable, text, Column};
use iced::{Element, Length, Subscription, Task, Theme};

use dorado_engine as engine;
use dorado_engine::{KdfParams, MacId, PrfId, Variant};

use dorado_gui_kit::{
    file_path_field, output_panel, password_field, picker, progress_status_row, segmented,
    theme_picker,
};
use rime::theme;
use rime::widgets::{button, card, labeled, slider, text_field, SecretHandle};
use zeroize::Zeroizing;

mod shot;

/// The default theme, by name (see [`rime::theme::builtin_themes`]).
const DEFAULT_THEME: &str = "Dracula";

/// The embedded app icon (a dorado, in rime's gold/teal tones). Shown as the
/// window/taskbar icon on Linux and Windows; macOS takes its Dock icon from
/// the `.app` bundle instead (see `packaging/AppIcon.icns`).
const APP_ICON_BYTES: &[u8] = include_bytes!("assets/icon.png");

/// Decode the embedded PNG into an iced window icon. Returns `None` (no icon,
/// never a crash) if the bytes ever fail to decode — the app still runs.
fn app_icon() -> Option<iced::window::Icon> {
    let mut reader = png::Decoder::new(APP_ICON_BYTES).read_info().ok()?;
    let mut buf = vec![0; reader.output_buffer_size()];
    let info = reader.next_frame(&mut buf).ok()?;
    buf.truncate(info.buffer_size());
    // The bundled asset is 8-bit RGBA; bail on any other shape rather than
    // hand a mis-sized buffer to `from_rgba` (which would just Err anyway).
    if info.bit_depth != png::BitDepth::Eight || info.color_type != png::ColorType::Rgba {
        return None;
    }
    iced::window::icon::from_rgba(buf, info.width, info.height).ok()
}

fn main() -> iced::Result {
    // A review screenshot (src/shot.rs) needs the whole scrollable content
    // visible with nothing scrolled out of frame, so it gets a taller window;
    // the normal app keeps its compact default.
    let height = if std::env::var_os("DORADO_SHOT").is_some() {
        780.0
    } else {
        640.0
    };
    iced::application(App::launch, App::update, App::view)
        .title(App::title)
        .theme(App::theme)
        .subscription(App::subscription)
        .window(iced::window::Settings {
            size: iced::Size::new(480.0, height),
            icon: app_icon(),
            ..Default::default()
        })
        .run()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Encrypt,
    Decrypt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    Text,
    File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KdfChoice {
    Argon2id,
    Scrypt,
    Pbkdf2,
}

const KDFS: [KdfChoice; 3] = [KdfChoice::Argon2id, KdfChoice::Scrypt, KdfChoice::Pbkdf2];

impl std::fmt::Display for KdfChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            KdfChoice::Argon2id => "Argon2id",
            KdfChoice::Scrypt => "scrypt",
            KdfChoice::Pbkdf2 => "PBKDF2",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VariantChoice {
    B256,
    B512,
    B1024,
}

const VARIANTS: [VariantChoice; 3] = [
    VariantChoice::B256,
    VariantChoice::B512,
    VariantChoice::B1024,
];

impl VariantChoice {
    fn to_variant(self) -> Variant {
        match self {
            VariantChoice::B256 => Variant::T256,
            VariantChoice::B512 => Variant::T512,
            VariantChoice::B1024 => Variant::T1024,
        }
    }
}

impl std::fmt::Display for VariantChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            VariantChoice::B256 => "256-bit",
            VariantChoice::B512 => "512-bit",
            VariantChoice::B1024 => "1024-bit",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MacChoice {
    Skein,
    HmacSha256,
    Blake3,
}

const MACS: [MacChoice; 3] = [MacChoice::Skein, MacChoice::HmacSha256, MacChoice::Blake3];

impl MacChoice {
    fn to_mac(self) -> MacId {
        match self {
            MacChoice::Skein => MacId::Skein512,
            MacChoice::HmacSha256 => MacId::HmacSha256,
            MacChoice::Blake3 => MacId::Blake3,
        }
    }
}

impl std::fmt::Display for MacChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            MacChoice::Skein => "Skein-512",
            MacChoice::HmacSha256 => "HMAC-SHA256",
            MacChoice::Blake3 => "BLAKE3",
        })
    }
}

#[derive(Debug, Clone)]
enum Message {
    DirectionSelected(Direction),
    SourceSelected(Source),
    /// The password field mutated its buffer. Carries nothing: the password
    /// stays in the app's `SecretHandle` and never enters the message queue.
    PasswordEdited,
    TextChanged(String),
    InPathChanged(String),
    OutPathChanged(String),
    BrowseInPath,
    BrowseOutPath,
    ToggleOptions,
    VariantSelected(VariantChoice),
    KdfSelected(KdfChoice),
    MacSelected(MacChoice),
    Argon2MemChanged(u32),
    Argon2TimeChanged(u32),
    ScryptLognChanged(u8),
    Pbkdf2RoundsChanged(u32),
    ChunkChanged(u32),
    TweakChanged(String),
    ThemeSelected(String),
    Run,
    Tick,
    Copy,
    Completed(Result<String, String>),
    /// A screenshot-harness lifecycle event; see [`shot`]. No-op unless
    /// `DORADO_SHOT` is set.
    Shot(shot::Event),
}

struct App {
    direction: Direction,
    source: Source,
    /// The password's single home: rime's `secure_input` buffer, fixed
    /// capacity (never reallocated), mlock'd into RAM best-effort, and
    /// zeroized on drop. The widget edits it in place and emits only unit
    /// messages, so the password never enters iced's message queue, widget
    /// tree, or text shaper; a job copies the bytes out under the lock into
    /// its own `Zeroizing` buffer for the engine call.
    password: SecretHandle,
    text: String,
    in_path: String,
    out_path: String,
    // Options.
    show_options: bool,
    variant: VariantChoice,
    kdf: KdfChoice,
    mac: MacChoice,
    argon2_mem_mib: u32,
    argon2_time: u32,
    scrypt_logn: u8,
    pbkdf2_rounds: u32,
    chunk_kib: u32,
    tweak_hex: String,
    // Appearance.
    theme_name: String,
    // Result.
    output: String,
    status: String,
    busy: bool,
    progress: f32,
    /// The review-screenshot harness, present only when `DORADO_SHOT` is set —
    /// otherwise `None` and the whole thing is inert. See [`shot`].
    shot: Option<shot::Shot>,
}

impl Default for App {
    fn default() -> Self {
        App {
            direction: Direction::Encrypt,
            source: Source::Text,
            password: SecretHandle::new(),
            text: String::new(),
            in_path: String::new(),
            out_path: String::new(),
            show_options: false,
            variant: VariantChoice::B256,
            kdf: KdfChoice::Argon2id,
            mac: MacChoice::Skein,
            argon2_mem_mib: 64,
            argon2_time: 3,
            scrypt_logn: 15,
            pbkdf2_rounds: 600_000,
            chunk_kib: 64,
            tweak_hex: String::new(),
            theme_name: DEFAULT_THEME.to_string(),
            output: String::new(),
            status: String::new(),
            busy: false,
            progress: 0.0,
            shot: None,
        }
    }
}

impl App {
    /// Build the encryption options from the current UI state. Decryption reads
    /// its parameters from the file header, so these only apply to encryption.
    fn options(&self) -> Result<engine::PasswordOptions, String> {
        let kdf = match self.kdf {
            KdfChoice::Argon2id => KdfParams::Argon2id {
                m_cost: self.argon2_mem_mib.saturating_mul(1024),
                t_cost: self.argon2_time,
                p_cost: 1,
            },
            KdfChoice::Scrypt => KdfParams::Scrypt {
                log_n: self.scrypt_logn,
                r: 8,
                p: 1,
            },
            KdfChoice::Pbkdf2 => KdfParams::Pbkdf2 {
                rounds: self.pbkdf2_rounds,
                prf: PrfId::HmacSha256,
            },
        };
        let tweak = if self.tweak_hex.trim().is_empty() {
            [0u8; 16]
        } else {
            engine::parse_tweak(&self.tweak_hex)?
        };
        Ok(engine::PasswordOptions {
            variant: self.variant.to_variant(),
            kdf,
            mac: self.mac.to_mac(),
            tweak,
            chunk_size: self.chunk_kib.saturating_mul(1024),
            // The GUI does not expose labels yet; encrypt without one.
            label: Vec::new(),
        })
    }

    /// The active palette: the named theme, falling back to the default for an
    /// unknown (e.g. stale) name.
    fn palette(&self) -> theme::Palette {
        theme::builtin_themes()
            .iter()
            .find(|(name, _, _)| *name == self.theme_name)
            .map(|(_, palette, _)| *palette)
            .unwrap_or(theme::DRACULA)
    }
}

/// A self-contained unit of work, so the crypto can run on a worker thread
/// without borrowing from the UI state.
struct Job {
    direction: Direction,
    source: Source,
    opts: engine::PasswordOptions,
    /// The worker's own copy of the password bytes (read out of the app's
    /// `SecretHandle` under its lock), zeroized when the job is dropped at the
    /// end of `run`.
    password: Zeroizing<Vec<u8>>,
    text: String,
    in_path: String,
    out_path: String,
}

impl Job {
    fn run(self) -> Result<String, String> {
        let pw: &[u8] = &self.password;
        if pw.is_empty() {
            return Err("password must not be empty".into());
        }
        match (self.source, self.direction) {
            (Source::Text, Direction::Encrypt) => {
                let ct = engine::encrypt_password_bytes(pw, &self.opts, self.text.as_bytes())?;
                Ok(hex(&ct))
            }
            (Source::Text, Direction::Decrypt) => {
                let data =
                    engine::parse_hex(&self.text).map_err(|e| format!("ciphertext hex: {e}"))?;
                let pt = engine::decrypt_password_bytes(pw, &data)?;
                Ok(String::from_utf8_lossy(&pt).into_owned())
            }
            (Source::File, dir) => {
                if self.in_path.is_empty() || self.out_path.is_empty() {
                    return Err("input and output file paths are required".into());
                }
                let input = std::fs::read(&self.in_path)
                    .map_err(|e| format!("read {}: {e}", self.in_path))?;
                let out = if dir == Direction::Encrypt {
                    engine::encrypt_password_bytes(pw, &self.opts, &input)?
                } else {
                    engine::decrypt_password_bytes(pw, &input)?
                };
                std::fs::write(&self.out_path, &out)
                    .map_err(|e| format!("write {}: {e}", self.out_path))?;
                Ok(format!("Wrote {} bytes to {}", out.len(), self.out_path))
            }
        }
    }
}

/// Run the (blocking, CPU-bound) job on a dedicated thread and await its result,
/// so the UI thread never blocks on the KDF.
async fn run_job(job: Job) -> Result<String, String> {
    let (tx, rx) = oneshot::channel();
    std::thread::spawn(move || {
        let _ = tx.send(job.run());
    });
    rx.await
        .unwrap_or_else(|_| Err("worker thread stopped unexpectedly".into()))
}

impl App {
    /// The initial state: `App::default`, then the screenshot harness gets a
    /// chance to seed it (a no-op unless `DORADO_SHOT` is set — see [`shot`]).
    fn launch() -> Self {
        let mut app = App::default();
        shot::configure(&mut app);
        app
    }

    fn title(&self) -> String {
        "dorado".to_string()
    }

    fn theme(&self) -> Theme {
        self.palette().iced_theme(self.theme_name.clone())
    }

    fn subscription(&self) -> Subscription<Message> {
        let busy = if self.busy {
            iced::time::every(Duration::from_millis(40)).map(|_| Message::Tick)
        } else {
            Subscription::none()
        };
        match shot::subscription(self) {
            Some(shot) => Subscription::batch([busy, shot]),
            None => busy,
        }
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::DirectionSelected(d) => self.direction = d,
            Message::SourceSelected(s) => self.source = s,
            // The secure_input already applied the edit to the handle; the
            // message only triggers this re-render.
            Message::PasswordEdited => {}
            Message::TextChanged(v) => self.text = v,
            Message::InPathChanged(v) => self.in_path = v,
            Message::OutPathChanged(v) => self.out_path = v,
            Message::BrowseInPath => {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    self.in_path = path.display().to_string();
                }
            }
            Message::BrowseOutPath => {
                if let Some(path) = rfd::FileDialog::new().save_file() {
                    self.out_path = path.display().to_string();
                }
            }
            Message::ToggleOptions => self.show_options = !self.show_options,
            Message::VariantSelected(v) => self.variant = v,
            Message::KdfSelected(k) => self.kdf = k,
            Message::MacSelected(m) => self.mac = m,
            Message::Argon2MemChanged(v) => self.argon2_mem_mib = v,
            Message::Argon2TimeChanged(v) => self.argon2_time = v,
            Message::ScryptLognChanged(v) => self.scrypt_logn = v,
            Message::Pbkdf2RoundsChanged(v) => self.pbkdf2_rounds = v,
            Message::ChunkChanged(v) => self.chunk_kib = v,
            Message::TweakChanged(v) => self.tweak_hex = v,
            Message::ThemeSelected(name) => self.theme_name = name,
            Message::Tick => self.progress = (self.progress + 0.04) % 1.0,
            Message::Copy => return iced::clipboard::write(self.output.clone()),
            Message::Run => {
                if self.busy {
                    return Task::none();
                }
                let opts = match self.options() {
                    Ok(o) => o,
                    Err(e) => {
                        self.status = format!("Error: {e}");
                        self.output.clear();
                        return Task::none();
                    }
                };
                let job = Job {
                    direction: self.direction,
                    source: self.source,
                    opts,
                    // Copy the bytes out under the handle's lock into a wiped
                    // buffer of the job's own.
                    password: Zeroizing::new(self.password.with_bytes(|pw| pw.to_vec())),
                    text: self.text.clone(),
                    in_path: self.in_path.clone(),
                    out_path: self.out_path.clone(),
                };
                self.busy = true;
                self.progress = 0.0;
                self.status = "Working…".to_string();
                self.output.clear();
                return Task::perform(run_job(job), Message::Completed);
            }
            Message::Completed(result) => {
                self.busy = false;
                match result {
                    Ok(out) => {
                        self.output = out;
                        self.status = "Done".to_string();
                    }
                    Err(e) => {
                        self.output.clear();
                        self.status = format!("Error: {e}");
                    }
                }
            }
            Message::Shot(e) => return shot::handle(self, e),
        }
        Task::none()
    }

    fn view(&self) -> Element<'_, Message> {
        let _scope = theme::enter(self.palette());
        let p = theme::tokens();

        let header = column![
            text("dorado").size(32).color(p.ink),
            text("Threefish password encryption")
                .size(13)
                .color(p.muted),
        ]
        .spacing(3);

        let direction = segmented(&[
            (
                "Encrypt",
                self.direction == Direction::Encrypt,
                Direction::Encrypt,
            ),
            (
                "Decrypt",
                self.direction == Direction::Decrypt,
                Direction::Decrypt,
            ),
        ])
        .map(Message::DirectionSelected);

        let source = segmented(&[
            ("Text", self.source == Source::Text, Source::Text),
            ("File", self.source == Source::File, Source::File),
        ])
        .map(Message::SourceSelected);

        let mut content = Column::new()
            .spacing(16)
            .max_width(420)
            .push(header)
            .push(theme_picker(&self.theme_name, Message::ThemeSelected))
            .push(direction)
            .push(source)
            // Enter in the password field submits, same as the Go button.
            .push(password_field(
                &self.password,
                Message::PasswordEdited,
                Message::Run,
            ));

        match self.source {
            Source::Text => {
                let (label, placeholder) = match self.direction {
                    Direction::Encrypt => ("Message", "text to encrypt"),
                    Direction::Decrypt => ("Ciphertext (hex)", "hex to decrypt"),
                };
                content = content.push(labeled(
                    label,
                    text_field(placeholder, &self.text, Message::TextChanged),
                ));
            }
            Source::File => {
                content = content
                    .push(file_path_field(
                        "Input file",
                        "path to read",
                        &self.in_path,
                        Message::InPathChanged,
                        Message::BrowseInPath,
                    ))
                    .push(file_path_field(
                        "Output file",
                        "path to write",
                        &self.out_path,
                        Message::OutPathChanged,
                        Message::BrowseOutPath,
                    ));
            }
        }

        let toggle_label = if self.show_options {
            "Options ▴"
        } else {
            "Options ▾"
        };
        content = content.push(button::ghost(toggle_label, Message::ToggleOptions));

        if self.show_options {
            content = content.push(self.options_view());
        }

        let go_label = if self.busy { "Working…" } else { "Go" };
        let mut go = iced::widget::button(
            text(go_label)
                .size(16)
                .width(Length::Fill)
                .align_x(Horizontal::Center),
        )
        .padding(13)
        .width(Length::Fill)
        .style(theme::rounded(iced::widget::button::primary));
        if !self.busy {
            go = go.on_press(Message::Run);
        }
        content = content.push(go);

        content = content.push(progress_status_row(self.busy, self.progress, &self.status));

        if !self.output.is_empty() {
            content = content.push(output_panel("Output", &self.output, Message::Copy));
        }

        let centered = container(content).center_x(Length::Fill);
        container(scrollable(centered))
            .padding(16)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }
}

impl App {
    /// The collapsible options panel: variant, KDF, KDF cost, chunk size, tweak.
    fn options_view(&self) -> Element<'_, Message> {
        let cost: Element<'_, Message> = match self.kdf {
            KdfChoice::Argon2id => column![
                slider(
                    "Memory",
                    4.0..=256.0,
                    self.argon2_mem_mib as f32,
                    format!("{} MiB", self.argon2_mem_mib),
                    |v: f32| Message::Argon2MemChanged(v.round() as u32),
                ),
                slider(
                    "Iterations",
                    1.0..=8.0,
                    self.argon2_time as f32,
                    format!("{}", self.argon2_time),
                    |v: f32| Message::Argon2TimeChanged(v.round() as u32),
                ),
            ]
            .spacing(12)
            .into(),
            KdfChoice::Scrypt => slider(
                "Cost log2(N)",
                8.0..=20.0,
                self.scrypt_logn as f32,
                format!("{}", self.scrypt_logn),
                |v: f32| Message::ScryptLognChanged(v.round() as u8),
            ),
            KdfChoice::Pbkdf2 => slider(
                "Rounds",
                10_000.0..=1_000_000.0,
                self.pbkdf2_rounds as f32,
                format!("{}", self.pbkdf2_rounds),
                |v: f32| Message::Pbkdf2RoundsChanged(v.round() as u32),
            ),
        };

        card(
            column![
                picker(
                    "Variant",
                    &VARIANTS[..],
                    Some(self.variant),
                    Message::VariantSelected,
                ),
                picker(
                    "Key derivation",
                    &KDFS[..],
                    Some(self.kdf),
                    Message::KdfSelected,
                ),
                picker(
                    "Authentication (MAC)",
                    &MACS[..],
                    Some(self.mac),
                    Message::MacSelected,
                ),
                cost,
                slider(
                    "Chunk size",
                    1.0..=512.0,
                    self.chunk_kib as f32,
                    format!("{} KiB", self.chunk_kib),
                    |v: f32| Message::ChunkChanged(v.round() as u32),
                ),
                labeled(
                    "Tweak (hex, optional)",
                    text_field("blank = zeros", &self.tweak_hex, Message::TweakChanged),
                ),
            ]
            .spacing(14),
        )
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
