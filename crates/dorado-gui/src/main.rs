//! A small, polished iced GUI to demo dorado. It is the password tool in a
//! window: pick encrypt/decrypt, a source (typed text or a file), enter a
//! password, optionally tune the cipher/KDF options, and go. The cryptographic
//! work (the same authenticated container the CLI writes) lives in `engine` and
//! runs on a background thread so the window stays responsive.
//!
//! Educational and unaudited. The cryptographic work lives in the
//! `dorado-engine` crate.

#![forbid(unsafe_code)]

mod style;

use std::time::Duration;

use iced::alignment::Horizontal;
use iced::futures::channel::oneshot;
use iced::widget::{
    button, column, container, pick_list, progress_bar, row, scrollable, slider, text, text_input,
    Column, Space,
};
use iced::{
    executor, Alignment, Application, Command, Element, Length, Settings, Subscription, Theme,
};

use dorado_engine as engine;
use dorado_engine::{KdfParams, PrfId, Variant};

fn main() -> iced::Result {
    App::run(Settings {
        window: iced::window::Settings {
            size: iced::Size::new(480.0, 640.0),
            ..Default::default()
        },
        ..Default::default()
    })
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

#[derive(Debug, Clone)]
enum Message {
    DirectionSelected(Direction),
    SourceSelected(Source),
    PasswordChanged(String),
    TextChanged(String),
    InPathChanged(String),
    OutPathChanged(String),
    ToggleOptions,
    VariantSelected(VariantChoice),
    KdfSelected(KdfChoice),
    Argon2MemChanged(u32),
    Argon2TimeChanged(u32),
    ScryptLognChanged(u8),
    Pbkdf2RoundsChanged(u32),
    ChunkChanged(u32),
    TweakChanged(String),
    Run,
    Tick,
    Copy,
    Completed(Result<String, String>),
}

struct App {
    direction: Direction,
    source: Source,
    password: String,
    text: String,
    in_path: String,
    out_path: String,
    // Options.
    show_options: bool,
    variant: VariantChoice,
    kdf: KdfChoice,
    argon2_mem_mib: u32,
    argon2_time: u32,
    scrypt_logn: u8,
    pbkdf2_rounds: u32,
    chunk_kib: u32,
    tweak_hex: String,
    // Result.
    output: String,
    status: String,
    busy: bool,
    progress: f32,
}

impl Default for App {
    fn default() -> Self {
        App {
            direction: Direction::Encrypt,
            source: Source::Text,
            password: String::new(),
            text: String::new(),
            in_path: String::new(),
            out_path: String::new(),
            show_options: false,
            variant: VariantChoice::B256,
            kdf: KdfChoice::Argon2id,
            argon2_mem_mib: 64,
            argon2_time: 3,
            scrypt_logn: 15,
            pbkdf2_rounds: 600_000,
            chunk_kib: 64,
            tweak_hex: String::new(),
            output: String::new(),
            status: String::new(),
            busy: false,
            progress: 0.0,
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
            tweak,
            chunk_size: self.chunk_kib.saturating_mul(1024),
        })
    }
}

/// A self-contained unit of work, so the crypto can run on a worker thread
/// without borrowing from the UI state.
struct Job {
    direction: Direction,
    source: Source,
    opts: engine::PasswordOptions,
    password: String,
    text: String,
    in_path: String,
    out_path: String,
}

impl Job {
    fn run(self) -> Result<String, String> {
        let pw = self.password.as_bytes();
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

impl Application for App {
    type Executor = executor::Default;
    type Message = Message;
    type Theme = Theme;
    type Flags = ();

    fn new(_flags: ()) -> (Self, Command<Message>) {
        (App::default(), Command::none())
    }

    fn title(&self) -> String {
        "dorado".to_string()
    }

    fn theme(&self) -> Theme {
        Theme::custom("darcula".to_string(), style::PALETTE)
    }

    fn subscription(&self) -> Subscription<Message> {
        if self.busy {
            iced::time::every(Duration::from_millis(40)).map(|_| Message::Tick)
        } else {
            Subscription::none()
        }
    }

    fn update(&mut self, message: Message) -> Command<Message> {
        match message {
            Message::DirectionSelected(d) => self.direction = d,
            Message::SourceSelected(s) => self.source = s,
            Message::PasswordChanged(v) => self.password = v,
            Message::TextChanged(v) => self.text = v,
            Message::InPathChanged(v) => self.in_path = v,
            Message::OutPathChanged(v) => self.out_path = v,
            Message::ToggleOptions => self.show_options = !self.show_options,
            Message::VariantSelected(v) => self.variant = v,
            Message::KdfSelected(k) => self.kdf = k,
            Message::Argon2MemChanged(v) => self.argon2_mem_mib = v,
            Message::Argon2TimeChanged(v) => self.argon2_time = v,
            Message::ScryptLognChanged(v) => self.scrypt_logn = v,
            Message::Pbkdf2RoundsChanged(v) => self.pbkdf2_rounds = v,
            Message::ChunkChanged(v) => self.chunk_kib = v,
            Message::TweakChanged(v) => self.tweak_hex = v,
            Message::Tick => self.progress = (self.progress + 0.04) % 1.0,
            Message::Copy => return iced::clipboard::write(self.output.clone()),
            Message::Run => {
                if self.busy {
                    return Command::none();
                }
                let opts = match self.options() {
                    Ok(o) => o,
                    Err(e) => {
                        self.status = format!("Error: {e}");
                        self.output.clear();
                        return Command::none();
                    }
                };
                let job = Job {
                    direction: self.direction,
                    source: self.source,
                    opts,
                    password: self.password.clone(),
                    text: self.text.clone(),
                    in_path: self.in_path.clone(),
                    out_path: self.out_path.clone(),
                };
                self.busy = true;
                self.progress = 0.0;
                self.status = "Working…".to_string();
                self.output.clear();
                return Command::perform(run_job(job), Message::Completed);
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
        }
        Command::none()
    }

    fn view(&self) -> Element<'_, Message> {
        let header = column![
            text("dorado").size(32).style(style::text_strong()),
            text("Threefish password encryption")
                .size(13)
                .style(style::text_muted()),
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
            .push(direction)
            .push(source)
            .push(field(
                "Password",
                input("password", &self.password, Message::PasswordChanged).secure(true),
            ));

        match self.source {
            Source::Text => {
                let (label, placeholder) = match self.direction {
                    Direction::Encrypt => ("Message", "text to encrypt"),
                    Direction::Decrypt => ("Ciphertext (hex)", "hex to decrypt"),
                };
                content = content.push(field(
                    label,
                    input(placeholder, &self.text, Message::TextChanged),
                ));
            }
            Source::File => {
                content = content
                    .push(field(
                        "Input file",
                        input("path to read", &self.in_path, Message::InPathChanged),
                    ))
                    .push(field(
                        "Output file",
                        input("path to write", &self.out_path, Message::OutPathChanged),
                    ));
            }
        }

        let toggle = button(
            text(if self.show_options {
                "Options ▴"
            } else {
                "Options ▾"
            })
            .size(13),
        )
        .padding([6, 12])
        .style(style::segment(false))
        .on_press(Message::ToggleOptions);
        content = content.push(toggle);

        if self.show_options {
            content = content.push(self.options_view());
        }

        let mut go = button(
            text(if self.busy { "Working…" } else { "Go" })
                .size(16)
                .horizontal_alignment(Horizontal::Center),
        )
        .padding(13)
        .width(Length::Fill)
        .style(style::primary());
        if !self.busy {
            go = go.on_press(Message::Run);
        }
        content = content.push(go);

        if self.busy {
            content =
                content.push(progress_bar(0.0..=1.0, self.progress).height(Length::Fixed(5.0)));
        }
        if !self.status.is_empty() {
            content = content.push(
                text(self.status.as_str())
                    .size(13)
                    .style(style::text_muted()),
            );
        }
        if !self.output.is_empty() {
            let head = row![
                text("Output").size(12).style(style::text_muted()),
                Space::with_width(Length::Fill),
                button(text("Copy").size(12))
                    .padding([5, 12])
                    .style(style::segment(false))
                    .on_press(Message::Copy),
            ]
            .align_items(Alignment::Center);
            content = content.push(head).push(
                container(scrollable(text(self.output.as_str()).size(13)))
                    .padding(12)
                    .width(Length::Fill)
                    .height(Length::Fixed(120.0))
                    .style(style::panel()),
            );
        }

        let centered = container(content).width(Length::Fill).center_x();
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
                slider_field(
                    format!("Memory: {} MiB", self.argon2_mem_mib),
                    slider(4..=256u32, self.argon2_mem_mib, Message::Argon2MemChanged),
                ),
                slider_field(
                    format!("Iterations: {}", self.argon2_time),
                    slider(1..=8u32, self.argon2_time, Message::Argon2TimeChanged),
                ),
            ]
            .spacing(12)
            .into(),
            KdfChoice::Scrypt => slider_field(
                format!("Cost log2(N): {}", self.scrypt_logn),
                slider(8..=20u8, self.scrypt_logn, Message::ScryptLognChanged),
            ),
            KdfChoice::Pbkdf2 => slider_field(
                format!("Rounds: {}", self.pbkdf2_rounds),
                slider(
                    10_000..=1_000_000u32,
                    self.pbkdf2_rounds,
                    Message::Pbkdf2RoundsChanged,
                ),
            ),
        };

        container(
            column![
                field(
                    "Variant",
                    pick_list(&VARIANTS[..], Some(self.variant), Message::VariantSelected)
                        .width(Length::Fill)
                        .padding(9),
                ),
                field(
                    "Key derivation",
                    pick_list(&KDFS[..], Some(self.kdf), Message::KdfSelected)
                        .width(Length::Fill)
                        .padding(9),
                ),
                cost,
                slider_field(
                    format!("Chunk size: {} KiB", self.chunk_kib),
                    slider(1..=512u32, self.chunk_kib, Message::ChunkChanged),
                ),
                field(
                    "Tweak (hex, optional)",
                    input("blank = zeros", &self.tweak_hex, Message::TweakChanged),
                ),
            ]
            .spacing(14),
        )
        .padding(14)
        .width(Length::Fill)
        .style(style::panel())
        .into()
    }
}

/// A muted label above a control.
fn field<'a>(label: &'a str, control: impl Into<Element<'a, Message>>) -> Element<'a, Message> {
    column![
        text(label).size(12).style(style::text_muted()),
        control.into()
    ]
    .spacing(7)
    .into()
}

/// A muted "label: value" caption above a slider.
fn slider_field<'a>(caption: String, s: impl Into<Element<'a, Message>>) -> Element<'a, Message> {
    column![text(caption).size(12).style(style::text_muted()), s.into()]
        .spacing(7)
        .into()
}

/// A styled single-line input.
fn input<'a>(
    placeholder: &'a str,
    value: &'a str,
    on_input: impl Fn(String) -> Message + 'a,
) -> iced::widget::TextInput<'a, Message> {
    text_input(placeholder, value)
        .on_input(on_input)
        .padding(11)
        .size(15)
        .style(style::input())
}

/// A segmented control: a row of pill buttons, one selected. Generic over the
/// value each segment carries.
fn segmented<'a, V: Copy + 'a>(items: &[(&'a str, bool, V)]) -> Element<'a, V> {
    let mut row = iced::widget::Row::new().spacing(8);
    for &(label, selected, value) in items {
        row = row.push(
            button(text(label).size(14))
                .padding([9, 20])
                .style(style::segment(selected))
                .on_press(value),
        );
    }
    row.into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
