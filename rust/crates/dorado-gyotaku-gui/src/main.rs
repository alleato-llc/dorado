//! A small iced GUI for gyotaku: Skein-512 hashing in a window. Pick a source
//! (typed text or a file), an output length, and it shows the digest, computed by
//! the same `dorado::skein` code the CLI uses (streaming a file in constant memory
//! on a worker thread). Optionally paste an expected digest to verify a match.
//!
//! The look is built on `rime`, the house iced component kit (a sibling repo),
//! plus `dorado-gui-kit`'s composites over it; see `rust/CLAUDE.md`. A sibling of
//! `dorado-gui`, the encryption GUI; the two share a look. Hashing is unkeyed,
//! matching the `gyotaku` CLI.

#![forbid(unsafe_code)]

use std::io::Read;
use std::time::Duration;

use iced::alignment::Horizontal;
use iced::futures::channel::oneshot;
use iced::widget::{column, container, scrollable, text, Column};
use iced::{Element, Length, Subscription, Task, Theme};

use dorado_gui_kit::{file_path_field, output_panel, progress_status_row, segmented, theme_picker};
use rime::theme;
use rime::widgets::{labeled, text_field};

mod shot;

/// The default theme, by name (see [`rime::theme::builtin_themes`]).
const DEFAULT_THEME: &str = "Dracula";

/// The embedded app icon (a gyotaku-style fish print). Shown as the
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
    // visible with nothing scrolled out of frame (the digest output panel is
    // taller than the normal window), so it gets a taller window; the normal
    // app keeps its compact default.
    let height = if std::env::var_os("GYOTAKU_SHOT").is_some() {
        760.0
    } else {
        560.0
    };
    iced::application(App::launch, App::update, App::view)
        .title(App::title)
        .theme(App::theme)
        .subscription(App::subscription)
        .window(iced::window::Settings {
            size: iced::Size::new(460.0, height),
            icon: app_icon(),
            ..Default::default()
        })
        .run()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    Text,
    File,
}

/// The selectable output lengths (Skein supports any multiple of 8; these are the
/// common ones, matching the cipher's block sizes). Labels are static so the
/// segmented control can borrow them for the lifetime of the view.
const SIZE_ITEMS: [(&str, usize); 3] = [("256-bit", 256), ("512-bit", 512), ("1024-bit", 1024)];

#[derive(Debug, Clone)]
enum Message {
    SourceSelected(Source),
    TextChanged(String),
    InPathChanged(String),
    BrowseInPath,
    BitsSelected(usize),
    ExpectedChanged(String),
    ThemeSelected(String),
    Run,
    Tick,
    Copy,
    Completed(Result<String, String>),
    /// A screenshot-harness lifecycle event; see [`shot`]. No-op unless
    /// `GYOTAKU_SHOT` is set.
    Shot(shot::Event),
}

struct App {
    source: Source,
    text: String,
    in_path: String,
    bits: usize,
    expected: String,
    // Appearance.
    theme_name: String,
    // Result.
    output: String,
    status: String,
    busy: bool,
    progress: f32,
    /// The review-screenshot harness, present only when `GYOTAKU_SHOT` is set —
    /// otherwise `None` and the whole thing is inert. See [`shot`].
    shot: Option<shot::Shot>,
}

impl Default for App {
    fn default() -> Self {
        App {
            source: Source::Text,
            text: String::new(),
            in_path: String::new(),
            bits: 256,
            expected: String::new(),
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

/// A self-contained unit of work, so the hash can run on a worker thread without
/// borrowing from the UI state.
struct Job {
    source: Source,
    text: String,
    in_path: String,
    out_len: usize,
}

impl Job {
    fn run(self) -> Result<String, String> {
        match self.source {
            Source::Text => Ok(hex(&dorado::skein::hash(
                self.out_len,
                self.text.as_bytes(),
            ))),
            Source::File => {
                if self.in_path.is_empty() {
                    return Err("choose an input file".into());
                }
                let file = std::fs::File::open(&self.in_path)
                    .map_err(|e| format!("open {}: {e}", self.in_path))?;
                digest_reader(file, self.out_len).map_err(|e| format!("read {}: {e}", self.in_path))
            }
        }
    }
}

/// Stream-hash a reader into a hex digest, in constant memory (so files larger
/// than RAM are fine), using the incremental Skein hasher.
fn digest_reader(mut reader: impl Read, out_len: usize) -> std::io::Result<String> {
    let mut h = dorado::skein::Skein512::new(out_len);
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    let mut out = vec![0u8; out_len];
    h.finalize_into(&mut out);
    Ok(hex(&out))
}

/// Run the (blocking) job on a dedicated thread and await its result, so the UI
/// thread never blocks while hashing a large file.
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
    /// chance to seed it (a no-op unless `GYOTAKU_SHOT` is set — see [`shot`]).
    fn launch() -> Self {
        let mut app = App::default();
        shot::configure(&mut app);
        app
    }

    fn title(&self) -> String {
        "gyotaku".to_string()
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
            Message::SourceSelected(s) => self.source = s,
            Message::TextChanged(v) => self.text = v,
            Message::InPathChanged(v) => self.in_path = v,
            Message::BrowseInPath => {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    self.in_path = path.display().to_string();
                }
            }
            Message::BitsSelected(b) => self.bits = b,
            Message::ExpectedChanged(v) => self.expected = v,
            Message::ThemeSelected(name) => self.theme_name = name,
            Message::Tick => self.progress = (self.progress + 0.04) % 1.0,
            Message::Copy => return iced::clipboard::write(self.output.clone()),
            Message::Run => {
                if self.busy {
                    return Task::none();
                }
                let job = Job {
                    source: self.source,
                    text: self.text.clone(),
                    in_path: self.in_path.clone(),
                    out_len: self.bits / 8,
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
                    Ok(digest) => {
                        let exp = self.expected.trim();
                        self.status = if exp.is_empty() {
                            "Done".to_string()
                        } else if digest.eq_ignore_ascii_case(exp) {
                            "Match".to_string()
                        } else {
                            "No match".to_string()
                        };
                        self.output = digest;
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
            text("gyotaku").size(32).color(p.ink),
            text("Skein-512 file fingerprint").size(13).color(p.muted),
        ]
        .spacing(3);

        let source = segmented(&[
            ("Text", self.source == Source::Text, Source::Text),
            ("File", self.source == Source::File, Source::File),
        ])
        .map(Message::SourceSelected);

        let bits_items: Vec<(&'static str, bool, usize)> = SIZE_ITEMS
            .iter()
            .map(|&(label, b)| (label, self.bits == b, b))
            .collect();
        let bits = segmented(&bits_items).map(Message::BitsSelected);

        let mut content = Column::new()
            .spacing(16)
            .max_width(420)
            .push(header)
            .push(theme_picker(&self.theme_name, Message::ThemeSelected))
            .push(source);

        match self.source {
            Source::Text => {
                content = content.push(labeled(
                    "Message",
                    text_field("text to hash", &self.text, Message::TextChanged),
                ));
            }
            Source::File => {
                content = content.push(file_path_field(
                    "Input file",
                    "path to read",
                    &self.in_path,
                    Message::InPathChanged,
                    Message::BrowseInPath,
                ));
            }
        }

        content = content.push(labeled("Output length", bits)).push(labeled(
            "Expected digest (hex, optional)",
            text_field("paste to verify", &self.expected, Message::ExpectedChanged),
        ));

        let go_label = if self.busy { "Working…" } else { "Hash" };
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
            content = content.push(output_panel("Digest", &self.output, Message::Copy));
        }

        let centered = container(content).center_x(Length::Fill);
        container(scrollable(centered))
            .padding(16)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
