//! A small iced GUI for gyotaku: Skein-512 hashing in a window. Pick a source
//! (typed text or a file), an output length, and it shows the digest, computed by
//! the same `dorado::skein` code the CLI uses (streaming a file in constant memory
//! on a worker thread). Optionally paste an expected digest to verify a match.
//!
//! Educational and unaudited. A sibling of `dorado-gui`, the encryption GUI; the
//! two share a look. Hashing is unkeyed, matching the `gyotaku` CLI.

#![forbid(unsafe_code)]

mod style;

use std::io::Read;
use std::time::Duration;

use iced::alignment::Horizontal;
use iced::futures::channel::oneshot;
use iced::widget::{
    button, column, container, progress_bar, row, scrollable, text, text_input, Column, Space,
};
use iced::{
    executor, Alignment, Application, Command, Element, Length, Settings, Subscription, Theme,
};

fn main() -> iced::Result {
    App::run(Settings {
        window: iced::window::Settings {
            size: iced::Size::new(460.0, 560.0),
            ..Default::default()
        },
        ..Default::default()
    })
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
    BitsSelected(usize),
    ExpectedChanged(String),
    Run,
    Tick,
    Copy,
    Completed(Result<String, String>),
}

struct App {
    source: Source,
    text: String,
    in_path: String,
    bits: usize,
    expected: String,
    output: String,
    status: String,
    busy: bool,
    progress: f32,
}

impl Default for App {
    fn default() -> Self {
        App {
            source: Source::Text,
            text: String::new(),
            in_path: String::new(),
            bits: 256,
            expected: String::new(),
            output: String::new(),
            status: String::new(),
            busy: false,
            progress: 0.0,
        }
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

impl Application for App {
    type Executor = executor::Default;
    type Message = Message;
    type Theme = Theme;
    type Flags = ();

    fn new(_flags: ()) -> (Self, Command<Message>) {
        (App::default(), Command::none())
    }

    fn title(&self) -> String {
        "gyotaku".to_string()
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
            Message::SourceSelected(s) => self.source = s,
            Message::TextChanged(v) => self.text = v,
            Message::InPathChanged(v) => self.in_path = v,
            Message::BitsSelected(b) => self.bits = b,
            Message::ExpectedChanged(v) => self.expected = v,
            Message::Tick => self.progress = (self.progress + 0.04) % 1.0,
            Message::Copy => return iced::clipboard::write(self.output.clone()),
            Message::Run => {
                if self.busy {
                    return Command::none();
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
                return Command::perform(run_job(job), Message::Completed);
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
        }
        Command::none()
    }

    fn view(&self) -> Element<'_, Message> {
        let header = column![
            text("gyotaku").size(32).style(style::text_strong()),
            text("Skein-512 file fingerprint")
                .size(13)
                .style(style::text_muted()),
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
            .push(source);

        match self.source {
            Source::Text => {
                content = content.push(field(
                    "Message",
                    input("text to hash", &self.text, Message::TextChanged),
                ));
            }
            Source::File => {
                content = content.push(field(
                    "Input file",
                    input("path to read", &self.in_path, Message::InPathChanged),
                ));
            }
        }

        content = content.push(field("Output length", bits)).push(field(
            "Expected digest (hex, optional)",
            input("paste to verify", &self.expected, Message::ExpectedChanged),
        ));

        let mut go = button(
            text(if self.busy { "Working…" } else { "Hash" })
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
                text("Digest").size(12).style(style::text_muted()),
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
                    .height(Length::Fixed(90.0))
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

/// A muted label above a control.
fn field<'a>(label: &'a str, control: impl Into<Element<'a, Message>>) -> Element<'a, Message> {
    column![
        text(label).size(12).style(style::text_muted()),
        control.into()
    ]
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
