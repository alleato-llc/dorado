//! Review-screenshot harness — a permanent, env-gated dev affordance. Never
//! remove this, even though it's dead weight outside a screenshot run.
//!
//! iced can capture its own window via wgpu readback (`window::screenshot`),
//! which sidesteps the macOS screen-recording TCC prompt and works headlessly.
//! This module wires that up so a slice can be reviewed as a PNG without a
//! display. It is **inert** unless `GYOTAKU_SHOT` is set: [`configure`] returns
//! early and [`App::shot`](crate::App) stays `None`, so nothing subscribes and
//! nothing renders differently.
//!
//! Ported from soroban's `rust/gui/src/shot.rs` (same structural pattern: a
//! `Shot` struct, an `Event` enum, `configure`/`handle`/`subscription`, and a
//! `save_png` helper), with gyotaku's own env-var names and fields. A sibling of
//! `dorado-gui`'s own `shot.rs`.
//!
//! Everything is parameterized by environment variables — no code edits per shot:
//!
//! - `GYOTAKU_SHOT=<path>` — enable; capture the window to `<path>` (a `.png`).
//! - `GYOTAKU_SHOT_SOURCE=text|file` — sets the text/file source toggle.
//! - `GYOTAKU_SHOT_BITS=256|512|1024` — sets the output-length picker.
//! - `GYOTAKU_SHOT_THEME=<name>` — apply a named theme (e.g. "Solarized Light").
//! - `GYOTAKU_SHOT_TEXT=<text>` — seeds the message field.
//! - `GYOTAKU_SHOT_EXPECTED=<hex>` — seeds the expected-digest field.
//!
//! Judgment call: unlike `dorado-gui`'s KDF-backed job, gyotaku's hash is cheap
//! and deterministic (no KDF cost), so `configure` always runs it synchronously
//! for a text source, exactly like `Job::run`'s text branch, populating
//! `app.output`/`app.status` for real ("Done", or "Match"/"No match" once
//! `GYOTAKU_SHOT_EXPECTED` is set) instead of leaving a blank pre-run state.
//! File source is left as configured with no synchronous run, since a real run
//! there depends on files present on the machine taking the shot.
//!
//! Capture waits three painted frames (so fonts/layout settle) then requests the
//! screenshot and exits.

use iced::{window, Task};

use crate::{hex, App, Message, Source};

/// The capture state, held by [`App`] only while shot mode is active.
pub struct Shot {
    path: String,
    window: Option<window::Id>,
    frames: u32,
    saved: bool,
}

/// A shot-harness lifecycle event, nested under [`Message::Shot`].
#[derive(Debug, Clone)]
pub enum Event {
    /// The window opened; remember its id so we can screenshot it.
    WindowOpened(window::Id),
    /// A frame painted; capture once a few have settled.
    Frame,
    /// The screenshot arrived; write it and exit.
    Captured(window::Screenshot),
}

/// Read `GYOTAKU_SHOT*` and, when enabled, seed the app and arm the capture.
/// A no-op (leaving `app.shot == None`) when `GYOTAKU_SHOT` is unset.
pub fn configure(app: &mut App) {
    let Ok(path) = std::env::var("GYOTAKU_SHOT") else {
        return;
    };

    match std::env::var("GYOTAKU_SHOT_SOURCE").as_deref() {
        Ok("text") => app.source = Source::Text,
        Ok("file") => app.source = Source::File,
        _ => {}
    }
    match std::env::var("GYOTAKU_SHOT_BITS").as_deref() {
        Ok("256") => app.bits = 256,
        Ok("512") => app.bits = 512,
        Ok("1024") => app.bits = 1024,
        _ => {}
    }
    if let Ok(name) = std::env::var("GYOTAKU_SHOT_THEME") {
        app.theme_name = name;
    }
    if let Ok(text) = std::env::var("GYOTAKU_SHOT_TEXT") {
        app.text = text;
    }
    if let Ok(expected) = std::env::var("GYOTAKU_SHOT_EXPECTED") {
        app.expected = expected;
    }

    // See the module doc's judgment-call note: run the real hash synchronously
    // (text source only) so the screenshot shows genuinely computed state.
    if app.source == Source::Text {
        run_sync(app);
    }

    app.shot = Some(Shot {
        path,
        window: None,
        frames: 0,
        saved: false,
    });
}

/// Hash `app.text` synchronously at `app.bits`, and populate
/// `app.output`/`app.status` exactly as `Message::Completed` would.
fn run_sync(app: &mut App) {
    let digest = hex(&dorado::skein::hash(app.bits / 8, app.text.as_bytes()));
    let exp = app.expected.trim();
    app.status = if exp.is_empty() {
        "Done".to_string()
    } else if digest.eq_ignore_ascii_case(exp) {
        "Match".to_string()
    } else {
        "No match".to_string()
    };
    app.output = digest;
}

/// Drive the capture forward from a [`Message::Shot`] event.
pub fn handle(app: &mut App, event: Event) -> Task<Message> {
    let Some(shot) = &mut app.shot else {
        return Task::none();
    };
    match event {
        Event::WindowOpened(id) => {
            shot.window = Some(id);
            Task::none()
        }
        Event::Frame => {
            if !shot.saved {
                if let Some(id) = shot.window {
                    shot.frames += 1;
                    if shot.frames >= 3 {
                        return window::screenshot(id).map(|s| Message::Shot(Event::Captured(s)));
                    }
                }
            }
            Task::none()
        }
        Event::Captured(screenshot) => {
            shot.saved = true;
            save_png(&shot.path, &screenshot);
            iced::exit()
        }
    }
}

/// The subscriptions that drive capture — only while shot mode is active.
pub fn subscription(app: &App) -> Option<iced::Subscription<Message>> {
    app.shot.as_ref()?;
    Some(iced::Subscription::batch([
        window::open_events().map(|id| Message::Shot(Event::WindowOpened(id))),
        window::frames().map(|_| Message::Shot(Event::Frame)),
    ]))
}

/// Encode the captured RGBA window into a PNG at `path`.
fn save_png(path: &str, screenshot: &window::Screenshot) {
    let file = std::fs::File::create(path).expect("create png");
    let mut encoder = png::Encoder::new(
        std::io::BufWriter::new(file),
        screenshot.size.width,
        screenshot.size.height,
    );
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().expect("png header");
    writer
        .write_image_data(&screenshot.rgba)
        .expect("png image data");
}
