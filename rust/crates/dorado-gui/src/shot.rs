//! Review-screenshot harness — a permanent, env-gated dev affordance. Never
//! remove this, even though it's dead weight outside a screenshot run.
//!
//! iced can capture its own window via wgpu readback (`window::screenshot`),
//! which sidesteps the macOS screen-recording TCC prompt and works headlessly.
//! This module wires that up so a slice can be reviewed as a PNG without a
//! display. It is **inert** unless `DORADO_SHOT` is set: [`configure`] returns
//! early and [`App::shot`](crate::App) stays `None`, so nothing subscribes and
//! nothing renders differently.
//!
//! Ported from soroban's `rust/gui/src/shot.rs` (same structural pattern: a
//! `Shot` struct, an `Event` enum, `configure`/`handle`/`subscription`, and a
//! `save_png` helper), with dorado's own env-var names and fields.
//!
//! Everything is parameterized by environment variables — no code edits per shot:
//!
//! - `DORADO_SHOT=<path>` — enable; capture the window to `<path>` (a `.png`).
//! - `DORADO_SHOT_DIRECTION=encrypt|decrypt` — sets the encrypt/decrypt toggle.
//! - `DORADO_SHOT_SOURCE=text|file` — sets the text/file source toggle.
//! - `DORADO_SHOT_OPTIONS=1` — expand the options panel (any non-empty value).
//! - `DORADO_SHOT_THEME=<name>` — apply a named theme (e.g. "Solarized Light").
//! - `DORADO_SHOT_KDF=argon2id|scrypt|pbkdf2` — sets the KDF picker.
//! - `DORADO_SHOT_VARIANT=256|512|1024` — sets the Threefish variant picker.
//! - `DORADO_SHOT_MAC=skein|hmac-sha256|blake3` — sets the MAC picker.
//! - `DORADO_SHOT_PASSWORD=<text>` — seeds the password field.
//! - `DORADO_SHOT_TEXT=<text>` — seeds the message/ciphertext-hex field.
//!
//! Judgment call: when the source is text and a password is set, `configure`
//! runs the real encrypt/decrypt synchronously via `engine::encrypt_password_bytes`
//! / `decrypt_password_bytes` (the same functions the worker-thread `Job` calls),
//! so the screenshot shows a genuinely computed output/status ("Done" or a real
//! error) rather than a blank pre-run state — mirroring how soroban's harness
//! seeds real evaluated state (`SOROBAN_SHOT_SEED`) rather than raw field
//! assignment. Blocking briefly at startup is fine; screenshot generation isn't
//! performance-sensitive. File source is left as configured with no synchronous
//! run, since a real run there depends on files present on the machine taking
//! the shot.
//!
//! Capture waits three painted frames (so fonts/layout settle) then requests the
//! screenshot and exits.

use iced::{window, Task};
use zeroize::Zeroize;

use dorado_engine as engine;

use crate::{hex, App, Direction, KdfChoice, MacChoice, Message, Source, VariantChoice};

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

/// Read `DORADO_SHOT*` and, when enabled, seed the app and arm the capture.
/// A no-op (leaving `app.shot == None`) when `DORADO_SHOT` is unset.
pub fn configure(app: &mut App) {
    let Ok(path) = std::env::var("DORADO_SHOT") else {
        return;
    };

    match std::env::var("DORADO_SHOT_DIRECTION").as_deref() {
        Ok("encrypt") => app.direction = Direction::Encrypt,
        Ok("decrypt") => app.direction = Direction::Decrypt,
        _ => {}
    }
    match std::env::var("DORADO_SHOT_SOURCE").as_deref() {
        Ok("text") => app.source = Source::Text,
        Ok("file") => app.source = Source::File,
        _ => {}
    }
    if std::env::var("DORADO_SHOT_OPTIONS").is_ok() {
        app.show_options = true;
    }
    if let Ok(name) = std::env::var("DORADO_SHOT_THEME") {
        app.theme_name = name;
    }
    match std::env::var("DORADO_SHOT_KDF").as_deref() {
        Ok("argon2id") => app.kdf = KdfChoice::Argon2id,
        Ok("scrypt") => app.kdf = KdfChoice::Scrypt,
        Ok("pbkdf2") => app.kdf = KdfChoice::Pbkdf2,
        _ => {}
    }
    match std::env::var("DORADO_SHOT_VARIANT").as_deref() {
        Ok("256") => app.variant = VariantChoice::B256,
        Ok("512") => app.variant = VariantChoice::B512,
        Ok("1024") => app.variant = VariantChoice::B1024,
        _ => {}
    }
    match std::env::var("DORADO_SHOT_MAC").as_deref() {
        Ok("skein") => app.mac = MacChoice::Skein,
        Ok("hmac-sha256") => app.mac = MacChoice::HmacSha256,
        Ok("blake3") => app.mac = MacChoice::Blake3,
        _ => {}
    }
    if let Ok(mut password) = std::env::var("DORADO_SHOT_PASSWORD") {
        // Write the env-provided password into the locked handle, then wipe
        // the intermediate String (best-effort; the env block itself remains).
        app.password.push_str(&password);
        password.zeroize();
    }
    if let Ok(text) = std::env::var("DORADO_SHOT_TEXT") {
        app.text = text;
    }

    // See the module doc's judgment-call note: run the real job synchronously
    // (text source only) so the screenshot shows genuinely computed state.
    if app.source == Source::Text && !app.password.is_empty() {
        run_sync(app);
    }

    app.shot = Some(Shot {
        path,
        window: None,
        frames: 0,
        saved: false,
    });
}

/// Run the configured encrypt/decrypt synchronously, blocking `configure`, and
/// populate `app.output`/`app.status` exactly as `Message::Completed` would.
fn run_sync(app: &mut App) {
    let opts = match app.options() {
        Ok(opts) => opts,
        Err(e) => {
            app.status = format!("Error: {e}");
            return;
        }
    };
    match compute(app, &opts) {
        Ok(out) => {
            app.output = out;
            app.status = "Done".to_string();
        }
        Err(e) => {
            app.output.clear();
            app.status = format!("Error: {e}");
        }
    }
}

/// The actual encrypt/decrypt, mirroring `Job::run`'s text-source branch. The
/// password bytes are read under the handle's lock for the duration of the
/// engine call.
fn compute(app: &App, opts: &engine::PasswordOptions) -> Result<String, String> {
    app.password.with_bytes(|pw| match app.direction {
        Direction::Encrypt => {
            let ct = engine::encrypt_password_bytes(pw, opts, app.text.as_bytes())?;
            Ok(hex(&ct))
        }
        Direction::Decrypt => {
            let data = engine::parse_hex(&app.text).map_err(|e| format!("ciphertext hex: {e}"))?;
            let pt = engine::decrypt_password_bytes(pw, &data)?;
            Ok(String::from_utf8_lossy(&pt).into_owned())
        }
    })
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
