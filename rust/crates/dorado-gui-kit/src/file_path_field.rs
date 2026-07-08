//! A labeled path field paired with a trailing "Browse…" button. This crate
//! does not depend on `rfd`; the host wires `on_browse` to its own native
//! Open/Save dialog and writes the result back into `value`.

use iced::widget::row;
use iced::{Alignment, Element, Length};
use rime::widgets::{button, labeled, text_field};

/// A `label` above a path field bound to `value` (via `on_input`) with a
/// trailing "Browse…" button (via `on_browse`, which the host fires
/// synchronously against its own native file dialog).
pub fn file_path_field<'a, M: Clone + 'a>(
    label: &'a str,
    placeholder: &'a str,
    value: &'a str,
    on_input: impl Fn(String) -> M + 'a,
    on_browse: M,
) -> Element<'a, M> {
    let field = row![
        text_field(placeholder, value, on_input).width(Length::Fill),
        button::secondary("Browse…", on_browse),
    ]
    .spacing(8)
    .align_y(Alignment::Center);
    labeled(label, field)
}
