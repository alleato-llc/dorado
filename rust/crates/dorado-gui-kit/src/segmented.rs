//! A segmented control: a row of pill buttons, one active. Generic over the
//! value each segment carries, so one control serves any two-or-more-way choice
//! (Encrypt/Decrypt, Text/File, ...) instead of a bespoke stylesheet per app.

use iced::widget::Row;
use iced::Element;
use rime::widgets::button;

/// A row of segments, one of which is `selected`. Each `(label, selected,
/// value)` becomes a button; pressing a segment emits its `value` directly (the
/// caller typically `.map`s the result into its own `Message`).
pub fn segmented<'a, V: Copy + 'a>(items: &[(&'a str, bool, V)]) -> Element<'a, V> {
    let mut row = Row::new().spacing(8);
    for &(label, selected, value) in items {
        row = row.push(if selected {
            button::primary(label, value)
        } else {
            button::secondary(label, value)
        });
    }
    row.into()
}
