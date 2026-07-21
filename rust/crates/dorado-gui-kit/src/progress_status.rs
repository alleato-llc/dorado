//! The busy footer: a progress bar shown while working, above a status caption.

use iced::widget::{progress_bar, text, Column, Space};
use iced::{Border, Element, Length};
use rime::theme::tokens;

/// The progress bar's height, reserved whether or not the bar is drawn.
const BAR_GIRTH: f32 = 5.0;

/// A progress bar (drawn only while `busy`) above a status caption ("Done" /
/// "Error: ...").
///
/// The row is a **constant height** in every state: an empty status still
/// occupies its line and the bar's slot is held open when idle. Collapsing
/// either one would shift everything below at the exact moment the user is
/// reading it, which is what happens when a job finishes and a "Done" line
/// appears out of nowhere.
pub fn progress_status_row<'a, M: 'a>(
    busy: bool,
    progress: f32,
    status: &'a str,
) -> Element<'a, M> {
    let p = tokens();
    let bar: Element<'a, M> = if busy {
        progress_bar(0.0..=1.0, progress)
            .girth(Length::Fixed(BAR_GIRTH))
            .style(move |_theme| iced::widget::progress_bar::Style {
                background: p.hairline.into(),
                bar: p.accent.into(),
                border: Border::default(),
            })
            .into()
    } else {
        Space::new().height(Length::Fixed(BAR_GIRTH)).into()
    };
    // A space rather than "": an empty string lays out with no line box, which
    // would collapse the row again. One space reserves exactly one line and
    // renders as nothing.
    let caption = if status.is_empty() { " " } else { status };
    Column::new()
        .spacing(8)
        .push(bar)
        .push(text(caption.to_string()).size(13).color(p.muted))
        .into()
}
