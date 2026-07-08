//! The busy footer: an optional progress bar above an optional status caption.

use iced::widget::{progress_bar, text, Column};
use iced::{Border, Element, Length};
use rime::theme::tokens;

/// A progress bar (shown only while `busy`) above a status caption (shown only
/// when `status` is non-empty). Used under a long-running job to show it is
/// working, then its final "Done" / "Error: ..." line.
pub fn progress_status_row<'a, M: 'a>(
    busy: bool,
    progress: f32,
    status: &'a str,
) -> Element<'a, M> {
    let p = tokens();
    let mut col = Column::new().spacing(8);
    if busy {
        col = col.push(
            progress_bar(0.0..=1.0, progress)
                .girth(Length::Fixed(5.0))
                .style(move |_theme| iced::widget::progress_bar::Style {
                    background: p.hairline.into(),
                    bar: p.accent.into(),
                    border: Border::default(),
                }),
        );
    }
    if !status.is_empty() {
        col = col.push(text(status.to_string()).size(13).color(p.muted));
    }
    col.into()
}
