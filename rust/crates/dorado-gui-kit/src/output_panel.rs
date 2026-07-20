//! A titled output block: a caption + "Copy" button header row above a
//! bordered, scrollable text block.

use iced::widget::text::Wrapping;
use iced::widget::{column, container, row, scrollable, text, Space};
use iced::{Alignment, Element, Length};
use rime::theme::tokens;
use rime::widgets::{button, card};

/// `caption` and a "Copy" button (emitting `on_copy`) in a header row, above
/// `body` shown in a scrollable card. Used for a completed job's result.
pub fn output_panel<'a, M: Clone + 'a>(
    caption: &'a str,
    body: &'a str,
    on_copy: M,
) -> Element<'a, M> {
    let p = tokens();
    let header = row![
        text(caption.to_string()).size(12).color(p.muted),
        Space::new().width(Length::Fill),
        button::ghost("Copy", on_copy),
    ]
    .align_y(Alignment::Center);
    // Ciphertext hex is one unbroken token, so the default word wrapping leaves
    // it running off the right edge; `WordOrGlyph` breaks it mid-token while
    // still wrapping decrypted plaintext on word boundaries.
    let content = card(
        container(scrollable(
            // Trailing gutter so wrapped lines clear the overlaid scrollbar
            // instead of running under it.
            container(
                text(body.to_string())
                    .size(13)
                    .wrapping(Wrapping::WordOrGlyph),
            )
            .padding([0, 10]),
        ))
        .width(Length::Fill)
        .height(Length::Fixed(120.0)),
    );
    column![header, content].spacing(8).into()
}
