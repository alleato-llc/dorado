//! A titled output block: a caption + "Copy" button header row above a
//! bordered, scrollable text block.

use iced::widget::text::Wrapping;
use iced::widget::{column, container, row, scrollable, text, Space};
use iced::{Alignment, Element, Length};
use rime::theme::tokens;
use rime::widgets::{button, card};

/// `caption` and a "Copy" button (emitting `on_copy`) in a header row, above
/// `body` shown in a scrollable card.
///
/// **Render this unconditionally, including before a job has run.** An empty
/// `body` draws the same frame with `placeholder` in it and the Copy button
/// disabled, so the panel is a fixed part of the layout rather than something
/// that pops into existence and shoves the rest of the window down.
///
/// `font` overrides the face the body is rendered in; `None` keeps iced's
/// default. Callers pass one because iced fixes the application-wide default
/// font at startup, so a user-chosen font has to reach the widget directly.
/// The placeholder always uses the default font: it is prose, not output.
///
/// `body` is **borrowed into the text widget, never copied**. iced's text takes
/// a `Cow`, so handing it a `String` (as `body.to_string()` would) allocates a
/// fresh owned copy on every redraw. When the body is decrypted plaintext, that
/// is a new unwiped copy of the secret per frame, which no amount of wiping on
/// the caller's side can catch. Borrowing produces `Cow::Borrowed` and
/// allocates nothing.
pub fn output_panel<'a, M: Clone + 'a>(
    caption: &'a str,
    body: &'a str,
    placeholder: &'a str,
    font: Option<iced::Font>,
    on_copy: M,
) -> Element<'a, M> {
    let p = tokens();
    let is_empty = body.is_empty();
    // Nothing to copy yet: keep the button in place (so the header does not
    // reflow when output arrives) but inert.
    let mut copy = button::ghost("Copy", on_copy);
    if is_empty {
        copy = copy.on_press_maybe(None);
    }
    let header = row![
        text(caption).size(12).color(p.muted),
        Space::new().width(Length::Fill),
        copy,
    ]
    .align_y(Alignment::Center);
    // Ciphertext hex is one unbroken token, so the default word wrapping leaves
    // it running off the right edge; `WordOrGlyph` breaks it mid-token while
    // still wrapping decrypted plaintext on word boundaries.
    let content = card(
        container(scrollable(
            // Trailing gutter so wrapped lines clear the overlaid scrollbar
            // instead of running under it.
            container(if is_empty {
                text(placeholder).size(13).color(p.muted)
            } else {
                let body = text(body).size(13).wrapping(Wrapping::WordOrGlyph);
                match font {
                    Some(font) => body.font(font),
                    None => body,
                }
            })
            .padding([0, 10]),
        ))
        .width(Length::Fill)
        .height(Length::Fixed(120.0)),
    );
    column![header, content].spacing(8).into()
}
