//! A labeled, secure (masked) password field.

use iced::Element;
use rime::widgets::{labeled, text_field};

/// A "Password" field bound to `value`, masking its contents and emitting
/// `on_input(text)` on every edit.
pub fn password_field<'a, M: Clone + 'a>(
    value: &'a str,
    on_input: impl Fn(String) -> M + 'a,
) -> Element<'a, M> {
    labeled(
        "Password",
        text_field("password", value, on_input).secure(true),
    )
}
