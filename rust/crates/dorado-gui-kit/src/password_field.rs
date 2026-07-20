//! A labeled, secure (masked) password field.

use iced::Element;
use rime::widgets::{labeled, secure_input, SecretHandle};

/// A "Password" field over a caller-owned [`SecretHandle`] (rime's locked,
/// wiped, fixed-capacity secret buffer). The typed password stays in the
/// handle and never enters the message queue: the field emits only the unit
/// message `on_edit` after any mutation and `on_submit` on Enter, and renders
/// mask bullets instead of text. Read the bytes with
/// [`SecretHandle::with_bytes`] when running a job.
pub fn password_field<'a, M: Clone + 'a>(
    secret: &SecretHandle,
    on_edit: M,
    on_submit: M,
) -> Element<'a, M> {
    labeled(
        "Password",
        secure_input("password", secret, on_edit, on_submit),
    )
}
