//! Composite, dorado-flavored widgets built on top of the `rime` component kit.
//!
//! `rime` supplies the generic primitives (buttons, a labeled text field, a
//! styled dropdown, a slider, a card...); this crate composes the handful of
//! app-shaped controls that both `dorado-gui` and (in a later phase)
//! `dorado-gyotaku-gui` need, so neither frontend re-derives them on its own.
//! Every composite here follows rime's own component contract: a pure
//! `fn(...) -> Element<'a, M>` builder, generic over the host's message type,
//! holding no state and reading colors only from [`rime::theme::tokens`].
//!
//! Internal to the dorado workspace; not published to crates.io.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod file_path_field;
mod output_panel;
mod password_field;
mod picker;
mod progress_status;
mod segmented;
mod theme_picker;

pub use file_path_field::file_path_field;
pub use output_panel::output_panel;
pub use password_field::password_field;
pub use picker::picker;
pub use progress_status::progress_status_row;
pub use segmented::segmented;
pub use theme_picker::theme_picker;
