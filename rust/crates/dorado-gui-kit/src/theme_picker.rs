//! The theme picker: a labeled dropdown over rime's built-in named palettes.

use iced::Element;
use rime::theme::builtin_themes;

use crate::picker::picker;

/// A "Theme" dropdown over [`rime::theme::builtin_themes`], showing `current`
/// (by name) and emitting the chosen theme's name via `on_select`. `current` not
/// matching any built-in name (e.g. a stale persisted value) just renders with
/// nothing selected; the host decides the fallback palette.
pub fn theme_picker<'a, M: Clone + 'a>(
    current: &'a str,
    on_select: impl Fn(String) -> M + 'a,
) -> Element<'a, M> {
    let names: Vec<&'static str> = builtin_themes().iter().map(|(name, _, _)| *name).collect();
    let selected = names.iter().copied().find(|name| *name == current);
    picker("Theme", names, selected, move |name: &'static str| {
        on_select(name.to_string())
    })
}
