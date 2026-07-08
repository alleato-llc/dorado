//! A labeled dropdown: [`rime::widgets::labeled`] wrapping [`rime::widgets::select`].
//! Replaces a bare `pick_list` plus a hand-rolled caption above it.

use std::borrow::Borrow;

use iced::widget::PickList;
use iced::{Element, Length, Theme};
use rime::widgets::{labeled, select};

/// A `label` above a styled dropdown over `options`, showing `selected`,
/// emitting `on_select(choice)` when the pick changes. Used for every
/// enum-valued option in the encryption settings (variant, KDF, MAC) as well as
/// any other labeled single-select.
pub fn picker<'a, T, L, V, M>(
    label: &'a str,
    options: L,
    selected: Option<V>,
    on_select: impl Fn(T) -> M + 'a,
) -> Element<'a, M>
where
    T: ToString + PartialEq + Clone + 'a,
    L: Borrow<[T]> + 'a,
    V: Borrow<T> + 'a,
    M: Clone + 'a,
{
    let pick: PickList<'a, T, L, V, M, Theme> =
        select(options, selected, on_select).width(Length::Fill);
    labeled(label, pick)
}
