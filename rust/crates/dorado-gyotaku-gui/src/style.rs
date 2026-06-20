//! Custom styling: a Darcula-flavored dark palette with rounded inputs, a
//! segmented control, and an accent action button. Shared in spirit with
//! dorado-gui so the two frontends look like one family.

use iced::widget::{button, container, text_input};
use iced::{theme, Background, Border, Color, Theme};

const fn rgb(r: u8, g: u8, b: u8) -> Color {
    Color {
        r: r as f32 / 255.0,
        g: g as f32 / 255.0,
        b: b as f32 / 255.0,
        a: 1.0,
    }
}

// Darcula-inspired palette.
const BG: Color = rgb(0x2b, 0x2b, 0x2b);
const PANEL: Color = rgb(0x31, 0x33, 0x35);
const FIELD: Color = rgb(0x3c, 0x3f, 0x41);
const SEG_OFF: Color = rgb(0x3c, 0x3f, 0x41);
const SEG_HOVER: Color = rgb(0x4c, 0x50, 0x52);
const BORDER: Color = rgb(0x51, 0x51, 0x51);
const ACCENT: Color = rgb(0x4d, 0x9e, 0xea);
const ACCENT_HOVER: Color = rgb(0x6a, 0xb0, 0xf0);
const ACCENT_DIM: Color = rgb(0x35, 0x50, 0x6b);
const TEXT: Color = rgb(0xa9, 0xb7, 0xc6);
const MUTED: Color = rgb(0x80, 0x80, 0x80);

pub const PALETTE: theme::Palette = theme::Palette {
    background: BG,
    text: TEXT,
    primary: ACCENT,
    success: ACCENT,
    danger: rgb(0xcc, 0x66, 0x66),
};

pub fn text_strong() -> theme::Text {
    theme::Text::Color(TEXT)
}

pub fn text_muted() -> theme::Text {
    theme::Text::Color(MUTED)
}

pub fn panel() -> theme::Container {
    theme::Container::Custom(Box::new(Panel))
}

pub fn input() -> theme::TextInput {
    theme::TextInput::Custom(Box::new(Field))
}

pub fn primary() -> theme::Button {
    theme::Button::Custom(Box::new(Primary))
}

pub fn segment(selected: bool) -> theme::Button {
    theme::Button::Custom(Box::new(Segment { selected }))
}

fn border(color: Color, width: f32, radius: f32) -> Border {
    Border {
        color,
        width,
        radius: radius.into(),
    }
}

struct Panel;
impl container::StyleSheet for Panel {
    type Style = Theme;
    fn appearance(&self, _: &Theme) -> container::Appearance {
        container::Appearance {
            text_color: None,
            background: Some(Background::Color(PANEL)),
            border: border(BORDER, 1.0, 10.0),
            ..Default::default()
        }
    }
}

struct Field;
impl text_input::StyleSheet for Field {
    type Style = Theme;
    fn active(&self, _: &Theme) -> text_input::Appearance {
        text_input::Appearance {
            background: Background::Color(FIELD),
            border: border(BORDER, 1.0, 10.0),
            icon_color: MUTED,
        }
    }
    fn focused(&self, _: &Theme) -> text_input::Appearance {
        text_input::Appearance {
            background: Background::Color(FIELD),
            border: border(ACCENT, 1.5, 10.0),
            icon_color: MUTED,
        }
    }
    fn disabled(&self, theme: &Theme) -> text_input::Appearance {
        self.active(theme)
    }
    fn placeholder_color(&self, _: &Theme) -> Color {
        MUTED
    }
    fn value_color(&self, _: &Theme) -> Color {
        TEXT
    }
    fn disabled_color(&self, _: &Theme) -> Color {
        MUTED
    }
    fn selection_color(&self, _: &Theme) -> Color {
        Color { a: 0.35, ..ACCENT }
    }
}

struct Primary;
impl button::StyleSheet for Primary {
    type Style = Theme;
    fn active(&self, _: &Theme) -> button::Appearance {
        button::Appearance {
            background: Some(Background::Color(ACCENT)),
            border: border(Color::TRANSPARENT, 0.0, 10.0),
            text_color: Color::WHITE,
            ..Default::default()
        }
    }
    fn hovered(&self, _: &Theme) -> button::Appearance {
        button::Appearance {
            background: Some(Background::Color(ACCENT_HOVER)),
            border: border(Color::TRANSPARENT, 0.0, 10.0),
            text_color: Color::WHITE,
            ..Default::default()
        }
    }
    fn disabled(&self, _: &Theme) -> button::Appearance {
        button::Appearance {
            background: Some(Background::Color(ACCENT_DIM)),
            border: border(Color::TRANSPARENT, 0.0, 10.0),
            text_color: Color {
                a: 0.7,
                ..Color::WHITE
            },
            ..Default::default()
        }
    }
}

struct Segment {
    selected: bool,
}
impl button::StyleSheet for Segment {
    type Style = Theme;
    fn active(&self, _: &Theme) -> button::Appearance {
        let (bg, fg) = if self.selected {
            (ACCENT, Color::WHITE)
        } else {
            (SEG_OFF, MUTED)
        };
        button::Appearance {
            background: Some(Background::Color(bg)),
            border: border(Color::TRANSPARENT, 0.0, 9.0),
            text_color: fg,
            ..Default::default()
        }
    }
    fn hovered(&self, theme: &Theme) -> button::Appearance {
        if self.selected {
            self.active(theme)
        } else {
            button::Appearance {
                background: Some(Background::Color(SEG_HOVER)),
                text_color: TEXT,
                ..self.active(theme)
            }
        }
    }
}
