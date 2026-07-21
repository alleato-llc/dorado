use super::*;

#[test]
fn section_labels_cover_every_variant() {
    // The rail speaks indices and `LABELS` is hand-written, so a new variant
    // could be added without a label (or vice versa). Walk every index the
    // labels claim and check it maps back to a distinct section.
    let sections: Vec<Section> = (0..Section::LABELS.len())
        .map(Section::from_index)
        .collect();
    assert_eq!(sections.len(), Section::LABELS.len());
    for (i, section) in sections.iter().enumerate() {
        assert_eq!(section.index(), i, "label {i} does not round-trip");
    }
}

#[test]
fn section_index_round_trips() {
    for section in [Section::Encryption, Section::Appearance, Section::Clipboard] {
        assert_eq!(Section::from_index(section.index()), section);
    }
}

#[test]
fn out_of_range_section_index_is_not_a_panic() {
    // `view` feeds the rail's index straight back in; a stale or bogus one must
    // degrade to the first section rather than take the window down.
    assert_eq!(Section::from_index(99), Section::Encryption);
}

#[test]
fn clipboard_labels_are_unique() {
    // The picker maps a chosen label back to its seconds value by searching for
    // an equal label. Two choices rendering the same string would silently
    // select the wrong interval.
    for (i, a) in CLIPBOARD_CLEAR_CHOICES.iter().enumerate() {
        for b in &CLIPBOARD_CLEAR_CHOICES[i + 1..] {
            assert_ne!(
                clipboard_clear_label(*a),
                clipboard_clear_label(*b),
                "{a}s and {b}s render identically"
            );
        }
    }
}

#[test]
fn clipboard_labels_round_trip_through_the_reverse_lookup() {
    // Mirrors what the picker's closure does with the selected label.
    for secs in CLIPBOARD_CLEAR_CHOICES {
        let label = clipboard_clear_label(*secs);
        let found = CLIPBOARD_CLEAR_CHOICES
            .iter()
            .copied()
            .find(|s| clipboard_clear_label(*s) == label);
        assert_eq!(found, Some(*secs));
    }
}

#[test]
fn zero_seconds_reads_as_never() {
    assert_eq!(clipboard_clear_label(0), "Never");
}

#[test]
fn font_lookup_resolves_only_offered_families() {
    // The default label means "leave iced alone", so it must not resolve.
    assert!(font_by_name(DEFAULT_FONT_LABEL).is_none());
    // An unlisted family resolves to None rather than being passed through,
    // which is what keeps `Font::with_name` off any non-'static string.
    assert!(font_by_name("Comic Sans MS").is_none());
    // Everything else on the menu resolves.
    for family in FONT_CHOICES.iter().filter(|f| **f != DEFAULT_FONT_LABEL) {
        assert!(font_by_name(family).is_some(), "{family} did not resolve");
    }
}

#[test]
fn every_font_choice_is_reachable_from_the_default() {
    // The picker offers `FONT_CHOICES` verbatim, so each entry must be a valid
    // selection: the default resolves to None and the rest to Some.
    for family in FONT_CHOICES {
        let resolved = font_by_name(family);
        assert_eq!(resolved.is_none(), *family == DEFAULT_FONT_LABEL);
    }
}
