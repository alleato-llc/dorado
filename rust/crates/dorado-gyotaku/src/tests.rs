use super::*;

#[test]
fn out_len_from_bits_accepts_whole_bytes() {
    assert_eq!(out_len_from_bits(8).unwrap(), 1);
    assert_eq!(out_len_from_bits(256).unwrap(), 32);
    assert_eq!(out_len_from_bits(512).unwrap(), 64);
}

#[test]
fn out_len_from_bits_rejects_zero_and_non_byte_lengths() {
    assert!(out_len_from_bits(0).is_err(), "zero bits is rejected");
    assert!(
        out_len_from_bits(7).is_err(),
        "non-multiple of 8 is rejected"
    );
    assert!(out_len_from_bits(255).is_err());
}

#[test]
fn hex_encodes_lowercase_two_digits_per_byte() {
    assert_eq!(hex(&[]), "");
    assert_eq!(hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
}

#[test]
fn digest_matches_official_empty_skein_512_vector() {
    // The published Skein-512-512 digest of the empty message. This anchors the
    // tool to the reference, on top of the differential tests in `dorado`.
    let want = "bc5b4c50925519c290cc634277ae3d6257212395cba733bbad37a4af0fa06af4\
                1fca7903d06564fea7a2d3730dbdb80c1f85562dfcc070334ea4d1d9e72cba7a";
    let got = hex(&dorado::skein::hash(out_len_from_bits(512).unwrap(), b""));
    assert_eq!(got, want);
}

#[test]
fn format_line_default_and_tagged() {
    assert_eq!(format_line(false, "abcd", "file.txt"), "abcd  file.txt");
    assert_eq!(
        format_line(true, "abcd", "file.txt"),
        "SKEIN-512 (file.txt) = abcd"
    );
}

#[test]
fn is_even_hex_distinguishes_digests() {
    assert!(is_even_hex("00ff"));
    assert!(!is_even_hex(""), "empty is not a digest");
    assert!(!is_even_hex("abc"), "odd length");
    assert!(!is_even_hex("zz"), "non-hex");
}

#[test]
fn parse_check_line_handles_default_form() {
    let (digest, name) = parse_check_line("0977b339  notes.txt").unwrap();
    assert_eq!(digest, "0977b339");
    assert_eq!(name, "notes.txt");

    // A leading '*' binary marker on the name is stripped.
    let (_, name) = parse_check_line("0977b339 *bin.dat").unwrap();
    assert_eq!(name, "bin.dat");
}

#[test]
fn parse_check_line_handles_bsd_tagged_form() {
    let (digest, name) = parse_check_line("SKEIN-512 (notes.txt) = 0977b339").unwrap();
    assert_eq!(digest, "0977b339");
    assert_eq!(name, "notes.txt");
}

#[test]
fn parse_check_line_rejects_malformed() {
    assert!(parse_check_line("not a checksum line").is_none());
    assert!(parse_check_line("xyz  file").is_none(), "non-hex digest");
    assert!(parse_check_line("abc  file").is_none(), "odd-length digest");
}
