use super::*;

fn parse(argv: &[&str]) -> Result<Cli, clap::Error> {
    Cli::try_parse_from(argv)
}

fn args_of(cli: &Cli) -> &Args {
    match &cli.command {
        Command::Encrypt(a) | Command::Decrypt(a) => a,
        Command::Inspect(_) => unreachable!("args_of is only used with encrypt/decrypt"),
    }
}

#[test]
fn cli_definition_is_valid() {
    // clap's own structural check over the whole argument tree.
    use clap::CommandFactory;
    Cli::command().debug_assert();
}

#[test]
fn credential_group_requires_exactly_one_source() {
    // No credential at all is rejected by the required ArgGroup.
    assert!(parse(&["dorado", "encrypt"]).is_err());
    // Two conflicting credentials are rejected.
    assert!(parse(&["dorado", "encrypt", "--password", "--key", "00"]).is_err());
    // A single source parses.
    assert!(parse(&["dorado", "encrypt", "--password"]).is_ok());
}

#[test]
fn variant_and_mac_args_map_to_engine_types() {
    assert!(matches!(VariantArg::V256.to_variant(), Variant::T256));
    assert!(matches!(VariantArg::V512.to_variant(), Variant::T512));
    assert!(matches!(VariantArg::V1024.to_variant(), Variant::T1024));

    assert!(matches!(MacArg::Skein.to_mac(), MacId::Skein512));
    assert!(matches!(MacArg::HmacSha256.to_mac(), MacId::HmacSha256));
    assert!(matches!(MacArg::Blake3.to_mac(), MacId::Blake3));
}

#[test]
fn kdf_params_built_for_each_kdf() {
    let cli = parse(&["dorado", "encrypt", "--password", "--kdf", "argon2id"]).unwrap();
    assert!(matches!(
        args_of(&cli).kdf_params(),
        KdfParams::Argon2id { .. }
    ));

    let cli = parse(&[
        "dorado",
        "encrypt",
        "--password",
        "--kdf",
        "scrypt",
        "--scrypt-logn",
        "14",
    ])
    .unwrap();
    match args_of(&cli).kdf_params() {
        KdfParams::Scrypt { log_n, .. } => assert_eq!(log_n, 14),
        other => panic!("expected scrypt, got {other:?}"),
    }

    let cli = parse(&[
        "dorado",
        "encrypt",
        "--password",
        "--kdf",
        "pbkdf2",
        "--pbkdf2-rounds",
        "1000",
    ])
    .unwrap();
    match args_of(&cli).kdf_params() {
        KdfParams::Pbkdf2 { rounds, .. } => assert_eq!(rounds, 1000),
        other => panic!("expected pbkdf2, got {other:?}"),
    }
}

#[test]
fn argon2_memory_is_converted_from_mib_to_kib() {
    let cli = parse(&["dorado", "encrypt", "--password", "--argon2-mem-mib", "64"]).unwrap();
    match args_of(&cli).kdf_params() {
        KdfParams::Argon2id { m_cost, .. } => assert_eq!(m_cost, 64 * 1024),
        other => panic!("expected argon2, got {other:?}"),
    }
}

#[test]
fn chunk_bytes_validates_bounds() {
    let ok = parse(&["dorado", "encrypt", "--password", "--chunk-kib", "64"]).unwrap();
    assert_eq!(args_of(&ok).chunk_bytes().unwrap(), 64 * 1024);

    // Zero is rejected.
    let zero = parse(&["dorado", "encrypt", "--password", "--chunk-kib", "0"]).unwrap();
    assert!(args_of(&zero).chunk_bytes().is_err());

    // Above the engine's maximum (1 GiB) is rejected without overflowing.
    let big = parse(&["dorado", "encrypt", "--password", "--chunk-kib", "1048577"]).unwrap();
    assert!(args_of(&big).chunk_bytes().is_err());

    // A multiplication that would overflow u32 is also rejected.
    let huge = parse(&[
        "dorado",
        "encrypt",
        "--password",
        "--chunk-kib",
        "4294967295",
    ])
    .unwrap();
    assert!(args_of(&huge).chunk_bytes().is_err());
}

#[test]
fn password_mode_reflects_the_credential() {
    let pw = parse(&["dorado", "encrypt", "--password"]).unwrap();
    assert!(args_of(&pw).password_mode());

    let raw = parse(&["dorado", "encrypt", "--key", "00"]).unwrap();
    assert!(!args_of(&raw).password_mode());
}

#[test]
fn password_options_assemble_from_flags() {
    let cli = parse(&[
        "dorado",
        "encrypt",
        "--password",
        "--variant",
        "512",
        "--mac",
        "blake3",
    ])
    .unwrap();
    let opts = args_of(&cli).password_options().unwrap();
    assert!(matches!(opts.variant, Variant::T512));
    assert!(matches!(opts.mac, MacId::Blake3));
    assert_eq!(opts.tweak, [0u8; 16], "default tweak is all zero");
}

#[test]
fn password_options_reject_a_malformed_tweak() {
    let cli = parse(&["dorado", "encrypt", "--password", "--tweak", "00"]).unwrap();
    assert!(
        args_of(&cli).password_options().is_err(),
        "a 1-byte tweak is not 16 bytes"
    );
}

#[test]
fn format_info_renders_every_field() {
    let info = engine::ContainerInfo {
        version: 4,
        variant: Variant::T1024,
        kdf: KdfParams::Scrypt {
            log_n: 15,
            r: 8,
            p: 1,
        },
        mac: MacId::HmacSha256,
        chunk_size: 65536,
        salt_len: 16,
        tweak: [0xab; 16],
        label: b"my-label".to_vec(),
    };
    let out = format_info(&info);
    assert!(out.contains("DRDO v4"), "{out}");
    assert!(out.contains("Threefish-1024"), "{out}");
    assert!(out.contains("scrypt (log2(N) 15, r 8, p 1)"), "{out}");
    assert!(out.contains("HMAC-SHA256"), "{out}");
    assert!(out.contains("65536 bytes"), "{out}");
    assert!(out.contains("abababab"), "tweak hex present: {out}");
    assert!(out.contains("my-label"), "label present: {out}");
}

#[test]
fn format_info_shows_none_for_an_empty_label() {
    let info = engine::ContainerInfo {
        version: 4,
        variant: Variant::T256,
        kdf: KdfParams::Pbkdf2 {
            rounds: 1000,
            prf: PrfId::HmacSha256,
        },
        mac: MacId::Skein512,
        chunk_size: 65536,
        salt_len: 16,
        tweak: [0u8; 16],
        label: Vec::new(),
    };
    assert!(format_info(&info).contains("label:    (none)"));
}

#[test]
fn label_and_expect_label_parse() {
    let cli = parse(&["dorado", "encrypt", "--password", "--label", "backup"]).unwrap();
    let opts = args_of(&cli).password_options().unwrap();
    assert_eq!(opts.label, b"backup");

    assert!(parse(&[
        "dorado",
        "decrypt",
        "--password",
        "--expect-label",
        "backup",
    ])
    .is_ok());
}

#[test]
fn unauthenticated_flag_parses_for_raw_key_mode() {
    let cli = parse(&[
        "dorado",
        "encrypt",
        "--key",
        "00",
        "--iv",
        "00",
        "--unauthenticated",
    ])
    .unwrap();
    assert!(args_of(&cli).unauthenticated);

    let default = parse(&["dorado", "encrypt", "--key", "00", "--iv", "00"]).unwrap();
    assert!(
        !args_of(&default).unauthenticated,
        "authenticated by default"
    );
}

#[test]
fn unauthenticated_is_rejected_in_password_mode() {
    let cli = parse(&["dorado", "encrypt", "--password", "--unauthenticated"]).unwrap();
    assert!(encrypt(args_of(&cli)).is_err());

    let cli = parse(&["dorado", "decrypt", "--password", "--unauthenticated"]).unwrap();
    assert!(decrypt(args_of(&cli)).is_err());
}

#[test]
fn inspect_command_takes_no_credential() {
    // inspect is a separate subcommand with no required credential group.
    assert!(parse(&["dorado", "inspect"]).is_ok());
    assert!(parse(&["dorado", "inspect", "--in", "file.mahi"]).is_ok());
}

#[cfg(unix)]
#[test]
fn core_dumps_can_be_suppressed_on_this_platform() {
    // Proves the measure actually takes effect here, not just that it compiles.
    // Lowers this test process's own core limit (harmless; no test wants a
    // core file), then reads it back.
    suppress_core_dumps();
    let (soft, _hard) = rlimit::getrlimit(rlimit::Resource::CORE).expect("getrlimit(CORE)");
    assert_eq!(
        soft, 0,
        "core-dump soft limit should be zero after suppression"
    );
}
