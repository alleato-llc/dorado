//! Command-line interface for dorado.
//!
//! Runs Threefish in CTR mode over stdin/stdout or files, streaming in constant
//! memory. There are two ways to supply the key:
//!
//!   * Raw key (`--key` / `--key-file`): you provide the exact key bytes as hex
//!     and the IV with `--iv`. Output is bare CTR ciphertext, no container, and
//!     no authentication.
//!   * Password (`--password` / `--password-stdin`): a KDF stretches your
//!     password into encryption and MAC keys, and the output is an authenticated
//!     chunked container (see the `engine` module).
//!
//! This is a thin frontend; the construction lives in the `dorado-engine` crate.
//! This tool is educational and unaudited; do not use it to protect real data.

#![forbid(unsafe_code)]

use std::fs;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::ops::Deref;
use std::process::ExitCode;

use clap::{ArgGroup, Args as ClapArgs, Parser, Subcommand};
use zeroize::{Zeroize, Zeroizing};

use dorado_engine as engine;

/// A password held in a `zeroize`-wiped buffer that is also `mlock`'d into RAM (out
/// of swap) for its lifetime. The lock is best-effort: if the OS refuses (for
/// example `RLIMIT_MEMLOCK` on a locked-down host) the bytes are still wiped on
/// drop. Field order matters: `pw` drops (and zeroizes) before `_guard` unlocks, so
/// the wipe happens while the pages are still locked.
struct LockedPassword {
    pw: Zeroizing<Vec<u8>>,
    _guard: Option<region::LockGuard>,
}

impl LockedPassword {
    fn new(pw: Zeroizing<Vec<u8>>) -> Self {
        let guard = if pw.is_empty() {
            None
        } else {
            region::lock(pw.as_ptr(), pw.len()).ok()
        };
        LockedPassword { pw, _guard: guard }
    }
}

impl Deref for LockedPassword {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.pw
    }
}
use dorado_engine::{KdfParams, MacId, PrfId, Variant};

#[derive(Parser)]
#[command(
    name = "dorado",
    version,
    about = "Threefish in CTR mode (educational, unaudited).",
    long_about = "Apply the Threefish block cipher in CTR mode. CTR provides \
confidentiality only and does not authenticate data. Supply the key directly \
with --key/--key-file, or derive it from a password with --password/--password-stdin."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt input with Threefish-CTR.
    Encrypt(Args),
    /// Decrypt input with Threefish-CTR (the same operation as encrypt).
    Decrypt(Args),
    /// Print a password file's non-secret parameters without decrypting it.
    Inspect(InspectArgs),
}

#[derive(ClapArgs)]
struct InspectArgs {
    /// The password container to inspect. Reads stdin when omitted.
    #[arg(long = "in", value_name = "FILE")]
    input: Option<String>,
}

#[derive(Copy, Clone, clap::ValueEnum)]
enum VariantArg {
    #[value(name = "256")]
    V256,
    #[value(name = "512")]
    V512,
    #[value(name = "1024")]
    V1024,
}

impl VariantArg {
    fn to_variant(self) -> Variant {
        match self {
            VariantArg::V256 => Variant::T256,
            VariantArg::V512 => Variant::T512,
            VariantArg::V1024 => Variant::T1024,
        }
    }
}

#[derive(Copy, Clone, clap::ValueEnum)]
enum KdfArg {
    Argon2id,
    Scrypt,
    Pbkdf2,
}

#[derive(Copy, Clone, clap::ValueEnum)]
enum MacArg {
    Skein,
    #[value(name = "hmac-sha256")]
    HmacSha256,
    Blake3,
}

impl MacArg {
    fn to_mac(self) -> MacId {
        match self {
            MacArg::Skein => MacId::Skein512,
            MacArg::HmacSha256 => MacId::HmacSha256,
            MacArg::Blake3 => MacId::Blake3,
        }
    }
}

#[derive(ClapArgs)]
#[command(group(
    ArgGroup::new("credential")
        .required(true)
        .args(["key", "key_file", "password", "password_stdin"])
))]
struct Args {
    /// Key as hex. Length selects the variant: 32 bytes = 256, 64 = 512, 128 = 1024.
    /// Note: a key on the command line is visible in the process list; prefer --key-file.
    #[arg(long)]
    key: Option<String>,

    /// Read the key (as hex) from a file. Whitespace in the file is ignored.
    #[arg(long = "key-file", value_name = "FILE")]
    key_file: Option<String>,

    /// Derive the key from a password entered interactively (no echo).
    #[arg(long)]
    password: bool,

    /// Derive the key from a password read from stdin. Requires --in for the data.
    #[arg(long = "password-stdin")]
    password_stdin: bool,

    /// Initial counter (IV) as hex, same length as the key. Raw-key mode only;
    /// in password mode the IV is generated and stored in the header.
    #[arg(long)]
    iv: Option<String>,

    /// Tweak as hex, 16 bytes. Defaults to all zero.
    #[arg(long, default_value = "00000000000000000000000000000000")]
    tweak: String,

    /// Variant to use for password encryption (raw-key mode infers it from the key).
    #[arg(long, value_enum, default_value = "256")]
    variant: VariantArg,

    /// KDF for password mode.
    #[arg(long, value_enum, default_value = "argon2id")]
    kdf: KdfArg,

    /// MAC for password mode (authentication).
    #[arg(long, value_enum, default_value = "skein")]
    mac: MacArg,

    /// Optional label to bind into a password file (authenticated, not secret;
    /// shown by `inspect`). Encrypt only.
    #[arg(long)]
    label: Option<String>,

    /// On decrypt, require the file's label to equal this value, or fail before
    /// writing any output. Decrypt only.
    #[arg(long = "expect-label")]
    expect_label: Option<String>,

    /// Argon2id memory cost in MiB.
    #[arg(long = "argon2-mem-mib", default_value_t = 64)]
    argon2_mem_mib: u32,

    /// Argon2id iterations (time cost).
    #[arg(long = "argon2-time", default_value_t = 3)]
    argon2_time: u32,

    /// Argon2id lanes (parallelism).
    #[arg(long = "argon2-par", default_value_t = 1)]
    argon2_par: u32,

    /// scrypt log2(N) cost.
    #[arg(long = "scrypt-logn", default_value_t = 15)]
    scrypt_logn: u8,

    /// scrypt block size factor r.
    #[arg(long = "scrypt-r", default_value_t = 8)]
    scrypt_r: u32,

    /// scrypt parallelization factor p.
    #[arg(long = "scrypt-p", default_value_t = 1)]
    scrypt_p: u32,

    /// PBKDF2-HMAC-SHA256 iteration count.
    #[arg(long = "pbkdf2-rounds", default_value_t = 600_000)]
    pbkdf2_rounds: u32,

    /// Authenticated chunk size for password encryption, in KiB.
    #[arg(long = "chunk-kib", default_value_t = 64)]
    chunk_kib: u32,

    /// Input file. Reads stdin when omitted.
    #[arg(long = "in", value_name = "FILE")]
    input: Option<String>,

    /// Output file. Writes stdout when omitted.
    #[arg(long = "out", value_name = "FILE")]
    output: Option<String>,
}

impl Args {
    fn password_mode(&self) -> bool {
        self.password || self.password_stdin
    }

    fn kdf_params(&self) -> KdfParams {
        match self.kdf {
            KdfArg::Argon2id => KdfParams::Argon2id {
                m_cost: self.argon2_mem_mib.saturating_mul(1024),
                t_cost: self.argon2_time,
                p_cost: self.argon2_par,
            },
            KdfArg::Scrypt => KdfParams::Scrypt {
                log_n: self.scrypt_logn,
                r: self.scrypt_r,
                p: self.scrypt_p,
            },
            KdfArg::Pbkdf2 => KdfParams::Pbkdf2 {
                rounds: self.pbkdf2_rounds,
                prf: PrfId::HmacSha256,
            },
        }
    }

    fn chunk_bytes(&self) -> Result<u32, String> {
        let bytes = self
            .chunk_kib
            .checked_mul(1024)
            .filter(|b| *b > 0)
            .ok_or("--chunk-kib must be between 1 and 1048576")?;
        if bytes > engine::max_chunk_bytes() {
            return Err(format!(
                "chunk size must be at most {} bytes",
                engine::max_chunk_bytes()
            ));
        }
        Ok(bytes)
    }

    fn password_options(&self) -> Result<engine::PasswordOptions, String> {
        Ok(engine::PasswordOptions {
            variant: self.variant.to_variant(),
            kdf: self.kdf_params(),
            mac: self.mac.to_mac(),
            tweak: engine::parse_tweak(&self.tweak)?,
            chunk_size: self.chunk_bytes()?,
            label: self.label.clone().unwrap_or_default().into_bytes(),
        })
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();
    match &cli.command {
        Command::Encrypt(args) => encrypt(args),
        Command::Decrypt(args) => decrypt(args),
        Command::Inspect(args) => inspect(args),
    }
}

fn inspect(args: &InspectArgs) -> Result<(), String> {
    let mut reader = open_reader(args.input.as_deref()).map_err(|e| e.to_string())?;
    let info = engine::inspect(reader.as_mut())?;
    print!("{}", format_info(&info));
    Ok(())
}

/// Render a container's non-secret parameters as human-readable lines.
fn format_info(info: &engine::ContainerInfo) -> String {
    let variant = match info.variant {
        Variant::T256 => "Threefish-256",
        Variant::T512 => "Threefish-512",
        Variant::T1024 => "Threefish-1024",
    };
    let kdf = match info.kdf {
        KdfParams::Argon2id {
            m_cost,
            t_cost,
            p_cost,
        } => format!("Argon2id (memory {m_cost} KiB, iterations {t_cost}, lanes {p_cost})"),
        KdfParams::Scrypt { log_n, r, p } => format!("scrypt (log2(N) {log_n}, r {r}, p {p})"),
        KdfParams::Pbkdf2 { rounds, .. } => format!("PBKDF2-HMAC-SHA256 (rounds {rounds})"),
    };
    let mac = match info.mac {
        MacId::Skein512 => "Skein-512",
        MacId::HmacSha256 => "HMAC-SHA256",
        MacId::Blake3 => "BLAKE3 (keyed)",
    };
    let tweak: String = info.tweak.iter().map(|b| format!("{b:02x}")).collect();
    let label = if info.label.is_empty() {
        "(none)".to_string()
    } else {
        String::from_utf8_lossy(&info.label).into_owned()
    };
    format!(
        "format:   dorado password container (DRDO v{})\n\
         variant:  {variant}\n\
         kdf:      {kdf}\n\
         mac:      {mac}\n\
         chunk:    {} bytes\n\
         salt:     {} bytes\n\
         tweak:    {tweak}\n\
         label:    {label}\n",
        info.version, info.chunk_size, info.salt_len,
    )
}

fn encrypt(args: &Args) -> Result<(), String> {
    if !args.password_mode() {
        return run_raw(args);
    }
    if args.iv.is_some() {
        return Err("--iv is not used in password mode; the IV is generated and stored".into());
    }
    guard_password_stdin(args)?;

    let opts = args.password_options()?;
    let password = read_password(args, true)?;
    let mut reader = open_reader(args.input.as_deref()).map_err(|e| e.to_string())?;
    let mut writer = open_writer(args.output.as_deref()).map_err(|e| e.to_string())?;
    engine::encrypt_password_stream(&password, &opts, reader.as_mut(), writer.as_mut())
        .map_err(String::from)
}

fn decrypt(args: &Args) -> Result<(), String> {
    if !args.password_mode() {
        // CTR is symmetric, so raw-key decryption is the same path as encryption.
        return run_raw(args);
    }
    if args.iv.is_some() {
        return Err("--iv is not used in password mode; it comes from the file header".into());
    }
    guard_password_stdin(args)?;

    let password = read_password(args, false)?;
    let mut reader = open_reader(args.input.as_deref()).map_err(|e| e.to_string())?;
    let mut writer = open_writer(args.output.as_deref()).map_err(|e| e.to_string())?;
    let expected = args.expect_label.as_deref().map(str::as_bytes);
    engine::decrypt_password_stream_expecting(&password, expected, reader.as_mut(), writer.as_mut())
        .map_err(String::from)
}

fn run_raw(args: &Args) -> Result<(), String> {
    let key = resolve_raw_key(args)?;
    let variant = engine::variant_from_key_len(key.len())?;
    let tweak = engine::parse_tweak(&args.tweak)?;

    let iv_hex = args
        .iv
        .as_deref()
        .ok_or("--iv is required with --key/--key-file")?;
    let iv = engine::parse_hex(iv_hex).map_err(|e| format!("iv: {e}"))?;
    if iv.len() != key.len() {
        return Err(format!(
            "iv must be the same length as the key ({} bytes), got {}",
            key.len(),
            iv.len()
        ));
    }

    let mut reader = open_reader(args.input.as_deref()).map_err(|e| e.to_string())?;
    let mut writer = open_writer(args.output.as_deref()).map_err(|e| e.to_string())?;
    engine::raw_ctr_stream(variant, &key, &tweak, &iv, reader.as_mut(), writer.as_mut())
        .map_err(String::from)
}

fn open_reader(path: Option<&str>) -> io::Result<Box<dyn Read>> {
    match path {
        Some(p) => Ok(Box::new(BufReader::new(fs::File::open(p)?))),
        None => Ok(Box::new(BufReader::new(io::stdin()))),
    }
}

fn open_writer(path: Option<&str>) -> io::Result<Box<dyn Write>> {
    match path {
        Some(p) => Ok(Box::new(BufWriter::new(fs::File::create(p)?))),
        None => Ok(Box::new(BufWriter::new(io::stdout()))),
    }
}

fn resolve_raw_key(args: &Args) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut hex = match (&args.key, &args.key_file) {
        (Some(k), _) => k.clone(),
        (None, Some(path)) => fs::read_to_string(path).map_err(|e| format!("key-file: {e}"))?,
        (None, None) => return Err("no key source provided".into()),
    };
    let key = engine::parse_hex(&hex).map_err(|e| format!("key: {e}"));
    hex.zeroize();
    Ok(Zeroizing::new(key?))
}

/// Reading the password from stdin conflicts with reading the data from stdin,
/// so require an explicit input file in that case.
fn guard_password_stdin(args: &Args) -> Result<(), String> {
    if args.password_stdin && args.input.is_none() {
        return Err(
            "with --password-stdin, pass the data via --in (stdin carries the password)".into(),
        );
    }
    Ok(())
}

fn read_password(args: &Args, confirm: bool) -> Result<LockedPassword, String> {
    if args.password_stdin {
        let mut line = String::new();
        io::stdin()
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        let pw = Zeroizing::new(line.trim_end_matches(['\n', '\r']).as_bytes().to_vec());
        line.zeroize();
        return Ok(LockedPassword::new(pw));
    }

    let pw = Zeroizing::new(
        rpassword::prompt_password("Password: ")
            .map_err(|e| e.to_string())?
            .into_bytes(),
    );
    if confirm {
        let again = Zeroizing::new(
            rpassword::prompt_password("Confirm password: ")
                .map_err(|e| e.to_string())?
                .into_bytes(),
        );
        if *pw != *again {
            return Err("passwords do not match".into());
        }
    }
    if pw.is_empty() {
        return Err("password must not be empty".into());
    }
    Ok(LockedPassword::new(pw))
}

#[cfg(test)]
mod tests;
