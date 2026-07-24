//! Best-effort process hardening, applied once at startup.
//!
//! Two measures, both aimed at one threat: **another process running as the
//! same user reading dorado's memory** (the class that infostealer malware
//! exploits, and that same-user `ptrace` or a core-dump file exposes).
//!
//! - **Core dumps are disabled** (`RLIMIT_CORE` = 0). A crash must not spill
//!   decrypted plaintext, or the password, into a dump file on disk.
//! - **On Linux, the process is marked non-dumpable** (`PR_SET_DUMPABLE` = 0),
//!   which also refuses `ptrace` attach from other same-user processes.
//!
//! What this buys that in-process wiping cannot: the copies of plaintext that
//! iced and cosmic-text keep in their own text and glyph buffers (see
//! `output_panel`) are unreachable from any widget, so they cannot be zeroized.
//! But if nothing may attach to or dump this process, those copies stop being
//! reachable by anything short of code already executing as the user, which no
//! amount of wiping would stop either. So this is the measure that covers the
//! residual the widget layer architecturally cannot.
//!
//! # Honest limits
//!
//! This is best-effort and does **not** defend against: root, a compromised
//! kernel, cold-boot / DMA, a debugger attached *before* the mark is set, or a
//! keylogger upstream of the app. It raises the bar against unprivileged
//! same-user snooping and accidental core dumps, nothing more. macOS gets only
//! the core-dump limit: its `PT_DENY_ATTACH` is a private, unreliable API that
//! also complicates notarization, so it is deliberately not used. This mirrors
//! how KeePassXC and libsodium frame the same measures.
//!
//! Applying `PR_SET_DUMPABLE` also blocks attaching a debugger to dorado
//! itself, so hardening is skipped when `DORADO_NO_HARDEN` is set (for local
//! debugging) and under the screenshot harness (`DORADO_SHOT`), which is a dev
//! affordance.

/// Apply the hardening, unless opted out. Best-effort: every failure is
/// swallowed, since a refused limit or an unsupported platform must never stop
/// the app from running.
pub fn apply() {
    if opted_out(
        std::env::var_os("DORADO_NO_HARDEN").is_some(),
        std::env::var_os("DORADO_SHOT").is_some(),
    ) {
        return;
    }

    // Cross-Unix: no core file, whatever its size, on a crash.
    let _ = rustix::process::setrlimit(
        rustix::process::Resource::Core,
        rustix::process::Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    );

    // Linux only: refuse ptrace from same-user processes and exclude from core
    // dumps. macOS has no equivalent that is both reliable and public.
    #[cfg(target_os = "linux")]
    let _ = rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable);
}

/// Whether to skip hardening: for local debugging (`DORADO_NO_HARDEN`) or under
/// the screenshot harness (`DORADO_SHOT`), both dev affordances that a
/// non-dumpable process would obstruct. Pure, so the policy is testable without
/// touching real process state.
fn opted_out(no_harden: bool, shot: bool) -> bool {
    no_harden || shot
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardens_by_default_opts_out_for_dev() {
        assert!(!opted_out(false, false), "default is to harden");
        assert!(opted_out(true, false), "DORADO_NO_HARDEN opts out");
        assert!(opted_out(false, true), "the screenshot harness opts out");
        assert!(opted_out(true, true));
    }

    #[test]
    fn core_dumps_can_be_disabled_on_this_platform() {
        // Proves the measure actually takes effect here, not just that it
        // compiles. Lowers this test process's own core limit (harmless; no
        // test wants a core file).
        use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};
        setrlimit(
            Resource::Core,
            Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        )
        .expect("setrlimit(RLIMIT_CORE, 0) should be permitted for one's own process");
        assert_eq!(getrlimit(Resource::Core).current, Some(0));
    }
}
