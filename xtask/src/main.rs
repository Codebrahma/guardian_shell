// =============================================================================
// xtask - Build Tooling for Guardian Shell
// =============================================================================
//
// This program provides build commands for the project, specifically for
// compiling the eBPF kernel program which requires special build flags.
//
// Usage:
//   cargo xtask build-ebpf           # Debug build
//   cargo xtask build-ebpf --release # Release build (recommended for deployment)
//
// WHAT THIS DOES:
//
// When you run `cargo xtask build-ebpf`, it executes:
//
//   cargo +nightly build
//     --package guardian-ebpf          # Only build the eBPF crate
//     --target bpfel-unknown-none      # Compile to BPF bytecode (little-endian)
//     -Z build-std=core                # Rebuild core library for BPF target
//     [--release]                      # Optional optimization
//
// The compiled eBPF binary is placed at:
//   target/bpfel-unknown-none/debug/guardian-ebpf    (debug)
//   target/bpfel-unknown-none/release/guardian-ebpf  (release)
//
// This binary is then loaded by the userspace daemon at runtime.

use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::Parser;

// =============================================================================
// Command-Line Interface
// =============================================================================

#[derive(Parser)]
#[command(name = "xtask", about = "Guardian Shell build tools")]
enum Cli {
    /// Build the eBPF kernel program
    ///
    /// Compiles the guardian-ebpf crate for the BPF target.
    /// The output is a BPF ELF binary that the userspace daemon loads into the kernel.
    BuildEbpf(BuildEbpfArgs),
}

#[derive(Parser)]
struct BuildEbpfArgs {
    /// Build in release mode with optimizations.
    ///
    /// Release mode is STRONGLY recommended because:
    ///   1. The BPF verifier is more likely to accept optimized code
    ///   2. Unoptimized BPF code can exceed instruction limits
    ///   3. Better runtime performance in the kernel
    #[arg(long)]
    release: bool,
}

// =============================================================================
// Main Entry Point
// =============================================================================

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli {
        Cli::BuildEbpf(args) => build_ebpf(args),
    }
}

// =============================================================================
// eBPF Build Logic
// =============================================================================

/// Builds the eBPF kernel program for the BPF target.
///
/// This runs cargo with the necessary flags to cross-compile Rust to BPF bytecode.
///
/// # Prerequisites
///
/// Before running this, ensure you have:
///
///   1. Nightly Rust toolchain:
///      ```
///      rustup install nightly
///      rustup component add rust-src --toolchain nightly
///      ```
///
///   2. BPF linker (for linking BPF object files):
///      ```
///      cargo install bpf-linker
///      ```
///
/// # Build Process
///
/// The build process is:
///   1. Cargo compiles guardian-common (shared types) for BPF target
///   2. Cargo compiles guardian-ebpf for BPF target
///   3. bpf-linker links the BPF object files into a final ELF binary
///   4. The ELF binary contains BPF programs, maps, and BTF metadata
///
/// # Target Architecture
///
/// We use `bpfel-unknown-none` which means:
///   - bpf: BPF bytecode (not x86, ARM, etc.)
///   - el: Little-endian (most common; use bpfeb for big-endian)
///   - unknown: No specific vendor
///   - none: No operating system (bare metal / kernel context)
fn build_ebpf(args: BuildEbpfArgs) -> Result<()> {
    println!("Building eBPF program...");

    let mut cmd = Command::new("cargo");

    // Use nightly toolchain (required for -Z build-std)
    cmd.arg("+nightly");

    cmd.arg("build")
        // Only build the eBPF crate (not the whole workspace)
        .arg("--package")
        .arg("guardian-ebpf")
        // Cross-compile to BPF target
        // bpfel = BPF little-endian (matches x86_64, aarch64 host byte order)
        .arg("--target")
        .arg("bpfel-unknown-none")
        // Rebuild the `core` library for the BPF target.
        // This is necessary because the BPF target doesn't come with
        // pre-compiled standard libraries (it's a tier 3 target).
        // -Z flags require nightly Rust.
        .arg("-Z")
        .arg("build-std=core");

    if args.release {
        cmd.arg("--release");
        println!("  Mode: release (optimized)");
    } else {
        println!("  Mode: debug");
    }

    println!("  Target: bpfel-unknown-none");
    println!(
        "  Output: target/bpfel-unknown-none/{}/guardian-ebpf",
        if args.release { "release" } else { "debug" }
    );
    println!();

    // Execute the build command
    let status = cmd
        .status()
        .context(
            "Failed to execute cargo. Is Rust installed?\n\
             Install Rust: https://rustup.rs/\n\
             Install nightly: rustup install nightly\n\
             Install rust-src: rustup component add rust-src --toolchain nightly\n\
             Install bpf-linker: cargo install bpf-linker",
        )?;

    if !status.success() {
        bail!(
            "eBPF build failed. Common issues:\n\
             \n\
             1. Missing nightly toolchain:\n\
             \x20  rustup install nightly\n\
             \x20  rustup component add rust-src --toolchain nightly\n\
             \n\
             2. Missing bpf-linker:\n\
             \x20  cargo install bpf-linker\n\
             \n\
             3. BPF verifier rejects the program (try --release for optimized code)\n\
             \n\
             4. Compilation errors: check the error messages above"
        );
    }

    println!();
    println!("eBPF program built successfully!");
    println!(
        "Binary: target/bpfel-unknown-none/{}/guardian-ebpf",
        if args.release { "release" } else { "debug" }
    );

    Ok(())
}
