//! Pulse CLI entry point.

use std::process::ExitCode;

use pulse_core::{Format, JsonStyle, Target};

mod dashboard;

// ----------------------------------------------------------
// CLI parsing
// ----------------------------------------------------------

#[derive(Debug, Default)]
struct Cli {
    command: Option<String>,
    help: bool,
    version_flag: bool,
    format: Option<Format>,
    json_shorthand: bool,
    compact: bool,
    output: Option<String>,
    context: Option<String>,
    verbose: bool,
}

fn parse_args(args: &[String]) -> Result<Cli, String> {
    let mut cli = Cli::default();
    for a in args {
        if a == "-h" || a == "--help" {
            cli.help = true;
        } else if a == "-V" || a == "--version" {
            cli.version_flag = true;
        } else if a == "--json" {
            cli.json_shorthand = true;
        } else if a == "--compact" {
            cli.compact = true;
        } else if a == "--verbose" {
            cli.verbose = true;
        } else if let Some(v) = a.strip_prefix("--context=") {
            cli.context = Some(v.to_string());
        } else if let Some(v) = a.strip_prefix("--format=") {
            cli.format =
                Some(Format::parse(v).ok_or_else(|| {
                    format!("unknown format '{v}' (expected: text, json, markdown)")
                })?);
        } else if let Some(v) = a.strip_prefix("--output=") {
            if v.is_empty() {
                return Err("--output requires a file path".into());
            }
            cli.output = Some(v.to_string());
        } else if a.starts_with("--since=")
            || a.starts_with("--source=")
            || a.starts_with("--pubkey=")
        {
            // Passthrough filters — handled inside specific subcommands
            // (currently: timeline). Silently accepted by parser.
        } else if a.starts_with("--") || (a.starts_with('-') && a.len() > 1) {
            return Err(format!("unknown option '{a}'"));
        } else {
            // Only set command if not already set — allows diff to have positional args
            if cli.command.is_none() {
                cli.command = Some(a.clone());
            }
        }
    }
    Ok(cli)
}

fn effective_format(cli: &Cli) -> Format {
    if let Some(f) = cli.format {
        return f;
    }
    if cli.json_shorthand {
        return Format::Json;
    }
    Format::Text
}

fn effective_json_style(cli: &Cli) -> JsonStyle {
    if cli.compact {
        JsonStyle::Compact
    } else {
        JsonStyle::Pretty
    }
}

// ----------------------------------------------------------
// Entry point
// ----------------------------------------------------------

fn main() -> ExitCode {
    let raw: Vec<String> = std::env::args().skip(1).collect();

    let mut cli = match parse_args(&raw) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    // Snapshot defaults to JSON (its primary use is serialization for later diff)
    if cli.command.as_deref() == Some("snapshot") && cli.format.is_none() && !cli.json_shorthand {
        cli.format = Some(Format::Json);
    }

    // Collect positional (non-flag) arguments for commands that need them (e.g. diff)
    let positional: Vec<&str> = raw
        .iter()
        .filter(|a| !a.starts_with("--") && *a != "-h" && *a != "-V")
        .map(String::as_str)
        .collect();

    if cli.help {
        print!("{}", render_help());
        return ExitCode::SUCCESS;
    }
    if cli.version_flag {
        println!("{}", pulse_core::banner());
        return ExitCode::SUCCESS;
    }

    let command = cli.command.as_deref().unwrap_or("help");

    // Non-root warning banner (text mode only, so JSON stays clean)
    let json_mode = cli.json_shorthand || matches!(cli.format, Some(Format::Json));
    if !json_mode && !pulse_platform::is_root() && pulse_platform::command_needs_root(command) {
        eprintln!();
        eprintln!("⚠️  Running without root privileges.");
        eprintln!("    '{}' typically requires root for full data.", command);
        eprintln!("    Some entries may fail with 'Permission denied'.");
        eprintln!(
            "    Try: sudo pulse {}   or   tsu pulse {}",
            command, command
        );
        eprintln!();
    }

    let content: Result<String, String> = match command {
        "dashboard" | "dash" => match dashboard::run() {
            Ok(()) => Ok(String::new()),
            Err(e) => Err(e),
        },
        "help" => Ok(render_help()),
        "version" => Ok(format!("{}\n", pulse_core::banner())),
        "platform" => generate_platform(&cli).map_err(|e| e.to_string()),
        "formats" => Ok(render_formats()),
        "system" => generate_system(&cli).map_err(|e| e.to_string()),
        "cpu" => generate_cpu(&cli).map_err(|e| e.to_string()),
        "memory" => generate_memory(&cli).map_err(|e| e.to_string()),
        "disk" => generate_disk(&cli).map_err(|e| e.to_string()),
        "network" => generate_network(&cli).map_err(|e| e.to_string()),
        "process" => generate_process(&cli).map_err(|e| e.to_string()),
        "thermal" => generate_thermal(&cli).map_err(|e| e.to_string()),
        "gpu" => generate_gpu(&cli).map_err(|e| e.to_string()),
        "analyze" => generate_analyze(&cli).map_err(|e| e.to_string()),
        "mem-detail" | "memdetail" => generate_memory_detail(&cli).map_err(|e| e.to_string()),
        "load" => generate_load(&cli).map_err(|e| e.to_string()),
        "vmstat" => generate_vmstat(&cli).map_err(|e| e.to_string()),
        "cputimes" => generate_cpu_times(&cli).map_err(|e| e.to_string()),
        "users" => generate_users(&cli).map_err(|e| e.to_string()),
        "packages" => generate_packages(&cli).map_err(|e| e.to_string()),
        "services" => generate_services(&cli).map_err(|e| e.to_string()),
        "filesystem" | "fs" => generate_filesystem(&cli).map_err(|e| e.to_string()),
        "env" => generate_env(&cli).map_err(|e| e.to_string()),
        "usb" => generate_usb(&cli).map_err(|e| e.to_string()),
        "pci" => generate_pci(&cli).map_err(|e| e.to_string()),
        "battery" => generate_battery(&cli).map_err(|e| e.to_string()),
        "sensors" => generate_sensors(&cli).map_err(|e| e.to_string()),
        "drivers" => generate_drivers(&cli).map_err(|e| e.to_string()),
        "containers" => generate_containers(&cli).map_err(|e| e.to_string()),
        "vm" => generate_vm(&cli).map_err(|e| e.to_string()),
        "browsers" => generate_browsers(&cli).map_err(|e| e.to_string()),
        "crypto" => generate_crypto(&cli).map_err(|e| e.to_string()),
        "cron" => generate_cron(&cli).map_err(|e| e.to_string()),
        "hwid" => generate_hwid(&cli).map_err(|e| e.to_string()),
        "trust" => generate_trust(&cli),
        "hardening" => generate_hardening(&cli),
        "attack-surface" | "attack" => generate_attack_surface(&cli),
        "memory-audit" | "memory-forensics" => generate_memory_audit(&cli),
        "vulns" | "vulnerabilities" => generate_vulnerabilities(&cli),
        "snapshot" => generate_snapshot(&cli).map_err(|e| e.to_string()),
        "merkle-leaves" => capture_snapshot().map_err(|e| e.to_string()).map(|snap| {
            let mut out = String::new();
            for (label, hash) in snap.merkle_leaves_labeled() {
                out.push_str(&format!("{}\t{}\n", hex_of(&hash), label));
            }
            out
        }),
        "diff" => generate_diff(&cli, &positional).map_err(|e| e.to_string()),
        "anomaly" => generate_anomaly(&cli, &positional).map_err(|e| e.to_string()),
        "timeline" => generate_timeline(&cli, &positional).map_err(|e| e.to_string()),
        "all" => generate_all(&cli).map_err(|e| e.to_string()),
        "sign" => generate_sign(&cli, &positional),
        "verify" => generate_verify(&cli, &positional),
        other => {
            eprintln!("error: unknown command '{other}'");
            eprintln!("run 'pulse help' for usage");
            return ExitCode::from(2);
        }
    };

    let content = match content {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };

    let target = match &cli.output {
        Some(p) => Target::from_path(p),
        None => Target::Stdout,
    };

    if let Err(e) = target.write(&content) {
        // Silent on broken pipe (e.g. `pulse timeline | head`)
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            return ExitCode::SUCCESS;
        }
        eprintln!("error writing output: {e}");
        return ExitCode::from(1);
    }

    if target.is_file() {
        if let Some(p) = target.path() {
            eprintln!("wrote {} bytes to {}", content.len(), p.display());
        }
    }

    ExitCode::SUCCESS
}

// ----------------------------------------------------------
// Static renderers
// ----------------------------------------------------------

// ----------------------------------------------------------
// v1.7.1 SIGN / VERIFY
// ----------------------------------------------------------

fn extract_json_field(json: &str, field: &str) -> Result<String, String> {
    let pattern = format!("\"{}\"", field);
    let start = json
        .find(&pattern)
        .ok_or_else(|| format!("missing field: {field}"))?;
    let after = &json[start + pattern.len()..];
    let colon = after
        .find(':')
        .ok_or_else(|| format!("malformed field: {field}"))?;
    let rest = after[colon + 1..].trim_start();
    let rest = rest.trim_start_matches('"');
    let end = rest
        .find('"')
        .ok_or_else(|| format!("unterminated field: {field}"))?;
    Ok(rest[..end].to_string())
}

fn hex_of(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn generate_sign(cli: &Cli, positional: &[&str]) -> Result<String, String> {
    if positional.len() < 2 {
        return Err("usage: pulse sign <file>".into());
    }
    let file_path = positional[1];

    let data = std::fs::read(file_path).map_err(|e| format!("cannot read {file_path}: {e}"))?;
    let size = data.len();
    let hash = pulse_platform::sha256::sha256_hex(&data);

    let info = pulse_platform::hwid_info(None).map_err(|e| format!("cannot derive hwid: {e}"))?;
    let sk = pulse_core::sign::SigningKey::from_hwid(&info.hash)
        .map_err(|_| "invalid hwid format".to_string())?;
    let vk = sk.verifying_key();
    let sig = sk.sign(hash.as_bytes());

    let envelope = format!(
        "{{\n  \"version\": 1,\n  \"algorithm\": \"ed25519\",\n  \"file\": \"{}\",\n  \"size\": {},\n  \"sha256\": \"{}\",\n  \"public_key\": \"{}\",\n  \"signature\": \"{}\"\n}}\n",
        file_path, size, hash, vk.to_hex(), sig.to_hex()
    );

    let sig_path = format!("{file_path}.sig");
    std::fs::write(&sig_path, &envelope).map_err(|e| format!("cannot write {sig_path}: {e}"))?;

    Ok(match effective_format(cli) {
        Format::Json => envelope,
        _ => format!(
            "signed: {file_path}\nsig:    {sig_path}\npubkey: {}\nsha256: {hash}\n",
            vk.to_hex()
        ),
    })
}

fn generate_verify(cli: &Cli, positional: &[&str]) -> Result<String, String> {
    if positional.len() < 2 {
        return Err("usage: pulse verify <file> [--pubkey=<hex>]".into());
    }
    let file_path = positional[1];

    let data = std::fs::read(file_path).map_err(|e| format!("cannot read {file_path}: {e}"))?;
    let sig_path = format!("{file_path}.sig");
    let sig_data =
        std::fs::read_to_string(&sig_path).map_err(|e| format!("cannot read {sig_path}: {e}"))?;

    let expected_hash = extract_json_field(&sig_data, "sha256")?;
    let pubkey_hex = extract_json_field(&sig_data, "public_key")?;
    let sig_hex = extract_json_field(&sig_data, "signature")?;

    let actual_hash = pulse_platform::sha256::sha256_hex(&data);
    if actual_hash != expected_hash {
        return Ok(match effective_format(cli) {
            Format::Json => {
                "{\"valid\": false, \"reason\": \"file modified since signing\"}\n".into()
            }
            _ => format!(
                "INVALID: {file_path} modified since signing\n  expected sha256: {expected_hash}\n  actual   sha256: {actual_hash}\n"
            ),
        });
    }

    let vk = pulse_core::sign::VerifyingKey::from_hex(&pubkey_hex)
        .map_err(|_| "invalid public_key hex".to_string())?;
    let sig = pulse_core::sign::Signature::from_hex(&sig_hex)
        .map_err(|_| "invalid signature hex".to_string())?;

    let valid = vk.verify(expected_hash.as_bytes(), &sig);

    let raw_args: Vec<String> = std::env::args().collect();
    let mut expected_pubkey: Option<String> = None;
    for a in &raw_args {
        if let Some(v) = a.strip_prefix("--pubkey=") {
            expected_pubkey = Some(v.to_lowercase());
        }
    }
    if let Some(want) = expected_pubkey {
        if want != vk.to_hex().to_lowercase() {
            return Ok(match effective_format(cli) {
                Format::Json => {
                    "{\"valid\": false, \"reason\": \"pubkey mismatch\"}\n".into()
                }
                _ => format!(
                    "INVALID: public key does not match --pubkey\n  embedded: {}\n  expected: {want}\n",
                    vk.to_hex()
                ),
            });
        }
    }

    Ok(match effective_format(cli) {
        Format::Json => format!(
            "{{\"valid\": {valid}, \"file\": \"{file_path}\", \"sha256\": \"{expected_hash}\", \"pubkey\": \"{}\"}}\n",
            vk.to_hex()
        ),
        _ => {
            if valid {
                format!(
                    "VALID: {file_path}\n  sha256: {expected_hash}\n  pubkey: {}\n",
                    vk.to_hex()
                )
            } else {
                format!("INVALID: signature does not verify for {file_path}\n")
            }
        }
    })
}

fn render_help() -> String {
    format!(
        "{banner}\n{desc}\n\n\
USAGE:\n    pulse [OPTIONS] [COMMAND]\n\n\
COMMANDS:\n\
    version     Show version information\n\
    platform    Show platform/architecture info\n\
    system      Deep system info (OS, kernel, uptime)\n\
    cpu         CPU details (model, cores, freq, features)\n\
    memory      Memory info (RAM, swap, buffers)\n\
    disk        Filesystem/mount info with usage\n\
    network     Network interfaces\n\
    process     Running processes\n\
    thermal     Thermal zones with temperatures\n\
    gpu         GPU devices detected\n\
    analyze     Health analysis with findings\n\
    mem-detail  Memory in full detail (~35 fields)\n\
    load        Load average + task counters\n\
    vmstat      Kernel VM statistics\n\
    cputimes    Per-core CPU time breakdown\n\
    users       Local users and groups\n\
    packages    Installed packages\n\
    services    Service units\n\
    filesystem  Filesystem roots overview\n\
    env         Environment variables\n\
    usb         USB devices\n\
    pci         PCI devices\n\
    battery     Battery status\n\
    sensors     Hardware sensor chips (hwmon)\n\
    drivers     Loaded kernel modules\n\
    containers  Container runtime detection\n\
    vm          Virtualization detection\n\
    browsers    Installed browsers\n\
    crypto      SSL certs and SSH keys\n\
    cron        Scheduled tasks\n\
    hwid        Stable hardware identifier (SHA-256)\n\
    trust       Security trust score (0-100)\n\
    hardening   Kernel hardening audit with 22 checks\n\
    attack-surface  Enumerate attack surface (ports, SUID, keys)\n    memory-audit Fileless malware scanner (RWX + memfd + deleted)\n\\

    vulns       Configuration vulnerability scan\n\
    snapshot    Save full system state to JSON\n\
    diff        Compare two snapshots (file1 file2)\n\
    anomaly     Learn/check statistical baseline (learn|check)\n\
    timeline    Unified chronological event stream\n\
    sign        Sign a file with the device HWID key\n\
    verify      Verify a signed file (--pubkey=<hex> optional)\n\
    all         Run all modules, produce composite report\n\
    formats     List supported output formats\n\
    dashboard   Interactive TUI dashboard\n\
    help        Show this help message\n\n\
OPTIONS:\n\
    --format=<fmt>   Output format: text | json | markdown\n\
    --output=<path>  Write output to file instead of stdout\n\
    --json           Shorthand for --format=json\n\
    --compact        Compact JSON (no pretty-print)\n\
    --context=<str>  Context for private HWID\n\
    --verbose        Verbose output\n\
    -h, --help       Show this message\n\
    -V, --version    Show version\n",
        banner = pulse_core::banner(),
        desc = pulse_core::DESCRIPTION
    )
}

fn generate_platform(cli: &Cli) -> Result<String, pulse_platform::PlatformError> {
    let info = pulse_platform::platform_info()?;
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&info, effective_json_style(cli)),
        Format::Markdown => pulse_core::render::platform_markdown(&info),
        Format::Text => pulse_core::render::platform_text(&info),
    })
}

fn render_formats() -> String {
    "Supported formats:\n\
     \x20   text      Human-readable (default)\n\
     \x20   json      Machine-readable\n\
     \x20   markdown  Markdown tables\n"
        .to_string()
}

// ----------------------------------------------------------
// Data renderers (need format/style)
// ----------------------------------------------------------

fn generate_system(cli: &Cli) -> Result<String, pulse_platform::PlatformError> {
    let info = pulse_platform::system_info()?;
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&info, effective_json_style(cli)),
        Format::Markdown => pulse_core::render::system_markdown(&info),
        Format::Text => pulse_core::render::system_text(&info),
    })
}

fn generate_cpu(cli: &Cli) -> Result<String, pulse_platform::PlatformError> {
    let info = pulse_platform::cpu_info()?;
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&info, effective_json_style(cli)),
        Format::Markdown => pulse_core::render::cpu_markdown(&info),
        Format::Text => pulse_core::render::cpu_text(&info),
    })
}

fn generate_memory(cli: &Cli) -> Result<String, pulse_platform::PlatformError> {
    let info = pulse_platform::memory_info()?;
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&info, effective_json_style(cli)),
        Format::Markdown => pulse_core::render::memory_markdown(&info),
        Format::Text => pulse_core::render::memory_text(&info),
    })
}

fn generate_all(cli: &Cli) -> Result<String, pulse_platform::PlatformError> {
    let report = pulse_core::build_full_report()?;
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&report, effective_json_style(cli)),
        Format::Markdown => report.render_markdown(),
        Format::Text => report.render_text(),
    })
}

// ----------------------------------------------------------
// Phase 4 renderers
// ----------------------------------------------------------

fn generate_disk(cli: &Cli) -> Result<String, pulse_platform::PlatformError> {
    let info = pulse_platform::disk_info()?;
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&info, effective_json_style(cli)),
        Format::Markdown => pulse_core::render::disk_markdown(&info),
        Format::Text => pulse_core::render::disk_text(&info),
    })
}

fn generate_network(cli: &Cli) -> Result<String, pulse_platform::PlatformError> {
    let info = pulse_platform::network_info()?;
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&info, effective_json_style(cli)),
        Format::Markdown => pulse_core::render::network_markdown(&info),
        Format::Text => pulse_core::render::network_text(&info),
    })
}

fn generate_process(cli: &Cli) -> Result<String, pulse_platform::PlatformError> {
    let info = pulse_platform::process_info()?;
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&info, effective_json_style(cli)),
        Format::Markdown => pulse_core::render::process_markdown(&info),
        Format::Text => pulse_core::render::process_text(&info),
    })
}

// ----------------------------------------------------------
// Phase 5 renderers
// ----------------------------------------------------------

fn generate_thermal(cli: &Cli) -> Result<String, pulse_platform::PlatformError> {
    let info = pulse_platform::thermal_info()?;
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&info, effective_json_style(cli)),
        Format::Markdown => pulse_core::render::thermal_markdown(&info),
        Format::Text => pulse_core::render::thermal_text(&info),
    })
}

fn generate_gpu(cli: &Cli) -> Result<String, pulse_platform::PlatformError> {
    let info = pulse_platform::gpu_info()?;
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&info, effective_json_style(cli)),
        Format::Markdown => pulse_core::render::gpu_markdown(&info),
        Format::Text => pulse_core::render::gpu_text(&info),
    })
}

fn generate_analyze(cli: &Cli) -> Result<String, pulse_platform::PlatformError> {
    let cpu = pulse_platform::cpu_info()?;
    let mem = pulse_platform::memory_info()?;
    let thermal =
        pulse_platform::thermal_info().unwrap_or(pulse_platform::ThermalInfo { zones: vec![] });
    let report = pulse_core::build_analysis(&cpu, &mem, &thermal);
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&report, effective_json_style(cli)),
        Format::Markdown => report.render_markdown(),
        Format::Text => report.render_text(),
    })
}

// ----------------------------------------------------------
// Phase 7 renderers
// ----------------------------------------------------------

fn generate_memory_detail(cli: &Cli) -> Result<String, pulse_platform::PlatformError> {
    let info = pulse_platform::memory_detail()?;
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&info, effective_json_style(cli)),
        Format::Markdown => pulse_core::render::memory_detail_markdown(&info),
        Format::Text => pulse_core::render::memory_detail_text(&info),
    })
}

fn generate_load(cli: &Cli) -> Result<String, pulse_platform::PlatformError> {
    let info = pulse_platform::load_avg()?;
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&info, effective_json_style(cli)),
        Format::Markdown => pulse_core::render::load_markdown(&info),
        Format::Text => pulse_core::render::load_text(&info),
    })
}

fn generate_vmstat(cli: &Cli) -> Result<String, pulse_platform::PlatformError> {
    let info = pulse_platform::vmstat()?;
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&info, effective_json_style(cli)),
        Format::Markdown => pulse_core::render::vmstat_markdown(&info),
        Format::Text => pulse_core::render::vmstat_text(&info),
    })
}

fn generate_cpu_times(cli: &Cli) -> Result<String, pulse_platform::PlatformError> {
    let info = pulse_platform::cpu_times()?;
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&info, effective_json_style(cli)),
        Format::Markdown => pulse_core::render::cpu_times_markdown(&info),
        Format::Text => pulse_core::render::cpu_times_text(&info),
    })
}

// ----------------------------------------------------------
// Phase 8 renderers
// ----------------------------------------------------------

fn generate_users(cli: &Cli) -> Result<String, pulse_platform::PlatformError> {
    let info = pulse_platform::users_info()?;
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&info, effective_json_style(cli)),
        Format::Markdown => pulse_core::render::users_markdown(&info),
        Format::Text => pulse_core::render::users_text(&info),
    })
}

fn generate_packages(cli: &Cli) -> Result<String, pulse_platform::PlatformError> {
    let info = pulse_platform::packages_info()?;
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&info, effective_json_style(cli)),
        Format::Markdown => pulse_core::render::packages_markdown(&info),
        Format::Text => pulse_core::render::packages_text(&info),
    })
}

fn generate_services(cli: &Cli) -> Result<String, pulse_platform::PlatformError> {
    let info = pulse_platform::services_info()?;
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&info, effective_json_style(cli)),
        Format::Markdown => pulse_core::render::services_markdown(&info),
        Format::Text => pulse_core::render::services_text(&info),
    })
}

fn generate_filesystem(cli: &Cli) -> Result<String, pulse_platform::PlatformError> {
    let info = pulse_platform::filesystem_info()?;
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&info, effective_json_style(cli)),
        Format::Markdown => pulse_core::render::fs_markdown(&info),
        Format::Text => pulse_core::render::fs_text(&info),
    })
}

fn generate_env(cli: &Cli) -> Result<String, pulse_platform::PlatformError> {
    let info = pulse_platform::env_info()?;
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&info, effective_json_style(cli)),
        Format::Markdown => pulse_core::render::env_markdown(&info),
        Format::Text => pulse_core::render::env_text(&info),
    })
}

// ----------------------------------------------------------
// Phase 9 renderers
// ----------------------------------------------------------

fn generate_usb(cli: &Cli) -> Result<String, pulse_platform::PlatformError> {
    let info = pulse_platform::usb_info()?;
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&info, effective_json_style(cli)),
        Format::Markdown => pulse_core::render::usb_markdown(&info),
        Format::Text => pulse_core::render::usb_text(&info),
    })
}

fn generate_pci(cli: &Cli) -> Result<String, pulse_platform::PlatformError> {
    let info = pulse_platform::pci_info()?;
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&info, effective_json_style(cli)),
        Format::Markdown => pulse_core::render::pci_markdown(&info),
        Format::Text => pulse_core::render::pci_text(&info),
    })
}

fn generate_battery(cli: &Cli) -> Result<String, pulse_platform::PlatformError> {
    let info = pulse_platform::battery_info()?;
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&info, effective_json_style(cli)),
        Format::Markdown => pulse_core::render::battery_markdown(&info),
        Format::Text => pulse_core::render::battery_text(&info),
    })
}

fn generate_sensors(cli: &Cli) -> Result<String, pulse_platform::PlatformError> {
    let info = pulse_platform::sensors_info()?;
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&info, effective_json_style(cli)),
        Format::Markdown => pulse_core::render::sensors_markdown(&info),
        Format::Text => pulse_core::render::sensors_text(&info),
    })
}

fn generate_drivers(cli: &Cli) -> Result<String, pulse_platform::PlatformError> {
    let info = pulse_platform::drivers_info()?;
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&info, effective_json_style(cli)),
        Format::Markdown => pulse_core::render::drivers_markdown(&info),
        Format::Text => pulse_core::render::drivers_text(&info),
    })
}

// ----------------------------------------------------------
// Phase 10 renderers
// ----------------------------------------------------------

fn generate_containers(cli: &Cli) -> Result<String, pulse_platform::PlatformError> {
    let info = pulse_platform::containers_info()?;
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&info, effective_json_style(cli)),
        Format::Markdown => pulse_core::render::containers_markdown(&info),
        Format::Text => pulse_core::render::containers_text(&info),
    })
}

fn generate_vm(cli: &Cli) -> Result<String, pulse_platform::PlatformError> {
    let info = pulse_platform::vm_info()?;
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&info, effective_json_style(cli)),
        Format::Markdown => pulse_core::render::vm_markdown(&info),
        Format::Text => pulse_core::render::vm_text(&info),
    })
}

fn generate_browsers(cli: &Cli) -> Result<String, pulse_platform::PlatformError> {
    let info = pulse_platform::browsers_info()?;
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&info, effective_json_style(cli)),
        Format::Markdown => pulse_core::render::browsers_markdown(&info),
        Format::Text => pulse_core::render::browsers_text(&info),
    })
}

fn generate_crypto(cli: &Cli) -> Result<String, pulse_platform::PlatformError> {
    let info = pulse_platform::crypto_info()?;
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&info, effective_json_style(cli)),
        Format::Markdown => pulse_core::render::crypto_markdown(&info),
        Format::Text => pulse_core::render::crypto_text(&info),
    })
}

fn generate_cron(cli: &Cli) -> Result<String, pulse_platform::PlatformError> {
    let info = pulse_platform::cron_info()?;
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&info, effective_json_style(cli)),
        Format::Markdown => pulse_core::render::cron_markdown(&info),
        Format::Text => pulse_core::render::cron_text(&info),
    })
}

// ----------------------------------------------------------
// v1.1.0 HWID
// ----------------------------------------------------------

fn generate_hardening(cli: &Cli) -> Result<String, String> {
    let report = pulse_core::HardeningReport::collect();
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&report, effective_json_style(cli)),
        Format::Markdown => report.render_markdown(),
        Format::Text => report.render_text(),
    })
}

fn generate_attack_surface(cli: &Cli) -> Result<String, String> {
    let surface = pulse_core::AttackSurface::collect();
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&surface, effective_json_style(cli)),
        Format::Markdown => surface.render_markdown(),
        Format::Text => surface.render_text(),
    })
}

fn generate_memory_audit(cli: &Cli) -> Result<String, String> {
    let report = pulse_core::MemoryForensicReport::collect();
    let show_all = cli.verbose;
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&report, effective_json_style(cli)),
        Format::Markdown => report.render_markdown_with(show_all),
        Format::Text => report.render_text_with(show_all),
    })
}

fn generate_vulnerabilities(cli: &Cli) -> Result<String, String> {
    let report = pulse_core::VulnerabilityReport::collect();
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&report, effective_json_style(cli)),
        Format::Markdown => report.render_markdown(),
        Format::Text => report.render_text(),
    })
}

fn generate_hwid(cli: &Cli) -> Result<String, pulse_platform::PlatformError> {
    let info = pulse_platform::hwid_info(cli.context.as_deref())?;
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&info, effective_json_style(cli)),
        Format::Markdown => pulse_core::render::hwid_markdown(&info, cli.verbose),
        Format::Text => pulse_core::render::hwid_text(&info, cli.verbose),
    })
}

// ----------------------------------------------------------
// v1.2.0 TRUST
// ----------------------------------------------------------

fn generate_trust(cli: &Cli) -> Result<String, String> {
    let report = pulse_core::build_trust_report();
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&report, effective_json_style(cli)),
        Format::Markdown => report.render_markdown(),
        Format::Text => report.render_text(),
    })
}

// ----------------------------------------------------------
// v1.3.0 SNAPSHOT + DIFF
// ----------------------------------------------------------

fn capture_snapshot() -> Result<pulse_core::Snapshot, pulse_platform::PlatformError> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let system = pulse_platform::system_info()?;
    let hostname = system.hostname.clone();

    let mut snap = pulse_core::Snapshot {
        version: pulse_core::VERSION.to_string(),
        timestamp,
        hostname,
        system,
        cpu: pulse_platform::cpu_info()?,
        memory: pulse_platform::memory_info()?,
        users: pulse_platform::users_info()?,
        processes: pulse_platform::process_info()?.processes,
        modules: pulse_platform::drivers_info()?.modules,
        network: pulse_platform::network_info()?,
        cron: pulse_platform::cron_info()?,
        env: pulse_platform::env_info()?,
        merkle_root: String::new(),
    };
    snap.merkle_root = snap.merkle_root_hex();
    Ok(snap)
}

fn generate_snapshot(cli: &Cli) -> Result<String, pulse_platform::PlatformError> {
    let snap = capture_snapshot()?;
    match effective_format(cli) {
        Format::Json => {
            let s = serde_json::to_string_pretty(&snap)
                .map_err(|e| pulse_platform::PlatformError::parse("json", e.to_string()))?;
            Ok(s)
        }
        Format::Markdown => Ok(format!(
            "# Snapshot\n\n```\n{}\n```\n",
            snap.render_summary()
        )),
        Format::Text => Ok(snap.render_summary()),
    }
}

fn generate_diff(cli: &Cli, positional: &[&str]) -> Result<String, pulse_platform::PlatformError> {
    if positional.len() < 3 {
        return Err(pulse_platform::PlatformError::parse(
            "diff",
            "usage: pulse diff <old.json> <new.json>",
        ));
    }
    let old_path = positional[1];
    let new_path = positional[2];

    let old_data = std::fs::read_to_string(old_path)
        .map_err(|e| pulse_platform::PlatformError::io(old_path, e))?;
    let new_data = std::fs::read_to_string(new_path)
        .map_err(|e| pulse_platform::PlatformError::io(new_path, e))?;

    let old_snap: pulse_core::Snapshot = serde_json::from_str(&old_data)
        .map_err(|e| pulse_platform::PlatformError::parse(old_path, e.to_string()))?;
    let new_snap: pulse_core::Snapshot = serde_json::from_str(&new_data)
        .map_err(|e| pulse_platform::PlatformError::parse(new_path, e.to_string()))?;

    let report = pulse_core::diff(&old_snap, &new_snap);
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&report, effective_json_style(cli)),
        Format::Markdown => report.render_markdown(),
        Format::Text => report.render_text(),
    })
}

// ----------------------------------------------------------
// v1.4.0 ANOMALY
// ----------------------------------------------------------

fn baseline_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let mut p = std::path::PathBuf::from(home);
    p.push(".config");
    p.push("pulse");
    std::fs::create_dir_all(&p).ok();
    p.push("baseline.json");
    p
}

fn generate_anomaly(
    cli: &Cli,
    positional: &[&str],
) -> Result<String, pulse_platform::PlatformError> {
    let sub = positional.get(1).copied().unwrap_or("help");
    match sub {
        "learn" => {
            let samples: u32 = 10;
            let delay_ms: u64 = 500;
            eprintln!("Learning baseline: {} samples, {}ms apart...", samples, delay_ms);
            let baseline = pulse_core::build_baseline(samples, delay_ms);
            let json = serde_json::to_string_pretty(&baseline)
                .map_err(|e| pulse_platform::PlatformError::parse("json", e.to_string()))?;
            let path = baseline_path();
            std::fs::write(&path, &json)
                .map_err(|e| pulse_platform::PlatformError::io(path.display().to_string(), e))?;
            Ok(format!(
                "Baseline saved to {}\n  samples : {}\n  metrics : {}\n  version : {}\n",
                path.display(), baseline.samples, baseline.metrics.len(), baseline.version))
        }
        "check" => {
            let path = baseline_path();
            let data = std::fs::read_to_string(&path)
                .map_err(|e| pulse_platform::PlatformError::io(path.display().to_string(), e))?;
            let baseline: pulse_core::Baseline = serde_json::from_str(&data)
                .map_err(|e| pulse_platform::PlatformError::parse(path.display().to_string(), e.to_string()))?;
            let report = pulse_core::check_anomalies(&baseline);
            Ok(match effective_format(cli) {
                Format::Json => pulse_core::render::to_json(&report, effective_json_style(cli)),
                Format::Markdown => report.render_markdown(),
                Format::Text => report.render_text(),
            })
        }
        _ => Ok("Usage:\n  pulse anomaly learn   — build baseline (10 samples)\n  pulse anomaly check   — compare against baseline\n".into()),
    }
}

// ----------------------------------------------------------
// v1.5.0 TIMELINE
// ----------------------------------------------------------

fn generate_timeline(
    cli: &Cli,
    positional: &[&str],
) -> Result<String, pulse_platform::PlatformError> {
    // Parse optional filters from raw args
    let mut since_filter: Option<u64> = None;
    let mut source_filter: Option<String> = None;
    let _ = positional;

    let raw: Vec<String> = std::env::args().collect();
    for a in &raw {
        if let Some(v) = a.strip_prefix("--since=") {
            if let Some(secs) = parse_duration(v) {
                since_filter = Some(secs);
            }
        } else if let Some(v) = a.strip_prefix("--source=") {
            source_filter = Some(v.to_string());
        }
    }

    let report = pulse_core::build_timeline(since_filter, source_filter.as_deref());
    Ok(match effective_format(cli) {
        Format::Json => pulse_core::render::to_json(&report, effective_json_style(cli)),
        Format::Markdown => report.render_markdown(),
        Format::Text => report.render_text(),
    })
}

fn parse_duration(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(v) = s.strip_suffix('s') {
        return v.parse::<u64>().ok();
    }
    if let Some(v) = s.strip_suffix('m') {
        return v.parse::<u64>().ok().map(|x| x * 60);
    }
    if let Some(v) = s.strip_suffix('h') {
        return v.parse::<u64>().ok().map(|x| x * 3600);
    }
    if let Some(v) = s.strip_suffix('d') {
        return v.parse::<u64>().ok().map(|x| x * 86400);
    }
    s.parse::<u64>().ok()
}
