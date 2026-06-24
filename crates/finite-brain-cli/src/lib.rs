//! Agent-native FiniteBrain CLI surface.

use std::collections::BTreeSet;
use std::env;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use finite_brain_core::portability::{
    VaultDirectoryManifest, VaultDirectoryPath, VaultDirectoryPortability,
    VaultDirectoryVaultSummary, VaultWorkingTreeStateManifest, WorkingTreeFolderRoot,
    WorkingTreeObjectManifestEntry, WorkingTreeSyncState,
};
use finite_brain_core::{
    AdminAccessAction, AdminAccessChangePayload, AdminAccessChangeValidation, FolderId, FolderKey,
    SafeRelativePath, VaultId, sha256_hex,
};
use finite_nostr::{NostrPublicKey, build_rumor, decrypt_nip44, encrypt_nip44, wrap_rumor};
use nostr::event::FinalizeEvent;
use nostr::{EventBuilder, Keys, Kind, Tag, Timestamp};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const AUTH_VERSION: &str = "finitebrain-agent-auth-v1";
const AGENT_STATE_VERSION: &str = "finitebrain-agent-state-v1";
const VAULT_DIRECTORY_VERSION: &str = "finite-vault-directory-v1";
const WORKING_TREE_STATE_VERSION: &str = "finite-vault-working-tree-state-v1";
const APP_SPECIFIC_KIND: u16 = 30_078;

/// Process-level environment for the CLI.
#[derive(Debug, Clone)]
pub struct CliEnvironment {
    pub cwd: PathBuf,
    pub config_dir: PathBuf,
    pub now: Option<String>,
}

impl CliEnvironment {
    /// Build a CLI environment from process env vars.
    pub fn from_process() -> Self {
        let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let config_dir = env::var_os("FBRAIN_CONFIG_DIR")
            .map(PathBuf::from)
            .or_else(|| {
                env::var_os("HOME").map(|home| PathBuf::from(home).join(".finitebrain/fbrain"))
            })
            .unwrap_or_else(|| cwd.join(".fbrain"));
        let now = env::var("FBRAIN_NOW").ok();
        Self {
            cwd,
            config_dir,
            now,
        }
    }
}

/// CLI error.
#[derive(Debug)]
pub enum CliError {
    Io(std::io::Error),
    Json(serde_json::Error),
    InvalidCommand(String),
    InvalidSigner(String),
    InvalidInput(String),
    Http(String),
    MissingAuth,
    MissingServer,
    MissingWorkingTree,
    MissingArgument(&'static str),
    NotFound(String),
    Unsupported(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::Json(error) => write!(f, "{error}"),
            Self::InvalidCommand(command) => write!(f, "unknown command: {command}"),
            Self::InvalidSigner(reason) => write!(f, "invalid local signer: {reason}"),
            Self::InvalidInput(reason) => write!(f, "invalid input: {reason}"),
            Self::Http(reason) => write!(f, "http request failed: {reason}"),
            Self::MissingAuth => write!(f, "no local signer configured"),
            Self::MissingServer => write!(f, "no FiniteBrain server URL configured"),
            Self::MissingWorkingTree => write!(f, "no Vault Working Tree found"),
            Self::MissingArgument(argument) => write!(f, "missing required argument: {argument}"),
            Self::NotFound(item) => write!(f, "not found: {item}"),
            Self::Unsupported(reason) => write!(f, "unsupported: {reason}"),
        }
    }
}

impl Error for CliError {}

impl From<std::io::Error> for CliError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for CliError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

/// Run `fbrain` using process args and stdout.
pub fn run_from_process(env: CliEnvironment) -> Result<(), CliError> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let mut stdout = std::io::stdout();
    run_with_env(args, env, &mut stdout)
}

/// Run `fbrain` with injected args and output. Tests use this public seam.
pub fn run_with_env<I, S, W>(args: I, env: CliEnvironment, output: &mut W) -> Result<(), CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
    W: Write,
{
    let mut args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    let json = take_flag(&mut args, "--json");
    let command = args.first().cloned().unwrap_or_else(|| "help".to_owned());
    match command.as_str() {
        "help" | "--help" | "-h" => help(output),
        "doctor" => doctor(&args[1..], &env, json, output),
        "auth" => auth(&args[1..], &env, json, output),
        "signer" => signer(&args[1..], &env, json, output),
        "daemon" => daemon(&args[1..], &env, json, output),
        "sync" => sync(&args[1..], &env, json, output),
        "open" => open_vault(&args[1..], &env, json, output),
        "status" => status(&env, json, output),
        "unlock" => unlock(&args[1..], &env, json, output),
        "conflicts" => conflicts(&env, json, output),
        "resolve" => resolve(&args[1..], &env, json, output),
        "activity" => activity(&env, json, output),
        "access" => access(&args[1..], &env, json, output),
        "vault" => vault(&args[1..], &env, json, output),
        "folder" => folder(&args[1..], &env, json, output),
        "permissions" | "permission" | "perms" => permissions(&args[1..], &env, json, output),
        "invites" | "invite" => invites(&args[1..], &env, json, output),
        "share" | "shared" => share(&args[1..], &env, json, output),
        other => Err(CliError::InvalidCommand(other.to_owned())),
    }
}

fn help<W: Write>(output: &mut W) -> Result<(), CliError> {
    writeln!(
        output,
        "fbrain doctor\nauth status|login|logout\nsigner status|public-key|sign|encrypt|decrypt\ndaemon status|start|stop|logs|tick\nsync status|now\nopen <vault-id> [path]\nstatus [--json]\nunlock [folder|--all]\nconflicts\nresolve <id>\nactivity\naccess explain <folder>\nvault create|metadata|export\nfolder create\npermissions add-member|remove-member|add-admin|remove-admin|grant-folder\ninvites create|show|accept|revoke\nshare link|accept|revoke|source|folder-invite|folder-accept"
    )?;
    Ok(())
}

fn doctor<W: Write>(
    args: &[String],
    env: &CliEnvironment,
    json: bool,
    output: &mut W,
) -> Result<(), CliError> {
    let server_url = option_value(args, "--server")
        .or_else(|| {
            find_agent_state(&env.cwd)
                .ok()
                .flatten()
                .and_then(|root| read_agent_state(&root).ok())
                .and_then(|state| state.server_url)
        })
        .or_else(|| std::env::var("FINITE_BRAIN_PUBLIC_BASE_URL").ok());
    let working_tree = find_agent_state(&env.cwd).ok().flatten();
    let auth = read_auth_optional(env)?;
    let daemon_state = working_tree
        .as_ref()
        .and_then(|root| read_agent_state(root).ok())
        .map(|state| state.daemon.state)
        .unwrap_or(DaemonRunState::Missing);
    let server = server_url
        .as_deref()
        .map(check_http_health)
        .unwrap_or_else(|| HealthCheck::skipped("no server URL configured"));
    let report = DoctorReport {
        cli: CheckState::ok("fbrain CLI is available"),
        auth: auth
            .as_ref()
            .map(|auth| CheckState::ok(format!("acting npub {}", auth.npub)))
            .unwrap_or_else(|| CheckState::warn("no local signer configured")),
        working_tree: working_tree
            .as_ref()
            .map(|root| CheckState::ok(format!("Vault Working Tree at {}", root.display())))
            .unwrap_or_else(|| CheckState::warn("not inside a Vault Working Tree")),
        daemon: match daemon_state {
            DaemonRunState::Running => CheckState::ok("daemon marked running"),
            DaemonRunState::Stopped => CheckState::warn("daemon marked stopped"),
            DaemonRunState::Missing => CheckState::warn("daemon state missing"),
        },
        server,
    };
    if json {
        write_json(output, &report)
    } else {
        writeln!(output, "fbrain doctor")?;
        writeln!(output, "- cli: {}", report.cli.message)?;
        writeln!(output, "- auth: {}", report.auth.message)?;
        writeln!(output, "- working tree: {}", report.working_tree.message)?;
        writeln!(output, "- daemon: {}", report.daemon.message)?;
        writeln!(output, "- server: {}", report.server.message)?;
        Ok(())
    }
}

fn auth<W: Write>(
    args: &[String],
    env: &CliEnvironment,
    json: bool,
    output: &mut W,
) -> Result<(), CliError> {
    match args.first().map(String::as_str).unwrap_or("status") {
        "status" => {
            let status = auth_status(env)?;
            if json {
                write_json(output, &status)
            } else {
                match status.state.as_str() {
                    "authenticated" => writeln!(
                        output,
                        "authenticated as {} ({})",
                        status.npub.as_deref().unwrap_or("-"),
                        status.signer
                    )?,
                    _ => writeln!(output, "not authenticated")?,
                }
                Ok(())
            }
        }
        "login" => {
            let nsec = option_value(args, "--nsec")
                .or_else(|| args.get(1).cloned())
                .ok_or(CliError::MissingArgument("--nsec"))?;
            let auth = PrototypeAuth::from_nsec(&nsec, timestamp(env))?;
            write_auth(env, &auth)?;
            let status = auth_status(env)?;
            if json {
                write_json(output, &status)
            } else {
                writeln!(
                    output,
                    "authenticated as {}",
                    status.npub.unwrap_or_default()
                )?;
                Ok(())
            }
        }
        "logout" => {
            let path = auth_path(env);
            if path.exists() {
                fs::remove_file(path)?;
            }
            if json {
                write_json(output, &serde_json::json!({ "state": "logged_out" }))
            } else {
                writeln!(output, "logged out")?;
                Ok(())
            }
        }
        other => Err(CliError::InvalidCommand(format!("auth {other}"))),
    }
}

fn signer<W: Write>(
    args: &[String],
    env: &CliEnvironment,
    json: bool,
    output: &mut W,
) -> Result<(), CliError> {
    match args.first().map(String::as_str).unwrap_or("status") {
        "status" => auth(&["status".to_owned()], env, json, output),
        "public-key" | "get-public-key" => {
            let auth = read_auth_required(env)?;
            if json {
                write_json(output, &serde_json::json!({ "npub": auth.npub }))
            } else {
                writeln!(output, "{}", auth.npub)?;
                Ok(())
            }
        }
        "sign" | "sign-event" => {
            let keys = signer_keys(env)?;
            let kind = option_value(args, "--kind")
                .as_deref()
                .map(parse_kind)
                .transpose()?
                .unwrap_or(Kind::TextNote);
            let content = option_value(args, "--content")
                .or_else(|| positional_values(args).get(1).cloned())
                .unwrap_or_default();
            let tags = option_values(args, "--tag")
                .into_iter()
                .map(parse_cli_tag)
                .collect::<Result<Vec<_>, _>>()?;
            let event = sign_event(&keys, kind, content, tags, unix_timestamp(), None)?;
            if json {
                write_json(
                    output,
                    &serde_json::json!({
                        "event": event,
                        "eventJson": event.as_json()
                    }),
                )
            } else {
                writeln!(output, "{}", event.as_json())?;
                Ok(())
            }
        }
        "encrypt" => {
            let keys = signer_keys(env)?;
            let recipient = option_value(args, "--to").ok_or(CliError::MissingArgument("--to"))?;
            let plaintext = option_value(args, "--text")
                .or_else(|| positional_values(args).get(1).cloned())
                .ok_or(CliError::MissingArgument("--text"))?;
            let recipient = NostrPublicKey::parse(&recipient)
                .map_err(|error| CliError::InvalidSigner(error.to_string()))?;
            let ciphertext = encrypt_nip44(keys.secret_key(), recipient, plaintext)
                .map_err(|error| CliError::InvalidSigner(error.to_string()))?;
            if json {
                write_json(output, &serde_json::json!({ "ciphertext": ciphertext }))
            } else {
                writeln!(output, "{ciphertext}")?;
                Ok(())
            }
        }
        "decrypt" => {
            let keys = signer_keys(env)?;
            let sender = option_value(args, "--from").ok_or(CliError::MissingArgument("--from"))?;
            let payload = option_value(args, "--payload")
                .or_else(|| positional_values(args).get(1).cloned())
                .ok_or(CliError::MissingArgument("--payload"))?;
            let sender = NostrPublicKey::parse(&sender)
                .map_err(|error| CliError::InvalidSigner(error.to_string()))?;
            let plaintext = decrypt_nip44(keys.secret_key(), sender, payload)
                .map_err(|error| CliError::InvalidSigner(error.to_string()))?;
            if json {
                write_json(output, &serde_json::json!({ "plaintext": plaintext }))
            } else {
                writeln!(output, "{plaintext}")?;
                Ok(())
            }
        }
        other => Err(CliError::InvalidCommand(format!("signer {other}"))),
    }
}

fn daemon<W: Write>(
    args: &[String],
    env: &CliEnvironment,
    json: bool,
    output: &mut W,
) -> Result<(), CliError> {
    match args.first().map(String::as_str).unwrap_or("status") {
        "status" => {
            let report = daemon_status(env)?;
            if json {
                write_json(output, &report)
            } else {
                writeln!(output, "daemon {}", report.state)?;
                Ok(())
            }
        }
        "start" => {
            let sync_result = sync_once(env, "daemon.start");
            mutate_agent_state(env, |state, now| {
                state.daemon.state = DaemonRunState::Running;
                state.daemon.last_started_at = Some(now.clone());
                state.sync.status = sync_result
                    .as_ref()
                    .map(|report| report.status.clone())
                    .unwrap_or_else(|error| format!("blocked: {error}"));
                state.add_activity(now, "daemon.started", "Agent Sync Daemon marked running");
                Ok(())
            })?;
            daemon(&["status".to_owned()], env, json, output)
        }
        "stop" => {
            mutate_agent_state(env, |state, now| {
                state.daemon.state = DaemonRunState::Stopped;
                state.sync.status = "paused".to_owned();
                state.add_activity(now, "daemon.stopped", "Agent Sync Daemon marked stopped");
                Ok(())
            })?;
            daemon(&["status".to_owned()], env, json, output)
        }
        "logs" => {
            let state = load_current_agent_state(env)?;
            let rows = state
                .activity
                .into_iter()
                .filter(|entry| entry.kind.starts_with("daemon."))
                .collect::<Vec<_>>();
            if json {
                write_json(output, &rows)
            } else {
                write_activity_rows(output, &rows)
            }
        }
        "tick" => {
            let report = sync_once(env, "daemon.tick")?;
            if json {
                write_json(output, &report)
            } else {
                writeln!(
                    output,
                    "{} latestSequence={}",
                    report.status, report.latest_sequence
                )?;
                Ok(())
            }
        }
        other => Err(CliError::InvalidCommand(format!("daemon {other}"))),
    }
}

fn sync<W: Write>(
    args: &[String],
    env: &CliEnvironment,
    json: bool,
    output: &mut W,
) -> Result<(), CliError> {
    match args.first().map(String::as_str).unwrap_or("status") {
        "status" => {
            let report = status_report(env)?;
            if json {
                write_json(output, &report.sync)
            } else {
                writeln!(
                    output,
                    "{} ({}) latestSequence={}",
                    report.sync.mode, report.sync.status, report.sync.latest_sequence
                )?;
                Ok(())
            }
        }
        "now" => {
            let report = sync_once(env, "sync.now")?;
            if json {
                write_json(output, &report)
            } else {
                writeln!(
                    output,
                    "{} latestSequence={}",
                    report.status, report.latest_sequence
                )?;
                Ok(())
            }
        }
        other => Err(CliError::InvalidCommand(format!("sync {other}"))),
    }
}

fn open_vault<W: Write>(
    args: &[String],
    env: &CliEnvironment,
    json: bool,
    output: &mut W,
) -> Result<(), CliError> {
    let vault_id = args.first().ok_or(CliError::MissingArgument("vault-id"))?;
    let path = positional_values(args)
        .get(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| env.cwd.join(vault_id));
    let server_url = option_value(args, "--server");
    fs::create_dir_all(path.join(".finitebrain/encrypted-sync"))?;
    let now = timestamp(env);
    let auth = read_auth_optional(env)?;
    let directory = VaultDirectoryManifest {
        version: VAULT_DIRECTORY_VERSION.to_owned(),
        vault: VaultDirectoryVaultSummary {
            id: vault_id.to_owned(),
            kind: "unknown".to_owned(),
            name: vault_id.to_owned(),
            owner_npub: auth.as_ref().map(|auth| auth.npub.clone()),
        },
        working_tree: VaultDirectoryPath {
            path: ".".to_owned(),
        },
        encrypted_sync: VaultDirectoryPath {
            path: ".finitebrain/encrypted-sync".to_owned(),
        },
        portability: VaultDirectoryPortability {
            owned_by_agent_runtime: true,
            owned_by_app_surface: false,
        },
        created_at: now.clone(),
        updated_at: now.clone(),
    };
    let tree_state = VaultWorkingTreeStateManifest {
        version: WORKING_TREE_STATE_VERSION.to_owned(),
        folder_roots: Vec::<WorkingTreeFolderRoot>::new(),
        objects: Vec::<WorkingTreeObjectManifestEntry>::new(),
        sync: WorkingTreeSyncState { latest_sequence: 0 },
    };
    write_json_file(&path.join(".finitebrain/vault-directory.json"), &directory)?;
    write_json_file(
        &path.join(".finitebrain/working-tree-state.json"),
        &tree_state,
    )?;

    let mut state = AgentState::new(vault_id, &now);
    state.server_url = server_url;
    state.daemon.state = DaemonRunState::Running;
    state.daemon.last_started_at = Some(now.clone());
    state.auth_npub = auth.map(|auth| auth.npub);
    state.add_activity(
        now,
        "working_tree.opened",
        "Vault Working Tree opened for agent use",
    );
    write_agent_state(&path, &state)?;
    let mut opened_env = env.clone();
    opened_env.cwd = path.clone();
    let sync_status = match sync_once(&opened_env, "working_tree.opened.sync") {
        Ok(report) => report.status,
        Err(error) => {
            let mut state = read_agent_state(&path)?;
            let now = timestamp(env);
            state.sync.status = format!("blocked: {error}");
            state.add_activity(
                now,
                "sync.blocked",
                format!("Automatic sync blocked: {error}"),
            );
            write_agent_state(&path, &state)?;
            format!("blocked: {error}")
        }
    };

    if json {
        write_json(
            output,
            &serde_json::json!({
                "vaultId": vault_id,
                "path": path,
                "daemon": "running",
                "syncMode": "automatic",
                "syncStatus": sync_status
            }),
        )
    } else {
        writeln!(output, "opened Vault Working Tree {}", path.display())?;
        Ok(())
    }
}

fn status<W: Write>(env: &CliEnvironment, json: bool, output: &mut W) -> Result<(), CliError> {
    let report = status_report(env)?;
    if json {
        write_json(output, &report)
    } else {
        writeln!(
            output,
            "Vault: {}",
            report.vault_id.as_deref().unwrap_or("-")
        )?;
        writeln!(
            output,
            "Tree: {}",
            report.working_tree_path.as_deref().unwrap_or("-")
        )?;
        writeln!(output, "Auth: {}", report.auth.state)?;
        writeln!(output, "Daemon: {}", report.daemon.state)?;
        writeln!(
            output,
            "Sync: {} ({})",
            report.sync.mode, report.sync.status
        )?;
        writeln!(
            output,
            "Unlocked Folders: {}",
            report.unlocked_folders.len()
        )?;
        writeln!(output, "Conflicts: {}", report.conflicts.len())?;
        Ok(())
    }
}

fn unlock<W: Write>(
    args: &[String],
    env: &CliEnvironment,
    json: bool,
    output: &mut W,
) -> Result<(), CliError> {
    let all = args.iter().any(|arg| arg == "--all");
    let target = args.iter().find(|arg| !arg.starts_with("--")).cloned();
    let root = current_tree_root(env)?;
    let tree = read_working_tree_state(&root)?;
    let mut opened = Vec::new();
    mutate_agent_state(env, |state, now| {
        let mut known = state
            .unlocked_folders
            .iter()
            .map(|folder| folder.folder_id.clone())
            .collect::<BTreeSet<_>>();
        let candidates = if all {
            tree.folder_roots
                .iter()
                .filter(|root| root.can_read)
                .map(|root| root.folder_id.clone())
                .collect::<Vec<_>>()
        } else {
            vec![
                target
                    .clone()
                    .ok_or(CliError::MissingArgument("folder or --all"))?,
            ]
        };
        for folder_id in candidates {
            if known.insert(folder_id.clone()) {
                state.unlocked_folders.push(UnlockedFolder {
                    folder_id: folder_id.clone(),
                    key_version: 1,
                    opened_at: now.clone(),
                    source: "prototype-local-signer".to_owned(),
                });
                opened.push(folder_id);
            }
        }
        state.add_activity(
            now,
            "folder_keys.opened",
            "Folder Keys opened in local session",
        );
        Ok(())
    })?;
    if json {
        write_json(output, &serde_json::json!({ "opened": opened }))
    } else if opened.is_empty() {
        writeln!(output, "no new Folder Keys opened")?;
        Ok(())
    } else {
        writeln!(output, "opened {}", opened.join(", "))?;
        Ok(())
    }
}

fn conflicts<W: Write>(env: &CliEnvironment, json: bool, output: &mut W) -> Result<(), CliError> {
    let state = load_current_agent_state(env)?;
    let active = state
        .conflicts
        .into_iter()
        .filter(|conflict| conflict.state == ConflictState::Open)
        .collect::<Vec<_>>();
    if json {
        write_json(output, &active)
    } else if active.is_empty() {
        writeln!(output, "no conflicts")?;
        Ok(())
    } else {
        for conflict in active {
            writeln!(output, "{} {}", conflict.id, conflict.reason)?;
        }
        Ok(())
    }
}

fn resolve<W: Write>(
    args: &[String],
    env: &CliEnvironment,
    json: bool,
    output: &mut W,
) -> Result<(), CliError> {
    let conflict_id = args
        .first()
        .ok_or(CliError::MissingArgument("conflict-id"))?;
    let mut found = false;
    mutate_agent_state(env, |state, now| {
        for conflict in &mut state.conflicts {
            if conflict.id == *conflict_id {
                conflict.state = ConflictState::Resolved;
                conflict.resolved_at = Some(now.clone());
                found = true;
            }
        }
        if !found {
            return Err(CliError::NotFound(conflict_id.clone()));
        }
        state.add_activity(
            now,
            "conflict.resolved",
            format!("Conflict {conflict_id} marked resolved"),
        );
        Ok(())
    })?;
    if json {
        write_json(output, &serde_json::json!({ "resolved": conflict_id }))
    } else {
        writeln!(output, "resolved {conflict_id}")?;
        Ok(())
    }
}

fn activity<W: Write>(env: &CliEnvironment, json: bool, output: &mut W) -> Result<(), CliError> {
    let state = load_current_agent_state(env)?;
    if json {
        write_json(output, &state.activity)
    } else {
        write_activity_rows(output, &state.activity)
    }
}

fn access<W: Write>(
    args: &[String],
    env: &CliEnvironment,
    json: bool,
    output: &mut W,
) -> Result<(), CliError> {
    match args.first().map(String::as_str) {
        Some("explain") => {
            let folder = args.get(1).ok_or(CliError::MissingArgument("folder"))?;
            let root = current_tree_root(env)?;
            let tree = read_working_tree_state(&root)?;
            let explanation = explain_access(folder, &tree);
            if json {
                write_json(output, &explanation)
            } else {
                writeln!(output, "{}: {}", explanation.folder, explanation.reason)?;
                Ok(())
            }
        }
        Some(other) => Err(CliError::InvalidCommand(format!("access {other}"))),
        None => Err(CliError::MissingArgument("access command")),
    }
}

fn vault<W: Write>(
    args: &[String],
    env: &CliEnvironment,
    json: bool,
    output: &mut W,
) -> Result<(), CliError> {
    match args.first().map(String::as_str).unwrap_or("metadata") {
        "create" => {
            let values = positional_values(args);
            let vault_id = values.get(1).ok_or(CliError::MissingArgument("vault-id"))?;
            let kind = option_value(args, "--kind").unwrap_or_else(|| "personal".to_owned());
            let name = option_value(args, "--name").unwrap_or_else(|| vault_id.clone());
            let body = serde_json::json!({
                "vaultId": vault_id,
                "kind": normalize_vault_kind(&kind)?,
                "name": name
            });
            let response = signed_json_request(env, args, "POST", "/_admin/vaults", Some(body))?;
            write_command_response(output, json, &response)
        }
        "metadata" | "status" => {
            let vault_id = option_value(args, "--vault")
                .or_else(|| positional_values(args).get(1).cloned())
                .or_else(|| current_vault_id(env))
                .ok_or(CliError::MissingArgument("vault-id or --vault"))?;
            let path = format!("/_admin/vaults/{vault_id}/metadata");
            let response = signed_json_request(env, args, "GET", &path, None)?;
            write_command_response(output, json, &response)
        }
        "export" => {
            let vault_id = option_value(args, "--vault")
                .or_else(|| positional_values(args).get(1).cloned())
                .or_else(|| current_vault_id(env))
                .ok_or(CliError::MissingArgument("vault-id or --vault"))?;
            let path = format!("/_admin/vaults/{vault_id}/export");
            let response = signed_json_request(env, args, "GET", &path, None)?;
            write_command_response(output, json, &response)
        }
        other => Err(CliError::InvalidCommand(format!("vault {other}"))),
    }
}

fn folder<W: Write>(
    args: &[String],
    env: &CliEnvironment,
    json: bool,
    output: &mut W,
) -> Result<(), CliError> {
    match args.first().map(String::as_str).unwrap_or("create") {
        "create" => {
            let values = positional_values(args);
            let folder_id = values
                .get(1)
                .ok_or(CliError::MissingArgument("folder-id"))?;
            let vault_id = command_vault_id(args, env)?;
            let name = option_value(args, "--name").unwrap_or_else(|| folder_id.clone());
            let path = option_value(args, "--path").unwrap_or_else(|| name.clone());
            let role = option_value(args, "--role").unwrap_or_else(|| "folder".to_owned());
            let metadata = fetch_vault_metadata(env, args, &vault_id)?;
            let access = option_value(args, "--access").unwrap_or_else(|| {
                if metadata.kind == "personal" {
                    "owner".to_owned()
                } else {
                    "restricted".to_owned()
                }
            });
            let access_users = option_values(args, "--member");
            let recipients = folder_required_recipients(&metadata, &access, &access_users)?;
            let folder_key = FolderKey::generate();
            let auth = read_auth_required(env)?;
            let event = admin_access_change_event(
                env,
                &vault_id,
                AdminAccessAction::SetFolderAccessMode,
                Some(folder_id),
                None,
                Some(1),
            )?;
            let grants = recipients
                .iter()
                .map(|recipient| {
                    folder_key_grant_request(
                        &auth,
                        &vault_id,
                        folder_id,
                        1,
                        recipient,
                        &folder_key,
                        env,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            let body = serde_json::json!({
                "folderId": folder_id,
                "name": name,
                "role": normalize_folder_role(&role)?,
                "access": normalize_folder_access(&access)?,
                "parentFolderId": option_value(args, "--parent"),
                "path": path,
                "sharedFolderSource": args.iter().any(|arg| arg == "--shared-source"),
                "accessUserIds": access_users,
                "grants": grants,
                "accessChangeEvent": event
            });
            let route = format!("/_admin/vaults/{vault_id}/folders");
            let response = signed_json_request(env, args, "POST", &route, Some(body))?;
            update_local_folder_after_create(env, folder_id, &path, &folder_key)?;
            write_command_response(output, json, &response)
        }
        other => Err(CliError::InvalidCommand(format!("folder {other}"))),
    }
}

fn permissions<W: Write>(
    args: &[String],
    env: &CliEnvironment,
    json: bool,
    output: &mut W,
) -> Result<(), CliError> {
    match args.first().map(String::as_str) {
        Some("add-member") | Some("member-add") => {
            let vault_id = command_vault_id(args, env)?;
            let target = required_option_or_positional(args, "--target", 1, "target-npub")?;
            let event = admin_access_change_event(
                env,
                &vault_id,
                AdminAccessAction::AddMember,
                None,
                Some(&target),
                None,
            )?;
            let body = serde_json::json!({
                "targetNpub": target,
                "accessChangeEvent": event
            });
            let route = format!("/_admin/vaults/{vault_id}/members");
            let response = signed_json_request(env, args, "POST", &route, Some(body))?;
            write_command_response(output, json, &response)
        }
        Some("remove-member") | Some("member-remove") => {
            let vault_id = command_vault_id(args, env)?;
            let target = required_option_or_positional(args, "--target", 1, "target-npub")?;
            let event = admin_access_change_event(
                env,
                &vault_id,
                AdminAccessAction::RemoveMember,
                None,
                Some(&target),
                None,
            )?;
            let route = format!("/_admin/vaults/{vault_id}/members/{target}");
            let response = signed_json_request(
                env,
                args,
                "DELETE",
                &route,
                Some(serde_json::json!({ "accessChangeEvent": event })),
            )?;
            write_command_response(output, json, &response)
        }
        Some("add-admin") | Some("admin-add") => {
            let vault_id = command_vault_id(args, env)?;
            let target = required_option_or_positional(args, "--target", 1, "target-npub")?;
            let event = admin_access_change_event(
                env,
                &vault_id,
                AdminAccessAction::AddAdmin,
                None,
                Some(&target),
                None,
            )?;
            let body = serde_json::json!({
                "targetNpub": target,
                "accessChangeEvent": event
            });
            let route = format!("/_admin/vaults/{vault_id}/admins");
            let response = signed_json_request(env, args, "POST", &route, Some(body))?;
            write_command_response(output, json, &response)
        }
        Some("remove-admin") | Some("admin-remove") => {
            let vault_id = command_vault_id(args, env)?;
            let target = required_option_or_positional(args, "--target", 1, "target-npub")?;
            let event = admin_access_change_event(
                env,
                &vault_id,
                AdminAccessAction::RemoveAdmin,
                None,
                Some(&target),
                None,
            )?;
            let route = format!("/_admin/vaults/{vault_id}/admins/{target}");
            let response = signed_json_request(
                env,
                args,
                "DELETE",
                &route,
                Some(serde_json::json!({ "accessChangeEvent": event })),
            )?;
            write_command_response(output, json, &response)
        }
        Some("grant-folder") | Some("folder-grant") => {
            let vault_id = command_vault_id(args, env)?;
            let folder_id =
                option_value(args, "--folder").ok_or(CliError::MissingArgument("--folder"))?;
            let target = required_option_or_positional(args, "--target", 1, "target-npub")?;
            let metadata = fetch_vault_metadata(env, args, &vault_id)?;
            let key_version = metadata
                .folders
                .iter()
                .find(|folder| folder.id == folder_id)
                .map(|folder| folder.current_key_version)
                .ok_or_else(|| CliError::NotFound(format!("folder {folder_id}")))?;
            let folder_key = FolderKey::generate();
            let auth = read_auth_required(env)?;
            let event = admin_access_change_event(
                env,
                &vault_id,
                AdminAccessAction::GrantFolderAccess,
                Some(&folder_id),
                Some(&target),
                Some(key_version),
            )?;
            let grant = folder_key_grant_request(
                &auth,
                &vault_id,
                &folder_id,
                key_version,
                &target,
                &folder_key,
                env,
            )?;
            let route = format!("/_admin/vaults/{vault_id}/folders/{folder_id}/access");
            let body = serde_json::json!({
                "targetNpub": target,
                "grant": grant,
                "accessChangeEvent": event
            });
            let response = signed_json_request(env, args, "POST", &route, Some(body))?;
            write_command_response(output, json, &response)
        }
        Some(other) => Err(CliError::InvalidCommand(format!("permissions {other}"))),
        None => Err(CliError::MissingArgument("permissions command")),
    }
}

fn invites<W: Write>(
    args: &[String],
    env: &CliEnvironment,
    json: bool,
    output: &mut W,
) -> Result<(), CliError> {
    match args.first().map(String::as_str) {
        Some("create") => {
            let vault_id = command_vault_id(args, env)?;
            let target = required_option_or_positional(args, "--target", 1, "target-npub")?;
            let expires_at = option_value(args, "--expires")
                .unwrap_or_else(|| "2099-01-01T00:00:00Z".to_owned());
            let folders = option_values(args, "--folder");
            let body = serde_json::json!({
                "targetNpub": target,
                "initialFolderAccess": folders,
                "expiresAt": expires_at
            });
            let route = format!("/_admin/vaults/{vault_id}/invitations");
            let response = signed_json_request(env, args, "POST", &route, Some(body))?;
            write_command_response(output, json, &response)
        }
        Some("show") => {
            let code = required_option_or_positional(args, "--code", 1, "invite-code")?;
            let route = format!("/_admin/vault-invitation-links/{code}");
            let response = signed_json_request(env, args, "GET", &route, None)?;
            write_command_response(output, json, &response)
        }
        Some("accept") => {
            let route = if let Some(code) =
                option_value(args, "--code").or_else(|| positional_values(args).get(1).cloned())
            {
                format!("/_admin/vault-invitation-links/{code}/accept")
            } else {
                let vault_id = command_vault_id(args, env)?;
                let id = option_value(args, "--id")
                    .ok_or(CliError::MissingArgument("--id or --code"))?;
                format!("/_admin/vaults/{vault_id}/invitations/{id}/accept")
            };
            let response = signed_json_request(env, args, "POST", &route, None)?;
            write_command_response(output, json, &response)
        }
        Some("revoke") => {
            let vault_id = command_vault_id(args, env)?;
            let id = required_option_or_positional(args, "--id", 1, "invitation-id")?;
            let route = format!("/_admin/vaults/{vault_id}/invitations/{id}");
            let response = signed_json_request(env, args, "DELETE", &route, None)?;
            write_command_response(output, json, &response)
        }
        Some(other) => Err(CliError::InvalidCommand(format!("invites {other}"))),
        None => Err(CliError::MissingArgument("invites command")),
    }
}

fn share<W: Write>(
    args: &[String],
    env: &CliEnvironment,
    json: bool,
    output: &mut W,
) -> Result<(), CliError> {
    match args.first().map(String::as_str) {
        Some("link") | Some("create-link") => {
            let vault_id = command_vault_id(args, env)?;
            let folder_id =
                option_value(args, "--folder").ok_or(CliError::MissingArgument("--folder"))?;
            let target = required_option_or_positional(args, "--target", 1, "target-npub")?;
            let expires_at = option_value(args, "--expires")
                .unwrap_or_else(|| "2099-01-01T00:00:00Z".to_owned());
            let metadata = fetch_vault_metadata(env, args, &vault_id)?;
            let key_version = metadata
                .folders
                .iter()
                .find(|folder| folder.id == folder_id)
                .map(|folder| folder.current_key_version)
                .ok_or_else(|| CliError::NotFound(format!("folder {folder_id}")))?;
            let folder_key = FolderKey::generate();
            let auth = read_auth_required(env)?;
            let event = admin_access_change_event(
                env,
                &vault_id,
                AdminAccessAction::GrantFolderAccess,
                Some(&folder_id),
                Some(&target),
                Some(key_version),
            )?;
            let grant = folder_key_grant_request(
                &auth,
                &vault_id,
                &folder_id,
                key_version,
                &target,
                &folder_key,
                env,
            )?;
            let body = serde_json::json!({
                "recipientNpub": target,
                "grant": grant,
                "accessChangeEvent": event,
                "expiresAt": expires_at,
                "createPersonalMount": args.iter().any(|arg| arg == "--personal-mount")
            });
            let route = format!("/_admin/vaults/{vault_id}/folders/{folder_id}/share-links");
            let response = signed_json_request(env, args, "POST", &route, Some(body))?;
            write_command_response(output, json, &response)
        }
        Some("accept") => {
            let id = required_option_or_positional(args, "--id", 1, "share-link-id")?;
            let route = format!("/_admin/share-links/{id}/accept");
            let response = signed_json_request(env, args, "POST", &route, None)?;
            write_command_response(output, json, &response)
        }
        Some("revoke") => {
            let id = required_option_or_positional(args, "--id", 1, "share-link-id")?;
            let route = format!("/_admin/share-links/{id}");
            let response = signed_json_request(env, args, "DELETE", &route, None)?;
            write_command_response(output, json, &response)
        }
        Some("source") => {
            let vault_id = command_vault_id(args, env)?;
            let folder_id =
                option_value(args, "--folder").ok_or(CliError::MissingArgument("--folder"))?;
            let metadata = fetch_vault_metadata(env, args, &vault_id)?;
            let key_version = metadata
                .folders
                .iter()
                .find(|folder| folder.id == folder_id)
                .map(|folder| folder.current_key_version)
                .ok_or_else(|| CliError::NotFound(format!("folder {folder_id}")))?;
            let event = admin_access_change_event(
                env,
                &vault_id,
                AdminAccessAction::SetFolderAccessMode,
                Some(&folder_id),
                None,
                Some(key_version),
            )?;
            let route = format!("/_admin/vaults/{vault_id}/folders/{folder_id}/share-source");
            let response = signed_json_request(
                env,
                args,
                "POST",
                &route,
                Some(serde_json::json!({ "accessChangeEvent": event })),
            )?;
            write_command_response(output, json, &response)
        }
        Some("folder-invite") => {
            let vault_id = command_vault_id(args, env)?;
            let folder_id =
                option_value(args, "--folder").ok_or(CliError::MissingArgument("--folder"))?;
            let destination_vault_id = option_value(args, "--destination-vault")
                .ok_or(CliError::MissingArgument("--destination-vault"))?;
            let destination_admin = option_value(args, "--destination-admin")
                .ok_or(CliError::MissingArgument("--destination-admin"))?;
            let metadata = fetch_vault_metadata(env, args, &vault_id)?;
            let key_version = metadata
                .folders
                .iter()
                .find(|folder| folder.id == folder_id)
                .map(|folder| folder.current_key_version)
                .ok_or_else(|| CliError::NotFound(format!("folder {folder_id}")))?;
            let folder_key = FolderKey::generate();
            let auth = read_auth_required(env)?;
            let event = admin_access_change_event(
                env,
                &vault_id,
                AdminAccessAction::GrantFolderAccess,
                Some(&folder_id),
                Some(&destination_admin),
                Some(key_version),
            )?;
            let grant = folder_key_grant_request(
                &auth,
                &vault_id,
                &folder_id,
                key_version,
                &destination_admin,
                &folder_key,
                env,
            )?;
            let route =
                format!("/_admin/vaults/{vault_id}/folders/{folder_id}/shared-folder-invitations");
            let body = serde_json::json!({
                "destinationVaultId": destination_vault_id,
                "destinationAdminNpub": destination_admin,
                "grant": grant,
                "accessChangeEvent": event
            });
            let response = signed_json_request(env, args, "POST", &route, Some(body))?;
            write_command_response(output, json, &response)
        }
        Some("folder-accept") => {
            let id = required_option_or_positional(args, "--id", 1, "shared-folder-invitation-id")?;
            let route = format!("/_admin/shared-folder-invitations/{id}/accept");
            let response = signed_json_request(env, args, "POST", &route, None)?;
            write_command_response(output, json, &response)
        }
        Some(other) => Err(CliError::InvalidCommand(format!("share {other}"))),
        None => Err(CliError::MissingArgument("share command")),
    }
}

fn auth_status(env: &CliEnvironment) -> Result<AuthStatus, CliError> {
    Ok(match read_auth_optional(env)? {
        Some(auth) => AuthStatus {
            state: "authenticated".to_owned(),
            npub: Some(auth.npub),
            signer: "local-nostr-keypair".to_owned(),
            capabilities: vec![
                "getPublicKey".to_owned(),
                "signEvent".to_owned(),
                "nip44.encrypt".to_owned(),
                "nip44.decrypt".to_owned(),
            ],
        },
        None => AuthStatus {
            state: "missing".to_owned(),
            npub: None,
            signer: "none".to_owned(),
            capabilities: Vec::new(),
        },
    })
}

fn daemon_status(env: &CliEnvironment) -> Result<DaemonStatus, CliError> {
    let state = load_current_agent_state(env)?;
    Ok(DaemonStatus {
        state: state.daemon.state.to_string(),
        sync_mode: state.sync.mode,
        last_started_at: state.daemon.last_started_at,
    })
}

fn status_report(env: &CliEnvironment) -> Result<StatusReport, CliError> {
    let auth = auth_status(env)?;
    let root = find_agent_state(&env.cwd)?;
    let Some(root) = root else {
        return Ok(StatusReport {
            vault_id: None,
            working_tree_path: None,
            auth,
            daemon: DaemonStatus {
                state: "missing".to_owned(),
                sync_mode: "automatic".to_owned(),
                last_started_at: None,
            },
            sync: SyncStatus {
                mode: "automatic".to_owned(),
                status: "no-working-tree".to_owned(),
                latest_sequence: 0,
            },
            unlocked_folders: Vec::new(),
            conflicts: Vec::new(),
            blocked: vec!["no Vault Working Tree found".to_owned()],
        });
    };
    let state = read_agent_state(&root)?;
    let tree_state = read_working_tree_state(&root)?;
    let open_conflicts = state
        .conflicts
        .iter()
        .filter(|conflict| conflict.state == ConflictState::Open)
        .cloned()
        .collect::<Vec<_>>();
    let mut blocked = Vec::new();
    if auth.state != "authenticated" {
        blocked.push("missing auth".to_owned());
    }
    if state.daemon.state != DaemonRunState::Running {
        blocked.push("daemon not running".to_owned());
    }
    if !open_conflicts.is_empty() {
        blocked.push("unresolved conflicts".to_owned());
    }
    Ok(StatusReport {
        vault_id: Some(state.vault_id),
        working_tree_path: Some(root.display().to_string()),
        auth,
        daemon: DaemonStatus {
            state: state.daemon.state.to_string(),
            sync_mode: state.sync.mode.clone(),
            last_started_at: state.daemon.last_started_at,
        },
        sync: SyncStatus {
            mode: state.sync.mode,
            status: state.sync.status,
            latest_sequence: tree_state.sync.latest_sequence,
        },
        unlocked_folders: state.unlocked_folders,
        conflicts: open_conflicts,
        blocked,
    })
}

fn explain_access(folder: &str, tree: &VaultWorkingTreeStateManifest) -> AccessExplanation {
    if let Some(root) = tree
        .folder_roots
        .iter()
        .find(|root| root.folder_id == folder || root.path == folder)
    {
        if root.can_read {
            AccessExplanation {
                folder: folder.to_owned(),
                state: "readable".to_owned(),
                reason: "Folder is materialized and readable in this Vault Working Tree".to_owned(),
            }
        } else if root.metadata_only {
            AccessExplanation {
                folder: folder.to_owned(),
                state: "locked".to_owned(),
                reason: "Folder is metadata-only; Folder Access or an open Folder Key is missing"
                    .to_owned(),
            }
        } else {
            AccessExplanation {
                folder: folder.to_owned(),
                state: "unavailable".to_owned(),
                reason: "Folder is present but not readable".to_owned(),
            }
        }
    } else {
        AccessExplanation {
            folder: folder.to_owned(),
            state: "unknown".to_owned(),
            reason: "Folder is not listed in working-tree state".to_owned(),
        }
    }
}

fn current_tree_root(env: &CliEnvironment) -> Result<PathBuf, CliError> {
    find_agent_state(&env.cwd)?.ok_or(CliError::MissingWorkingTree)
}

fn load_current_agent_state(env: &CliEnvironment) -> Result<AgentState, CliError> {
    let root = current_tree_root(env)?;
    read_agent_state(&root)
}

fn mutate_agent_state<F>(env: &CliEnvironment, f: F) -> Result<(), CliError>
where
    F: FnOnce(&mut AgentState, String) -> Result<(), CliError>,
{
    let root = current_tree_root(env)?;
    let mut state = read_agent_state(&root)?;
    f(&mut state, timestamp(env))?;
    write_agent_state(&root, &state)
}

fn find_agent_state(start: &Path) -> Result<Option<PathBuf>, CliError> {
    let mut cursor = start.to_path_buf();
    loop {
        if cursor.join(".finitebrain/agent-state.json").exists() {
            return Ok(Some(cursor));
        }
        if !cursor.pop() {
            return Ok(None);
        }
    }
}

fn read_agent_state(root: &Path) -> Result<AgentState, CliError> {
    read_json_file(&root.join(".finitebrain/agent-state.json"))
}

fn write_agent_state(root: &Path, state: &AgentState) -> Result<(), CliError> {
    write_json_file(&root.join(".finitebrain/agent-state.json"), state)
}

fn read_working_tree_state(root: &Path) -> Result<VaultWorkingTreeStateManifest, CliError> {
    read_json_file(&root.join(".finitebrain/working-tree-state.json"))
}

fn read_auth_optional(env: &CliEnvironment) -> Result<Option<PrototypeAuth>, CliError> {
    let path = auth_path(env);
    if !path.exists() {
        return Ok(None);
    }
    read_json_file(&path).map(Some)
}

fn write_auth(env: &CliEnvironment, auth: &PrototypeAuth) -> Result<(), CliError> {
    let path = auth_path(env);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_vec_pretty(auth)?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&path)?;
    file.write_all(&body)?;
    set_secret_permissions(&path)?;
    Ok(())
}

fn auth_path(env: &CliEnvironment) -> PathBuf {
    env.config_dir.join("auth.json")
}

fn read_json_file<T>(path: &Path) -> Result<T, CliError>
where
    T: for<'de> Deserialize<'de>,
{
    let mut body = String::new();
    fs::File::open(path)?.read_to_string(&mut body)?;
    serde_json::from_str(&body).map_err(CliError::from)
}

fn write_json_file<T>(path: &Path, value: &T) -> Result<(), CliError>
where
    T: Serialize,
{
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn write_json<W, T>(output: &mut W, value: &T) -> Result<(), CliError>
where
    W: Write,
    T: Serialize,
{
    serde_json::to_writer_pretty(&mut *output, value)?;
    writeln!(output)?;
    Ok(())
}

fn write_activity_rows<W: Write>(output: &mut W, rows: &[ActivityEntry]) -> Result<(), CliError> {
    if rows.is_empty() {
        writeln!(output, "no activity")?;
        return Ok(());
    }
    for row in rows {
        writeln!(output, "{} {} {}", row.at, row.kind, row.message)?;
    }
    Ok(())
}

fn timestamp(env: &CliEnvironment) -> String {
    env.now.clone().unwrap_or_else(|| {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0));
        let datetime = OffsetDateTime::from_unix_timestamp(now.as_secs() as i64)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH);
        datetime
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
    })
}

fn take_flag(args: &mut Vec<String>, flag: &str) -> bool {
    let before = args.len();
    args.retain(|arg| arg != flag);
    before != args.len()
}

fn option_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find_map(|window| (window[0] == flag).then(|| window[1].clone()))
}

fn check_http_health(url: &str) -> HealthCheck {
    let Some((host, port, path)) = parse_http_url(url) else {
        return HealthCheck::warn("server health skipped: only http URLs are supported");
    };
    let address = format!("{host}:{port}");
    let Some(socket_address) = address
        .to_socket_addrs()
        .ok()
        .and_then(|mut addresses| addresses.next())
    else {
        return HealthCheck::warn(format!("server address could not be resolved: {address}"));
    };
    let Ok(mut stream) = TcpStream::connect_timeout(&socket_address, Duration::from_millis(500))
    else {
        return HealthCheck::warn(format!("server unavailable at {address}"));
    };
    let health_path = if path == "/" {
        "/health".to_owned()
    } else {
        format!("{path}/health")
    };
    let request =
        format!("GET {health_path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return HealthCheck::warn("server health request failed");
    }
    let mut response = String::new();
    if stream.read_to_string(&mut response).is_err() {
        return HealthCheck::warn("server health response failed");
    }
    if response.starts_with("HTTP/1.1 200") || response.starts_with("HTTP/1.0 200") {
        HealthCheck::ok(format!("server healthy at {url}"))
    } else {
        HealthCheck::warn(format!("server health did not return 200 at {url}"))
    }
}

fn sync_once(env: &CliEnvironment, activity_kind: &str) -> Result<SyncOnceReport, CliError> {
    let root = current_tree_root(env)?;
    let state = read_agent_state(&root)?;
    let server_url = state
        .server_url
        .clone()
        .or_else(|| env::var("FINITE_BRAIN_PUBLIC_BASE_URL").ok())
        .ok_or(CliError::MissingServer)?;
    let mut tree_state = read_working_tree_state(&root)?;
    let path = if tree_state.sync.latest_sequence == 0 {
        format!("/_admin/vaults/{}/sync/bootstrap", state.vault_id)
    } else {
        format!(
            "/_admin/vaults/{}/sync/records?after={}&limit=100",
            state.vault_id, tree_state.sync.latest_sequence
        )
    };
    let response = signed_json_request_to_server(env, &server_url, "GET", &path, None)?;
    let latest_sequence = response
        .get("latestSequence")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(tree_state.sync.latest_sequence);
    let record_count = response
        .get("count")
        .and_then(serde_json::Value::as_u64)
        .or_else(|| {
            response
                .get("objectCount")
                .and_then(serde_json::Value::as_u64)
        })
        .unwrap_or(0) as usize;
    let sync_dir = root.join(".finitebrain/encrypted-sync");
    fs::create_dir_all(&sync_dir)?;
    let file_name = if tree_state.sync.latest_sequence == 0 {
        "bootstrap.json".to_owned()
    } else {
        format!("records-after-{}.json", tree_state.sync.latest_sequence)
    };
    write_json_file(&sync_dir.join(file_name), &response)?;
    tree_state.sync.latest_sequence = latest_sequence;
    write_json_file(
        &root.join(".finitebrain/working-tree-state.json"),
        &tree_state,
    )?;
    let status = if record_count == 0 {
        "caught-up".to_owned()
    } else {
        "applied-remote-records".to_owned()
    };
    let report = SyncOnceReport {
        status: status.clone(),
        latest_sequence,
        record_count,
        server_url,
    };
    mutate_agent_state(env, |state, now| {
        state.sync.status = status;
        state.add_activity(
            now,
            activity_kind,
            format!("Automatic sync observed latest sequence {latest_sequence}"),
        );
        Ok(())
    })?;
    Ok(report)
}

fn signed_json_request(
    env: &CliEnvironment,
    args: &[String],
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
) -> Result<serde_json::Value, CliError> {
    let server_url = server_url_for_command(env, args)?;
    signed_json_request_to_server(env, &server_url, method, path, body)
}

fn signed_json_request_to_server(
    env: &CliEnvironment,
    server_url: &str,
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
) -> Result<serde_json::Value, CliError> {
    let body = body.map(|body| serde_json::to_vec(&body)).transpose()?;
    let url = absolute_server_url(server_url, path);
    let auth = read_auth_required(env)?;
    let keys = Keys::parse(&auth.secret_key)
        .map_err(|error| CliError::InvalidSigner(error.to_string()))?;
    let authorization = signed_http_auth_header(&keys, method, &url, body.as_deref())?;
    let response = http_request(method, &url, Some(&authorization), body.as_deref())?;
    if !(200..300).contains(&response.status) {
        return Err(CliError::Http(format!(
            "server returned {}: {}",
            response.status,
            response.body.trim()
        )));
    }
    if response.body.trim().is_empty() {
        return Ok(serde_json::json!({ "status": "ok" }));
    }
    serde_json::from_str(&response.body).map_err(CliError::from)
}

fn http_request(
    method: &str,
    url: &str,
    authorization: Option<&str>,
    body: Option<&[u8]>,
) -> Result<HttpResponse, CliError> {
    let Some((host, port, path)) = parse_http_url(url) else {
        return Err(CliError::Unsupported(
            "fbrain prototype HTTP client supports http:// URLs only".to_owned(),
        ));
    };
    let address = format!("{host}:{port}");
    let socket_address = address
        .to_socket_addrs()
        .map_err(|error| CliError::Http(error.to_string()))?
        .next()
        .ok_or_else(|| {
            CliError::Http(format!("server address could not be resolved: {address}"))
        })?;
    let mut stream = TcpStream::connect_timeout(&socket_address, Duration::from_secs(2))
        .map_err(|error| CliError::Http(error.to_string()))?;
    let body = body.unwrap_or_default();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nAccept: application/json\r\nConnection: close\r\n"
    );
    if let Some(authorization) = authorization {
        request.push_str(&format!("Authorization: {authorization}\r\n"));
    }
    if !body.is_empty() {
        request.push_str("Content-Type: application/json\r\n");
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes())?;
    if !body.is_empty() {
        stream.write_all(body)?;
    }
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| CliError::Http("malformed HTTP response".to_owned()))?;
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| CliError::Http("HTTP status did not parse".to_owned()))?;
    Ok(HttpResponse {
        status,
        body: body.to_owned(),
    })
}

fn signed_http_auth_header(
    keys: &Keys,
    method: &str,
    url: &str,
    body: Option<&[u8]>,
) -> Result<String, CliError> {
    let nonce = auth_nonce();
    let mut tags = vec![
        tag_vec(["u", url])?,
        tag_vec(["method", method])?,
        tag_vec(["nonce", &nonce])?,
    ];
    if let Some(body) = body {
        let payload = sha256_hex(body);
        tags.push(tag_vec(["payload", &payload])?);
    }
    let event = sign_event(keys, Kind::HttpAuth, "", tags, unix_timestamp(), None)?;
    Ok(format!("Nostr {}", BASE64_STANDARD.encode(event.as_json())))
}

fn sign_event(
    keys: &Keys,
    kind: Kind,
    content: impl Into<String>,
    tags: Vec<Tag>,
    created_at: u64,
    _label: Option<&str>,
) -> Result<nostr::Event, CliError> {
    EventBuilder::new(kind, content)
        .tags(tags)
        .custom_created_at(Timestamp::from_secs(created_at))
        .finalize(keys)
        .map_err(|error| CliError::InvalidSigner(error.to_string()))
}

fn fetch_vault_metadata(
    env: &CliEnvironment,
    args: &[String],
    vault_id: &str,
) -> Result<VaultMetadataView, CliError> {
    let path = format!("/_admin/vaults/{vault_id}/metadata");
    let response = signed_json_request(env, args, "GET", &path, None)?;
    serde_json::from_value(response).map_err(CliError::from)
}

fn folder_required_recipients(
    metadata: &VaultMetadataView,
    access: &str,
    access_users: &[String],
) -> Result<Vec<String>, CliError> {
    let mut recipients = BTreeSet::new();
    match normalize_folder_access(access)? {
        "owner" => {
            let owner = metadata.owner_user_id.clone().ok_or_else(|| {
                CliError::InvalidInput("owner access requires a personal vault".to_owned())
            })?;
            recipients.insert(owner);
        }
        "admin_only" => {
            recipients.extend(metadata.admins.iter().cloned());
        }
        "all_members" => {
            recipients.extend(metadata.admins.iter().cloned());
            recipients.extend(metadata.members.iter().cloned());
        }
        "restricted" => {
            recipients.extend(metadata.admins.iter().cloned());
            recipients.extend(access_users.iter().cloned());
        }
        other => {
            return Err(CliError::InvalidInput(format!(
                "unknown folder access mode {other}"
            )));
        }
    }
    if recipients.is_empty() {
        return Err(CliError::InvalidInput(
            "folder key needs at least one recipient".to_owned(),
        ));
    }
    Ok(recipients.into_iter().collect())
}

fn folder_key_grant_request(
    auth: &PrototypeAuth,
    vault_id: &str,
    folder_id: &str,
    key_version: u32,
    recipient_npub: &str,
    folder_key: &FolderKey,
    env: &CliEnvironment,
) -> Result<serde_json::Value, CliError> {
    let keys = Keys::parse(&auth.secret_key)
        .map_err(|error| CliError::InvalidSigner(error.to_string()))?;
    let recipient = NostrPublicKey::parse(recipient_npub)
        .map_err(|error| CliError::InvalidSigner(error.to_string()))?;
    let grant_id = deterministic_id(
        "grant",
        &[
            vault_id,
            folder_id,
            &key_version.to_string(),
            recipient_npub,
            &timestamp(env),
        ],
    );
    let content = serde_json::json!({
        "version": "finite-folder-key-grant-v1",
        "vaultId": vault_id,
        "folderId": folder_id,
        "keyVersion": key_version,
        "folderKey": folder_key.to_base64(),
        "issuerNpub": auth.npub,
        "recipientNpub": recipient_npub,
        "createdAt": timestamp(env)
    })
    .to_string();
    let rumor = build_rumor(
        NostrPublicKey::from_protocol(keys.public_key()),
        Kind::Custom(APP_SPECIFIC_KIND),
        vec![
            tag_vec([
                "d",
                &format!("finite-folder-key-grant:{vault_id}:{folder_id}:{key_version}"),
            ])?,
            tag_vec(["vault", vault_id])?,
            tag_vec(["folder", folder_id])?,
            tag_vec(["keyVersion", &key_version.to_string()])?,
        ],
        content,
        unix_timestamp(),
    );
    let wrapped = wrap_rumor(&keys, recipient, rumor)
        .map_err(|error| CliError::InvalidSigner(error.to_string()))?;
    Ok(serde_json::json!({
        "id": grant_id,
        "keyVersion": key_version,
        "recipientNpub": recipient_npub,
        "wrappedEventJson": wrapped.as_json(),
        "createdAt": timestamp(env)
    }))
}

fn admin_access_change_event(
    env: &CliEnvironment,
    vault_id: &str,
    action: AdminAccessAction,
    folder_id: Option<&str>,
    target_npub: Option<&str>,
    key_version: Option<u32>,
) -> Result<serde_json::Value, CliError> {
    let auth = read_auth_required(env)?;
    let keys = Keys::parse(&auth.secret_key)
        .map_err(|error| CliError::InvalidSigner(error.to_string()))?;
    let change_id = deterministic_id(
        "access-change",
        &[
            vault_id,
            action.as_str(),
            folder_id.unwrap_or("-"),
            target_npub.unwrap_or("-"),
            &timestamp(env),
        ],
    );
    let validation = AdminAccessChangeValidation {
        vault_id: VaultId::new(vault_id.to_owned())
            .map_err(|error| CliError::InvalidInput(error.to_string()))?,
        change_id,
        action,
        admin_npub: auth.npub,
        folder_id: folder_id
            .map(|id| FolderId::new(id.to_owned()))
            .transpose()
            .map_err(|error| CliError::InvalidInput(error.to_string()))?,
        target_npub: target_npub.map(ToOwned::to_owned),
        key_version,
        note: None,
        created_at: timestamp(env),
    };
    let payload = AdminAccessChangePayload::new(&validation);
    let event = sign_event(
        &keys,
        Kind::Custom(APP_SPECIFIC_KIND),
        payload.canonical_json(),
        admin_access_change_tags(&validation)?,
        unix_timestamp(),
        Some("admin-access-change"),
    )?;
    serde_json::from_str(&event.as_json()).map_err(CliError::from)
}

fn admin_access_change_tags(input: &AdminAccessChangeValidation) -> Result<Vec<Tag>, CliError> {
    let mut tags = vec![
        tag_vec([
            "d",
            &format!(
                "finite-vault-admin-access-change:{}:{}",
                input.vault_id, input.change_id
            ),
        ])?,
        tag_vec(["vault", &input.vault_id.to_string()])?,
        tag_vec(["action", input.action.as_str()])?,
    ];
    if let Some(folder_id) = &input.folder_id {
        tags.push(tag_vec(["folder", &folder_id.to_string()])?);
    }
    if let Some(target_npub) = &input.target_npub {
        let target = NostrPublicKey::parse(target_npub)
            .map_err(|error| CliError::InvalidSigner(error.to_string()))?;
        tags.push(tag_vec(["p", &target.to_hex()])?);
    }
    if let Some(key_version) = input.key_version {
        tags.push(tag_vec(["keyVersion", &key_version.to_string()])?);
    }
    Ok(tags)
}

fn update_local_folder_after_create(
    env: &CliEnvironment,
    folder_id: &str,
    path: &str,
    folder_key: &FolderKey,
) -> Result<(), CliError> {
    let Some(root) = find_agent_state(&env.cwd)? else {
        return Ok(());
    };
    SafeRelativePath::new("folder_path", path.to_owned())
        .map_err(|error| CliError::InvalidInput(error.to_string()))?;
    let mut tree = read_working_tree_state(&root)?;
    if !tree
        .folder_roots
        .iter()
        .any(|candidate| candidate.folder_id == folder_id)
    {
        tree.folder_roots.push(WorkingTreeFolderRoot {
            folder_id: folder_id.to_owned(),
            path: path.to_owned(),
            can_read: true,
            metadata_only: false,
        });
        tree.folder_roots
            .sort_by(|left, right| left.path.cmp(&right.path));
        write_json_file(&root.join(".finitebrain/working-tree-state.json"), &tree)?;
    }
    for subdir in ["", "raw", "compiled", "output"] {
        fs::create_dir_all(root.join(path).join(subdir))?;
    }
    mutate_agent_state(env, |state, now| {
        if !state
            .local_folder_keys
            .iter()
            .any(|key| key.folder_id == folder_id && key.key_version == 1)
        {
            state.local_folder_keys.push(LocalFolderKey {
                folder_id: folder_id.to_owned(),
                key_version: 1,
                key_base64: folder_key.to_base64(),
                source: "created-by-fbrain".to_owned(),
                opened_at: now.clone(),
            });
        }
        if !state
            .unlocked_folders
            .iter()
            .any(|folder| folder.folder_id == folder_id)
        {
            state.unlocked_folders.push(UnlockedFolder {
                folder_id: folder_id.to_owned(),
                key_version: 1,
                opened_at: now.clone(),
                source: "created-by-fbrain".to_owned(),
            });
        }
        state.add_activity(now, "folder.created", format!("Folder {folder_id} created"));
        Ok(())
    })
}

fn write_command_response<W: Write>(
    output: &mut W,
    json: bool,
    value: &serde_json::Value,
) -> Result<(), CliError> {
    if json {
        write_json(output, value)
    } else if let Some(id) = value
        .get("id")
        .or_else(|| value.get("vaultId"))
        .or_else(|| value.get("folderId"))
        .and_then(serde_json::Value::as_str)
    {
        writeln!(output, "ok {id}")?;
        Ok(())
    } else {
        writeln!(output, "ok")?;
        Ok(())
    }
}

fn read_auth_required(env: &CliEnvironment) -> Result<PrototypeAuth, CliError> {
    read_auth_optional(env)?.ok_or(CliError::MissingAuth)
}

fn signer_keys(env: &CliEnvironment) -> Result<Keys, CliError> {
    let auth = read_auth_required(env)?;
    Keys::parse(&auth.secret_key).map_err(|error| CliError::InvalidSigner(error.to_string()))
}

fn server_url_for_command(env: &CliEnvironment, args: &[String]) -> Result<String, CliError> {
    option_value(args, "--server")
        .or_else(|| {
            find_agent_state(&env.cwd)
                .ok()
                .flatten()
                .and_then(|root| read_agent_state(&root).ok())
                .and_then(|state| state.server_url)
        })
        .or_else(|| env::var("FINITE_BRAIN_PUBLIC_BASE_URL").ok())
        .ok_or(CliError::MissingServer)
}

fn command_vault_id(args: &[String], env: &CliEnvironment) -> Result<String, CliError> {
    option_value(args, "--vault")
        .or_else(|| current_vault_id(env))
        .ok_or(CliError::MissingArgument("vault-id or --vault"))
}

fn current_vault_id(env: &CliEnvironment) -> Option<String> {
    find_agent_state(&env.cwd)
        .ok()
        .flatten()
        .and_then(|root| read_agent_state(&root).ok())
        .map(|state| state.vault_id)
}

fn required_option_or_positional(
    args: &[String],
    option: &str,
    positional_index: usize,
    name: &'static str,
) -> Result<String, CliError> {
    option_value(args, option)
        .or_else(|| positional_values(args).get(positional_index).cloned())
        .ok_or(CliError::MissingArgument(name))
}

fn normalize_vault_kind(kind: &str) -> Result<&'static str, CliError> {
    match kind {
        "personal" => Ok("personal"),
        "organization" | "org" => Ok("organization"),
        other => Err(CliError::InvalidInput(format!(
            "unknown vault kind {other}"
        ))),
    }
}

fn normalize_folder_role(role: &str) -> Result<&'static str, CliError> {
    match role {
        "personal_home" | "personal-home" => Ok("personal_home"),
        "vault_ops" | "vault-ops" => Ok("vault_ops"),
        "general" => Ok("general"),
        "folder" => Ok("folder"),
        other => Err(CliError::InvalidInput(format!(
            "unknown folder role {other}"
        ))),
    }
}

fn normalize_folder_access(access: &str) -> Result<&'static str, CliError> {
    match access {
        "owner" => Ok("owner"),
        "admin_only" | "admin-only" | "admin" => Ok("admin_only"),
        "all_members" | "all-members" | "members" => Ok("all_members"),
        "restricted" => Ok("restricted"),
        other => Err(CliError::InvalidInput(format!(
            "unknown folder access mode {other}"
        ))),
    }
}

fn parse_kind(value: &str) -> Result<Kind, CliError> {
    match value {
        "text" | "text-note" => Ok(Kind::TextNote),
        "http-auth" => Ok(Kind::HttpAuth),
        "app" | "application-specific" => Ok(Kind::Custom(APP_SPECIFIC_KIND)),
        other => u16::from_str(other)
            .map(Kind::from_u16)
            .map_err(|_| CliError::InvalidInput(format!("event kind {other} did not parse"))),
    }
}

fn parse_cli_tag(value: String) -> Result<Tag, CliError> {
    let parts = value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if parts.is_empty() {
        return Err(CliError::InvalidInput("tag cannot be empty".to_owned()));
    }
    Tag::parse(parts).map_err(|error| CliError::InvalidInput(error.to_string()))
}

fn tag_vec<const N: usize>(parts: [&str; N]) -> Result<Tag, CliError> {
    Tag::parse(parts.into_iter().map(ToOwned::to_owned).collect::<Vec<_>>())
        .map_err(|error| CliError::InvalidInput(error.to_string()))
}

fn option_values(args: &[String], flag: &str) -> Vec<String> {
    args.windows(2)
        .filter(|window| window[0] == flag)
        .map(|window| window[1].clone())
        .collect()
}

fn positional_values(args: &[String]) -> Vec<String> {
    let mut values = Vec::new();
    let mut skip_next = false;
    for (index, arg) in args.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg.starts_with("--") {
            if args
                .get(index + 1)
                .is_some_and(|next| !next.starts_with("--"))
            {
                skip_next = true;
            }
            continue;
        }
        values.push(arg.clone());
    }
    values
}

fn absolute_server_url(server_url: &str, path: &str) -> String {
    format!(
        "{}{}",
        server_url.trim_end_matches('/'),
        if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        }
    )
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

fn auth_nonce() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_nanos();
    deterministic_id("nonce", &[&nanos.to_string()])
}

fn deterministic_id(prefix: &str, parts: &[&str]) -> String {
    let digest = Sha256::digest(parts.join("\n").as_bytes());
    format!(
        "{prefix}-{}",
        digest
            .iter()
            .take(8)
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn parse_http_url(url: &str) -> Option<(String, u16, String)> {
    let rest = url.strip_prefix("http://")?;
    let (host_port, path) = rest.split_once('/').unwrap_or((rest, ""));
    let (host, port) = host_port
        .split_once(':')
        .map(|(host, port)| (host.to_owned(), port.parse().ok()))
        .unwrap_or_else(|| (host_port.to_owned(), Some(80)));
    Some((host, port?, format!("/{}", path.trim_end_matches('/'))))
}

#[cfg(unix)]
fn set_secret_permissions(path: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_secret_permissions(_path: &Path) -> Result<(), CliError> {
    Ok(())
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PrototypeAuth {
    version: String,
    npub: String,
    secret_key: String,
    signer: String,
    capabilities: Vec<String>,
    created_at: String,
}

impl PrototypeAuth {
    fn from_nsec(nsec: &str, created_at: String) -> Result<Self, CliError> {
        let keys = Keys::parse(nsec).map_err(|error| CliError::InvalidSigner(error.to_string()))?;
        let npub = NostrPublicKey::from_protocol(keys.public_key())
            .to_npub()
            .map_err(|error| CliError::InvalidSigner(error.to_string()))?;
        Ok(Self {
            version: AUTH_VERSION.to_owned(),
            npub,
            secret_key: nsec.to_owned(),
            signer: "local-nostr-keypair".to_owned(),
            capabilities: vec![
                "getPublicKey".to_owned(),
                "signEvent".to_owned(),
                "nip44.encrypt".to_owned(),
                "nip44.decrypt".to_owned(),
            ],
            created_at,
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AgentState {
    version: String,
    vault_id: String,
    server_url: Option<String>,
    auth_npub: Option<String>,
    daemon: DaemonState,
    sync: AgentSyncState,
    unlocked_folders: Vec<UnlockedFolder>,
    #[serde(default)]
    local_folder_keys: Vec<LocalFolderKey>,
    conflicts: Vec<ConflictEntry>,
    activity: Vec<ActivityEntry>,
    created_at: String,
    updated_at: String,
}

impl AgentState {
    fn new(vault_id: &str, now: &str) -> Self {
        Self {
            version: AGENT_STATE_VERSION.to_owned(),
            vault_id: vault_id.to_owned(),
            server_url: None,
            auth_npub: None,
            daemon: DaemonState {
                state: DaemonRunState::Stopped,
                last_started_at: None,
            },
            sync: AgentSyncState {
                mode: "automatic".to_owned(),
                status: "idle".to_owned(),
            },
            unlocked_folders: Vec::new(),
            local_folder_keys: Vec::new(),
            conflicts: Vec::new(),
            activity: Vec::new(),
            created_at: now.to_owned(),
            updated_at: now.to_owned(),
        }
    }

    fn add_activity(&mut self, at: String, kind: impl Into<String>, message: impl Into<String>) {
        let kind = kind.into();
        let id = activity_id(&at, self.activity.len() + 1, &kind);
        self.activity.push(ActivityEntry {
            id,
            at: at.clone(),
            kind,
            message: message.into(),
        });
        self.updated_at = at;
    }
}

fn activity_id(at: &str, index: usize, kind: &str) -> String {
    let digest = Sha256::digest(format!("{at}\n{index}\n{kind}").as_bytes());
    format!(
        "activity-{}",
        digest
            .iter()
            .take(8)
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct DaemonState {
    state: DaemonRunState,
    last_started_at: Option<String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum DaemonRunState {
    Running,
    Stopped,
    Missing,
}

impl fmt::Display for DaemonRunState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Running => f.write_str("running"),
            Self::Stopped => f.write_str("stopped"),
            Self::Missing => f.write_str("missing"),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AgentSyncState {
    mode: String,
    status: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockedFolder {
    pub folder_id: String,
    pub key_version: u32,
    pub opened_at: String,
    pub source: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalFolderKey {
    folder_id: String,
    key_version: u32,
    key_base64: String,
    source: String,
    opened_at: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConflictEntry {
    pub id: String,
    pub folder_id: Option<String>,
    pub path: Option<String>,
    pub reason: String,
    pub state: ConflictState,
    pub created_at: String,
    pub resolved_at: Option<String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictState {
    Open,
    Resolved,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityEntry {
    pub id: String,
    pub at: String,
    pub kind: String,
    pub message: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthStatus {
    state: String,
    npub: Option<String>,
    signer: String,
    capabilities: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct DaemonStatus {
    state: String,
    sync_mode: String,
    last_started_at: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct SyncStatus {
    mode: String,
    status: String,
    latest_sequence: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct SyncOnceReport {
    status: String,
    latest_sequence: u64,
    record_count: usize,
    server_url: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusReport {
    vault_id: Option<String>,
    working_tree_path: Option<String>,
    auth: AuthStatus,
    daemon: DaemonStatus,
    sync: SyncStatus,
    unlocked_folders: Vec<UnlockedFolder>,
    conflicts: Vec<ConflictEntry>,
    blocked: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CheckState {
    state: String,
    message: String,
}

impl CheckState {
    fn ok(message: impl Into<String>) -> Self {
        Self {
            state: "ok".to_owned(),
            message: message.into(),
        }
    }

    fn warn(message: impl Into<String>) -> Self {
        Self {
            state: "warn".to_owned(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct HealthCheck {
    state: String,
    message: String,
}

impl HealthCheck {
    fn ok(message: impl Into<String>) -> Self {
        Self {
            state: "ok".to_owned(),
            message: message.into(),
        }
    }

    fn warn(message: impl Into<String>) -> Self {
        Self {
            state: "warn".to_owned(),
            message: message.into(),
        }
    }

    fn skipped(message: impl Into<String>) -> Self {
        Self {
            state: "skipped".to_owned(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct DoctorReport {
    cli: CheckState,
    auth: CheckState,
    working_tree: CheckState,
    daemon: CheckState,
    server: HealthCheck,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct AccessExplanation {
    folder: String,
    state: String,
    reason: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct HttpResponse {
    status: u16,
    body: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultMetadataView {
    vault_id: String,
    kind: String,
    name: String,
    owner_user_id: Option<String>,
    members: Vec<String>,
    admins: Vec<String>,
    folders: Vec<FolderMetadataView>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FolderMetadataView {
    id: String,
    name: String,
    access: String,
    path: String,
    access_user_ids: Vec<String>,
    current_key_version: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use tempfile::TempDir;

    fn env_for(tmp: &TempDir) -> CliEnvironment {
        CliEnvironment {
            cwd: tmp.path().to_path_buf(),
            config_dir: tmp.path().join("config"),
            now: Some("2026-06-24T20:46:36Z".to_owned()),
        }
    }

    fn run(tmp: &TempDir, args: &[&str]) -> String {
        let mut output = Vec::new();
        run_with_env(args.iter().copied(), env_for(tmp), &mut output).unwrap();
        String::from_utf8(output).unwrap()
    }

    #[test]
    fn auth_login_status_and_logout_are_stateful() {
        let tmp = TempDir::new().unwrap();
        let output = run(
            &tmp,
            &[
                "auth",
                "login",
                "--nsec",
                "0000000000000000000000000000000000000000000000000000000000000001",
                "--json",
            ],
        );
        let json: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(json["state"], "authenticated");
        assert_eq!(json["signer"], "local-nostr-keypair");
        assert!(json["npub"].as_str().unwrap().starts_with("npub"));

        let status = run(&tmp, &["auth", "status", "--json"]);
        let json: Value = serde_json::from_str(&status).unwrap();
        assert_eq!(json["capabilities"][1], "signEvent");

        assert_eq!(run(&tmp, &["auth", "logout"]).trim(), "logged out");
        let status = run(&tmp, &["auth", "status", "--json"]);
        let json: Value = serde_json::from_str(&status).unwrap();
        assert_eq!(json["state"], "missing");
    }

    #[test]
    fn open_creates_working_tree_and_status_json() {
        let tmp = TempDir::new().unwrap();
        run(
            &tmp,
            &[
                "auth",
                "login",
                "--nsec",
                "0000000000000000000000000000000000000000000000000000000000000001",
            ],
        );
        let tree = tmp.path().join("agent-vault");
        let output = run(
            &tmp,
            &[
                "open",
                "agent-vault",
                tree.to_str().unwrap(),
                "--server",
                "http://127.0.0.1:3015",
                "--json",
            ],
        );
        let json: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(json["vaultId"], "agent-vault");
        assert_eq!(json["daemon"], "running");
        assert!(tree.join(".finitebrain/vault-directory.json").exists());
        assert!(tree.join(".finitebrain/working-tree-state.json").exists());
        assert!(tree.join(".finitebrain/agent-state.json").exists());

        let mut env = env_for(&tmp);
        env.cwd = tree;
        let mut output = Vec::new();
        run_with_env(["status", "--json"], env, &mut output).unwrap();
        let json: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(json["vaultId"], "agent-vault");
        assert_eq!(json["auth"]["state"], "authenticated");
        assert_eq!(json["daemon"]["state"], "running");
        assert_eq!(json["sync"]["mode"], "automatic");
    }

    #[test]
    fn daemon_unlock_conflicts_activity_and_access_commands_use_agent_state() {
        let tmp = TempDir::new().unwrap();
        let tree = tmp.path().join("vault");
        run(&tmp, &["open", "vault", tree.to_str().unwrap()]);
        let roots = VaultWorkingTreeStateManifest {
            version: WORKING_TREE_STATE_VERSION.to_owned(),
            folder_roots: vec![
                WorkingTreeFolderRoot {
                    folder_id: "general".to_owned(),
                    path: "General".to_owned(),
                    can_read: true,
                    metadata_only: false,
                },
                WorkingTreeFolderRoot {
                    folder_id: "locked".to_owned(),
                    path: "Locked".to_owned(),
                    can_read: false,
                    metadata_only: true,
                },
            ],
            objects: Vec::new(),
            sync: WorkingTreeSyncState { latest_sequence: 7 },
        };
        write_json_file(&tree.join(".finitebrain/working-tree-state.json"), &roots).unwrap();

        let mut env = env_for(&tmp);
        env.cwd = tree.clone();
        let mut output = Vec::new();
        run_with_env(["daemon", "stop"], env.clone(), &mut output).unwrap();
        assert!(String::from_utf8(output).unwrap().contains("stopped"));

        let mut output = Vec::new();
        run_with_env(["daemon", "start", "--json"], env.clone(), &mut output).unwrap();
        let json: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(json["state"], "running");

        let mut output = Vec::new();
        run_with_env(["unlock", "--all", "--json"], env.clone(), &mut output).unwrap();
        let json: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(json["opened"][0], "general");

        let mut state = read_agent_state(&tree).unwrap();
        state.conflicts.push(ConflictEntry {
            id: "conflict-1".to_owned(),
            folder_id: Some("general".to_owned()),
            path: Some("General/page.md".to_owned()),
            reason: "baseRevision does not match current folder object revision".to_owned(),
            state: ConflictState::Open,
            created_at: "2026-06-24T20:46:36Z".to_owned(),
            resolved_at: None,
        });
        write_agent_state(&tree, &state).unwrap();

        let mut output = Vec::new();
        run_with_env(["conflicts", "--json"], env.clone(), &mut output).unwrap();
        let json: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(json[0]["id"], "conflict-1");

        let mut output = Vec::new();
        run_with_env(["resolve", "conflict-1"], env.clone(), &mut output).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap().trim(),
            "resolved conflict-1"
        );

        let mut output = Vec::new();
        run_with_env(
            ["access", "explain", "Locked", "--json"],
            env.clone(),
            &mut output,
        )
        .unwrap();
        let json: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(json["state"], "locked");

        let mut output = Vec::new();
        run_with_env(["activity"], env, &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("working_tree.opened"));
    }

    #[test]
    fn doctor_reports_missing_working_tree_without_failing() {
        let tmp = TempDir::new().unwrap();
        let output = run(&tmp, &["doctor", "--json"]);
        let json: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(json["cli"]["state"], "ok");
        assert_eq!(json["auth"]["state"], "warn");
        assert_eq!(json["workingTree"]["state"], "warn");
    }

    #[test]
    fn signer_sign_encrypt_and_decrypt_behaves_like_local_nip07() {
        let tmp = TempDir::new().unwrap();
        run(
            &tmp,
            &[
                "auth",
                "login",
                "--nsec",
                "0000000000000000000000000000000000000000000000000000000000000001",
            ],
        );

        let public_key = run(&tmp, &["signer", "public-key"]);
        assert!(public_key.trim().starts_with("npub"));

        let signed = run(
            &tmp,
            &[
                "signer",
                "sign",
                "--kind",
                "text",
                "--content",
                "hello finite",
                "--json",
            ],
        );
        let json: Value = serde_json::from_str(&signed).unwrap();
        assert_eq!(json["event"]["kind"], 1);
        assert_eq!(json["event"]["content"], "hello finite");

        let encrypted = run(
            &tmp,
            &[
                "signer",
                "encrypt",
                "--to",
                public_key.trim(),
                "--text",
                "folder secret",
                "--json",
            ],
        );
        let encrypted: Value = serde_json::from_str(&encrypted).unwrap();
        let decrypted = run(
            &tmp,
            &[
                "signer",
                "decrypt",
                "--from",
                public_key.trim(),
                "--payload",
                encrypted["ciphertext"].as_str().unwrap(),
                "--json",
            ],
        );
        let decrypted: Value = serde_json::from_str(&decrypted).unwrap();
        assert_eq!(decrypted["plaintext"], "folder secret");
    }

    #[test]
    fn signed_http_auth_header_validates_against_finite_nostr() {
        let keys = Keys::parse("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap();
        let body = br#"{"vaultId":"agent"}"#;
        let url = "http://127.0.0.1:3015/_admin/vaults";
        let header = signed_http_auth_header(&keys, "POST", url, Some(body)).unwrap();
        let encoded = header.strip_prefix("Nostr ").unwrap();
        let event_json = String::from_utf8(BASE64_STANDARD.decode(encoded).unwrap()).unwrap();
        let event = nostr::Event::from_json(event_json).unwrap();
        let expected = finite_nostr::HttpAuthValidation::new("POST", url, unix_timestamp(), 60)
            .with_body(body.to_vec());

        let signer = finite_nostr::validate_http_auth_event(&event, &expected).unwrap();

        assert_eq!(signer, NostrPublicKey::from_protocol(keys.public_key()));
    }

    #[test]
    fn management_parser_uses_current_vault_not_target_positional() {
        let tmp = TempDir::new().unwrap();
        let tree = tmp.path().join("vault");
        run(&tmp, &["open", "agent-vault", tree.to_str().unwrap()]);

        let mut env = env_for(&tmp);
        env.cwd = tree;
        let args = vec!["add-member".to_owned(), "npub-target".to_owned()];

        assert_eq!(command_vault_id(&args, &env).unwrap(), "agent-vault");
    }

    #[test]
    fn folder_required_recipients_follow_access_mode() {
        let metadata = VaultMetadataView {
            vault_id: "org".to_owned(),
            kind: "organization".to_owned(),
            name: "Org".to_owned(),
            owner_user_id: None,
            members: vec!["npub-member".to_owned()],
            admins: vec!["npub-admin".to_owned()],
            folders: Vec::new(),
        };

        assert_eq!(
            folder_required_recipients(&metadata, "restricted", &["npub-member".to_owned()])
                .unwrap(),
            vec!["npub-admin".to_owned(), "npub-member".to_owned()]
        );
        assert_eq!(
            folder_required_recipients(&metadata, "admin_only", &[]).unwrap(),
            vec!["npub-admin".to_owned()]
        );
    }
}
