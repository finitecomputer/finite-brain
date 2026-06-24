//! Agent-native FiniteBrain CLI surface.

mod admin;
mod args;
mod clock;
mod environment;
mod error;
mod http;
mod models;
mod output;
mod signer;
mod state;

pub use environment::CliEnvironment;
pub use error::CliError;
pub use models::{ActivityEntry, ConflictEntry, ConflictState, UnlockedFolder};

pub(crate) use admin::*;
pub(crate) use args::*;
pub(crate) use clock::*;
pub(crate) use http::*;
pub(crate) use models::*;
pub(crate) use output::*;
pub(crate) use signer::*;
pub(crate) use state::*;

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use finite_brain_core::portability::{
    VaultDirectoryManifest, VaultDirectoryPath, VaultDirectoryPortability,
    VaultDirectoryVaultSummary, VaultWorkingTreeStateManifest, WorkingTreeFolderRoot,
    WorkingTreeObjectManifestEntry, WorkingTreeSyncState,
};
use finite_brain_core::{AdminAccessAction, FolderKey};
use finite_nostr::{NostrPublicKey, decrypt_nip44, encrypt_nip44};
use nostr::Kind;

pub(crate) const AUTH_VERSION: &str = "finitebrain-agent-auth-v1";
pub(crate) const AGENT_STATE_VERSION: &str = "finitebrain-agent-state-v1";
pub(crate) const VAULT_DIRECTORY_VERSION: &str = "finite-vault-directory-v1";
pub(crate) const WORKING_TREE_STATE_VERSION: &str = "finite-vault-working-tree-state-v1";
pub(crate) const APP_SPECIFIC_KIND: u16 = 30_078;

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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use finite_nostr::NostrPublicKey;
    use nostr::Keys;
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
