use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use finite_brain_core::portability::{
    OkfOmittedFolder, OpenedPage, WorkingTreeChange, WorkingTreeChangeIntent,
    WorkingTreeFolderRoot, WorkingTreeIntentAction, WorkingTreeIntentRoute,
    WorkingTreeMaterializeInput, WorkingTreeObjectManifestEntry, WorkingTreeProjection,
    materialize_vault_working_tree, plan_working_tree_change_intents,
};
use finite_brain_core::{
    DisplayName, EncryptedFolderObjectEnvelope, Folder, FolderAccessMode, FolderId, FolderKey,
    FolderObjectAad, FolderObjectOperation, FolderObjectRevisionPayload, FolderRole, ObjectId,
    RevisionValidation, SafeRelativePath, TombstoneValidation, UserId, Vault, VaultId, VaultKind,
    encrypt_folder_object, open_folder_object, sha256_hex,
};
use finite_nostr::{GiftWrapValidation, NostrPublicKey, open_gift_wrap};
use nostr::{Event, Keys, Kind, Tag};
use serde::Deserialize;

use crate::{
    APP_SPECIFIC_KIND, AgentState, CliEnvironment, CliError, ConflictEntry, ConflictState,
    LocalFolderKey, SyncOnceReport, UnlockedFolder, current_tree_root, deterministic_id,
    read_agent_state, read_auth_required, read_working_tree_state, server_url_for_command,
    sign_event, signed_json_request_to_server, tag_vec, timestamp, timestamp_from_unix,
    unix_timestamp, write_agent_state, write_json_file,
};

const CIPHER_AES_256_GCM: &str = "AES-256-GCM";
const FOLDER_OBJECT_PAGE_VERSION: &str = "finite-folder-object-page-v1";

pub(crate) fn run_working_tree_sync(
    env: &CliEnvironment,
    args: &[String],
    activity_kind: &str,
) -> Result<SyncOnceReport, CliError> {
    let root = current_tree_root(env)?;
    let agent_state = read_agent_state(&root)?;
    let server_url = server_url_for_command(env, args)?;
    let auth = read_auth_required(env)?;
    let export = fetch_encrypted_export(env, &server_url, &agent_state.vault_id)?;
    let opened_grants = open_export_folder_key_grants(env, &root, &auth, &export)?;
    let local_result = push_local_working_tree_changes(env, &root, &server_url, &agent_state)?;
    let bootstrap = fetch_sync_bootstrap(env, &server_url, &agent_state.vault_id)?;
    write_sync_evidence(&root, &export, &bootstrap)?;

    materialize_remote_projection(
        env,
        &root,
        &auth.npub,
        &export,
        &bootstrap,
        &local_result.path_overrides,
    )?;
    restore_conflicted_markdown(&root, &local_result.conflicted_markdown)?;

    let latest_sequence = bootstrap.latest_sequence;
    let remote_count = bootstrap
        .objects
        .iter()
        .filter(|object| !object.deleted)
        .count();
    let status = if local_result.conflict_count > 0 {
        "blocked-local-conflicts".to_owned()
    } else if local_result.pushed_count > 0 {
        "pushed-local-changes".to_owned()
    } else if remote_count > 0 || opened_grants > 0 {
        "applied-remote-records".to_owned()
    } else {
        "caught-up".to_owned()
    };

    mutate_agent_state_at_root(&root, timestamp(env), |state, now| {
        state.sync.status = status.clone();
        state.add_activity(
            now,
            activity_kind,
            format!(
                "Sync latest sequence {latest_sequence}; openedGrants={opened_grants}; pushed={}; conflicts={}",
                local_result.pushed_count, local_result.conflict_count
            ),
        );
    })?;

    Ok(SyncOnceReport {
        status,
        latest_sequence,
        record_count: remote_count + local_result.pushed_count,
        server_url,
    })
}

fn fetch_encrypted_export(
    env: &CliEnvironment,
    server_url: &str,
    vault_id: &str,
) -> Result<CliEncryptedVaultExport, CliError> {
    let path = format!("/_admin/vaults/{vault_id}/export");
    let response = signed_json_request_to_server(env, server_url, "GET", &path, None)?;
    serde_json::from_value(response).map_err(CliError::from)
}

fn fetch_sync_bootstrap(
    env: &CliEnvironment,
    server_url: &str,
    vault_id: &str,
) -> Result<CliSyncBootstrap, CliError> {
    let path = format!("/_admin/vaults/{vault_id}/sync/bootstrap");
    let response = signed_json_request_to_server(env, server_url, "GET", &path, None)?;
    serde_json::from_value(response).map_err(CliError::from)
}

fn write_sync_evidence(
    root: &Path,
    export: &CliEncryptedVaultExport,
    bootstrap: &CliSyncBootstrap,
) -> Result<(), CliError> {
    let sync_dir = root.join(".finitebrain/encrypted-sync");
    fs::create_dir_all(&sync_dir)?;
    write_json_file(&sync_dir.join("export.json"), export)?;
    write_json_file(&sync_dir.join("bootstrap.json"), bootstrap)?;
    Ok(())
}

fn restore_conflicted_markdown(
    root: &Path,
    conflicted_markdown: &BTreeMap<String, String>,
) -> Result<(), CliError> {
    for (relative_path, markdown) in conflicted_markdown {
        let path = root.join(relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, markdown)?;
    }
    Ok(())
}

fn open_export_folder_key_grants(
    env: &CliEnvironment,
    root: &Path,
    auth: &crate::PrototypeAuth,
    export: &CliEncryptedVaultExport,
) -> Result<usize, CliError> {
    let keys = Keys::parse(&auth.secret_key)
        .map_err(|error| CliError::InvalidSigner(error.to_string()))?;
    let recipient = NostrPublicKey::parse(&auth.npub)
        .map_err(|error| CliError::InvalidSigner(error.to_string()))?;
    let validation = GiftWrapValidation::new(recipient);
    let mut opened = Vec::new();
    for grant in &export.key_grants {
        if grant.recipient_npub != auth.npub {
            continue;
        }
        let Ok(event) = Event::from_json(grant.wrapped_event_json.clone()) else {
            continue;
        };
        let Ok(opened_wrap) = open_gift_wrap(&keys, &event, &validation) else {
            continue;
        };
        let Ok(plaintext) =
            serde_json::from_str::<CliFolderKeyGrantPlaintext>(&opened_wrap.rumor.content)
        else {
            continue;
        };
        if plaintext.version != "finite-folder-key-grant-v1"
            || plaintext.vault_id != export.vault.id
            || plaintext.folder_id != grant.folder_id
            || plaintext.key_version != grant.key_version
            || plaintext.recipient_npub != auth.npub
        {
            continue;
        }
        FolderKey::from_base64(&plaintext.folder_key)
            .map_err(|error| CliError::InvalidInput(error.to_string()))?;
        opened.push(plaintext);
    }

    if opened.is_empty() {
        return Ok(0);
    }

    let opened_count = opened.len();
    mutate_agent_state_at_root(root, timestamp(env), |state, now| {
        for grant in opened {
            if !state
                .local_folder_keys
                .iter()
                .any(|key| key.folder_id == grant.folder_id && key.key_version == grant.key_version)
            {
                state.local_folder_keys.push(LocalFolderKey {
                    folder_id: grant.folder_id.clone(),
                    key_version: grant.key_version,
                    key_base64: grant.folder_key.clone(),
                    source: format!("folder-key-grant:{}", grant.issuer_npub),
                    opened_at: now.clone(),
                });
            }
            if !state
                .unlocked_folders
                .iter()
                .any(|folder| folder.folder_id == grant.folder_id)
            {
                state.unlocked_folders.push(UnlockedFolder {
                    folder_id: grant.folder_id,
                    key_version: grant.key_version,
                    opened_at: now.clone(),
                    source: "folder-key-grant".to_owned(),
                });
            }
        }
        state.add_activity(now, "folder_keys.opened", "Folder Key Grants opened");
    })?;
    Ok(opened_count)
}

fn push_local_working_tree_changes(
    env: &CliEnvironment,
    root: &Path,
    server_url: &str,
    agent_state: &AgentState,
) -> Result<LocalSyncResult, CliError> {
    let tree_state = read_working_tree_state(root)?;
    let changes = scan_working_tree_changes(root, &tree_state)?;
    if changes.is_empty() {
        return Ok(LocalSyncResult::default());
    }

    let intents = plan_working_tree_change_intents(&tree_state, &changes);
    let keys_by_folder = read_agent_state(root)?
        .local_folder_keys
        .into_iter()
        .map(|key| ((key.folder_id.clone(), key.key_version), key))
        .collect::<BTreeMap<_, _>>();
    let latest_key_by_folder = latest_local_key_by_folder(&keys_by_folder);
    let signing_keys = Keys::parse(&read_auth_required(env)?.secret_key)
        .map_err(|error| CliError::InvalidSigner(error.to_string()))?;
    let actor_npub = NostrPublicKey::from_protocol(signing_keys.public_key())
        .to_npub()
        .map_err(|error| CliError::InvalidSigner(error.to_string()))?;

    let submit_context = SubmitIntentContext {
        env,
        server_url,
        agent_state,
        signing_keys: &signing_keys,
        actor_npub: &actor_npub,
        keys_by_folder: &keys_by_folder,
        latest_key_by_folder: &latest_key_by_folder,
    };
    let mut result = LocalSyncResult::default();
    let mut conflicts = Vec::new();
    for (change, intent) in changes.iter().zip(intents.iter()) {
        match submit_change_intent(&submit_context, intent) {
            Ok(SubmitIntentOutcome::Submitted) => {
                result.pushed_count += 1;
                if let (Some(folder_id), Some(object_id), Some(target_path)) = (
                    intent.folder_id.as_ref(),
                    intent.object_id.as_ref(),
                    intent.target_path.as_ref(),
                ) {
                    result.path_overrides.insert(
                        (folder_id.to_string(), object_id.as_str().to_owned()),
                        target_path.to_string(),
                    );
                }
            }
            Ok(SubmitIntentOutcome::Conflict(reason)) => {
                result.conflict_count += 1;
                preserve_conflicted_markdown(&mut result, change);
                conflicts.push(conflict_for_change(change, intent, reason, timestamp(env)));
            }
            Err(error) if is_http_conflict(&error) => {
                result.conflict_count += 1;
                preserve_conflicted_markdown(&mut result, change);
                conflicts.push(conflict_for_change(
                    change,
                    intent,
                    error.to_string(),
                    timestamp(env),
                ));
            }
            Err(error) => return Err(error),
        }
    }

    if !conflicts.is_empty() {
        mutate_agent_state_at_root(root, timestamp(env), |state, now| {
            for conflict in conflicts {
                if !state.conflicts.iter().any(|existing| {
                    existing.id == conflict.id && existing.state == ConflictState::Open
                }) {
                    state.conflicts.push(conflict);
                }
            }
            state.add_activity(now, "sync.blocked", "Local working-tree conflicts recorded");
        })?;
    }

    Ok(result)
}

struct SubmitIntentContext<'a> {
    env: &'a CliEnvironment,
    server_url: &'a str,
    agent_state: &'a AgentState,
    signing_keys: &'a Keys,
    actor_npub: &'a str,
    keys_by_folder: &'a BTreeMap<(String, u32), LocalFolderKey>,
    latest_key_by_folder: &'a BTreeMap<String, LocalFolderKey>,
}

fn submit_change_intent(
    context: &SubmitIntentContext<'_>,
    intent: &WorkingTreeChangeIntent,
) -> Result<SubmitIntentOutcome, CliError> {
    if intent.route == WorkingTreeIntentRoute::Unresolved
        || intent.action == WorkingTreeIntentAction::Unresolved
    {
        return Ok(SubmitIntentOutcome::Conflict(
            intent
                .reason
                .clone()
                .unwrap_or_else(|| "working-tree change could not be mapped".to_owned()),
        ));
    }

    let folder_id = intent
        .folder_id
        .as_ref()
        .ok_or_else(|| CliError::InvalidInput("missing intent folder id".to_owned()))?;
    let object_id = intent
        .object_id
        .as_ref()
        .ok_or_else(|| CliError::InvalidInput("missing intent object id".to_owned()))?;

    match intent.action {
        WorkingTreeIntentAction::Create
        | WorkingTreeIntentAction::Update
        | WorkingTreeIntentAction::Move => {
            let markdown = intent.markdown.as_deref().ok_or_else(|| {
                CliError::InvalidInput("write intent is missing markdown".to_owned())
            })?;
            let target_path = intent.target_path.as_ref().ok_or_else(|| {
                CliError::InvalidInput("write intent is missing target path".to_owned())
            })?;
            let local_key = intent
                .base_revision
                .and_then(|_| {
                    key_for_existing_object(context.keys_by_folder, folder_id.as_str(), intent)
                })
                .or_else(|| {
                    context
                        .latest_key_by_folder
                        .get(folder_id.as_str())
                        .cloned()
                })
                .ok_or_else(|| {
                    CliError::InvalidInput(format!("no local Folder Key for {folder_id}"))
                })?;
            let key = FolderKey::from_base64(&local_key.key_base64)
                .map_err(|error| CliError::InvalidInput(error.to_string()))?;
            let aad = FolderObjectAad {
                vault_id: VaultId::new(context.agent_state.vault_id.clone())
                    .map_err(|error| CliError::InvalidInput(error.to_string()))?,
                folder_id: folder_id.clone(),
                object_id: object_id.clone(),
                key_version: local_key.key_version,
            };
            let plaintext = encode_folder_object_page_plaintext(target_path, markdown)?;
            let envelope = encrypt_folder_object(&key, &aad, &plaintext)
                .map_err(|error| CliError::InvalidInput(error.to_string()))?;
            let envelope_json = envelope.canonical_json();
            let operation = match intent.action {
                WorkingTreeIntentAction::Create => FolderObjectOperation::Create,
                WorkingTreeIntentAction::Update => FolderObjectOperation::Update,
                WorkingTreeIntentAction::Move => FolderObjectOperation::Move,
                _ => unreachable!("handled above"),
            };
            let event = signed_revision_event(
                context.signing_keys,
                RevisionEventInput {
                    actor_npub: context.actor_npub,
                    vault_id: &context.agent_state.vault_id,
                    folder_id,
                    object_id,
                    operation,
                    base_revision: intent.base_revision,
                    key_version: local_key.key_version,
                    envelope_json: envelope_json.clone(),
                },
            )?;
            let body = serde_json::json!({
                "baseRevision": intent.base_revision,
                "keyVersion": local_key.key_version,
                "cipher": CIPHER_AES_256_GCM,
                "ciphertext": envelope_json,
                "revisionEvent": event
            });
            let route = match intent.action {
                WorkingTreeIntentAction::Move => format!(
                    "/_admin/vaults/{}/folders/{}/objects/{}/move",
                    context.agent_state.vault_id,
                    folder_id,
                    object_id.as_str()
                ),
                _ => format!(
                    "/_admin/vaults/{}/folders/{}/objects/{}",
                    context.agent_state.vault_id,
                    folder_id,
                    object_id.as_str()
                ),
            };
            signed_json_request_to_server(
                context.env,
                context.server_url,
                if intent.action == WorkingTreeIntentAction::Move {
                    "POST"
                } else {
                    "PUT"
                },
                &route,
                Some(body),
            )?;
            Ok(SubmitIntentOutcome::Submitted)
        }
        WorkingTreeIntentAction::Delete => {
            let base_revision = intent.base_revision.ok_or_else(|| {
                CliError::InvalidInput("delete intent is missing base revision".to_owned())
            })?;
            let event = signed_tombstone_event(
                context.signing_keys,
                context.actor_npub,
                &context.agent_state.vault_id,
                folder_id,
                object_id,
                base_revision,
            )?;
            let body = serde_json::json!({
                "baseRevision": base_revision,
                "tombstoneEvent": event
            });
            let route = format!(
                "/_admin/vaults/{}/folders/{}/objects/{}",
                context.agent_state.vault_id,
                folder_id,
                object_id.as_str()
            );
            signed_json_request_to_server(
                context.env,
                context.server_url,
                "DELETE",
                &route,
                Some(body),
            )?;
            Ok(SubmitIntentOutcome::Submitted)
        }
        WorkingTreeIntentAction::Unresolved => Ok(SubmitIntentOutcome::Conflict(
            intent
                .reason
                .clone()
                .unwrap_or_else(|| "working-tree change could not be mapped".to_owned()),
        )),
    }
}

struct RevisionEventInput<'a> {
    actor_npub: &'a str,
    vault_id: &'a str,
    folder_id: &'a FolderId,
    object_id: &'a ObjectId,
    operation: FolderObjectOperation,
    base_revision: Option<u64>,
    key_version: u32,
    envelope_json: String,
}

fn signed_revision_event(
    keys: &Keys,
    input: RevisionEventInput<'_>,
) -> Result<serde_json::Value, CliError> {
    let created_at_unix = unix_timestamp();
    let expected = RevisionValidation {
        vault_id: VaultId::new(input.vault_id.to_owned())
            .map_err(|error| CliError::InvalidInput(error.to_string()))?,
        folder_id: input.folder_id.clone(),
        object_id: input.object_id.clone(),
        operation: input.operation,
        revision: input.base_revision.map_or(1, |base| base + 1),
        base_revision: input.base_revision,
        key_version: input.key_version,
        envelope_json: input.envelope_json,
        author_npub: input.actor_npub.to_owned(),
        created_at: timestamp_from_unix(created_at_unix),
    };
    let payload = FolderObjectRevisionPayload::new(&expected);
    let event = sign_event(
        keys,
        Kind::Custom(APP_SPECIFIC_KIND),
        payload.canonical_json(),
        revision_tags(&expected)?,
        created_at_unix,
        Some("folder-object-revision"),
    )?;
    serde_json::from_str(&event.as_json()).map_err(CliError::from)
}

fn signed_tombstone_event(
    keys: &Keys,
    actor_npub: &str,
    vault_id: &str,
    folder_id: &FolderId,
    object_id: &ObjectId,
    base_revision: u64,
) -> Result<serde_json::Value, CliError> {
    let created_at_unix = unix_timestamp();
    let expected = TombstoneValidation {
        vault_id: VaultId::new(vault_id.to_owned())
            .map_err(|error| CliError::InvalidInput(error.to_string()))?,
        folder_id: folder_id.clone(),
        object_id: object_id.clone(),
        revision: base_revision + 1,
        base_revision,
        author_npub: actor_npub.to_owned(),
        deleted_at: timestamp_from_unix(created_at_unix),
    };
    let payload = finite_brain_core::FolderObjectTombstonePayload::new(&expected);
    let event = sign_event(
        keys,
        Kind::Custom(APP_SPECIFIC_KIND),
        payload.canonical_json(),
        tombstone_tags(&expected)?,
        created_at_unix,
        Some("folder-object-tombstone"),
    )?;
    serde_json::from_str(&event.as_json()).map_err(CliError::from)
}

fn revision_tags(input: &RevisionValidation) -> Result<Vec<Tag>, CliError> {
    Ok(vec![
        tag_vec([
            "d",
            &format!(
                "finite-folder-object-revision:{}:{}:{}:{}",
                input.vault_id,
                input.folder_id,
                input.object_id.as_str(),
                input.revision
            ),
        ])?,
        tag_vec(["vault", &input.vault_id.to_string()])?,
        tag_vec(["folder", &input.folder_id.to_string()])?,
        tag_vec(["object", input.object_id.as_str()])?,
        tag_vec(["operation", input.operation.as_str()])?,
        tag_vec(["keyVersion", &input.key_version.to_string()])?,
    ])
}

fn tombstone_tags(input: &TombstoneValidation) -> Result<Vec<Tag>, CliError> {
    Ok(vec![
        tag_vec([
            "d",
            &format!(
                "finite-folder-object-tombstone:{}:{}:{}:{}",
                input.vault_id,
                input.folder_id,
                input.object_id.as_str(),
                input.revision
            ),
        ])?,
        tag_vec(["vault", &input.vault_id.to_string()])?,
        tag_vec(["folder", &input.folder_id.to_string()])?,
        tag_vec(["object", input.object_id.as_str()])?,
        tag_vec(["operation", "delete"])?,
    ])
}

fn materialize_remote_projection(
    env: &CliEnvironment,
    root: &Path,
    actor_npub: &str,
    export: &CliEncryptedVaultExport,
    bootstrap: &CliSyncBootstrap,
    path_overrides: &BTreeMap<(String, String), String>,
) -> Result<(), CliError> {
    let prior_state = read_working_tree_state(root)?;
    let vault = vault_from_export(export)?;
    let local_keys = read_agent_state(root)?
        .local_folder_keys
        .into_iter()
        .map(|key| ((key.folder_id.clone(), key.key_version), key))
        .collect::<BTreeMap<_, _>>();
    let mut prior_paths = prior_state
        .objects
        .iter()
        .map(|entry| {
            (
                (entry.folder_id.clone(), entry.object_id.clone()),
                entry.path.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for (key, path) in path_overrides {
        prior_paths.insert(key.clone(), path.clone());
    }
    let mut opened_pages = Vec::new();
    let mut readable_folder_ids = BTreeSet::new();

    for object in bootstrap.objects.iter().filter(|object| !object.deleted) {
        let envelope = EncryptedFolderObjectEnvelope::from_json(&object.ciphertext)
            .map_err(|error| CliError::InvalidInput(error.to_string()))?;
        let Some(local_key) = local_keys.get(&(object.folder_id.clone(), envelope.key_version))
        else {
            continue;
        };
        let key = FolderKey::from_base64(&local_key.key_base64)
            .map_err(|error| CliError::InvalidInput(error.to_string()))?;
        let aad = FolderObjectAad {
            vault_id: VaultId::new(export.vault.id.clone())
                .map_err(|error| CliError::InvalidInput(error.to_string()))?,
            folder_id: FolderId::new(object.folder_id.clone())
                .map_err(|error| CliError::InvalidInput(error.to_string()))?,
            object_id: ObjectId::new(object.object_id.clone())
                .map_err(|error| CliError::InvalidInput(error.to_string()))?,
            key_version: envelope.key_version,
        };
        let plaintext = open_folder_object(&key, &aad, &envelope)
            .map_err(|error| CliError::InvalidInput(error.to_string()))?;
        let folder = export
            .folders
            .iter()
            .find(|folder| folder.id == object.folder_id)
            .ok_or_else(|| CliError::NotFound(format!("folder {}", object.folder_id)))?;
        let fallback_page_path = prior_paths
            .get(&(object.folder_id.clone(), object.object_id.clone()))
            .cloned()
            .unwrap_or_else(|| format!("{}.md", object.object_id));
        let (page_path, markdown) =
            decode_folder_object_page_plaintext(plaintext, fallback_page_path)?;
        readable_folder_ids.insert(object.folder_id.clone());
        opened_pages.push(OpenedPage {
            folder_id: FolderId::new(object.folder_id.clone())
                .map_err(|error| CliError::InvalidInput(error.to_string()))?,
            object_id: ObjectId::new(object.object_id.clone())
                .map_err(|error| CliError::InvalidInput(error.to_string()))?,
            folder_display_path: SafeRelativePath::new("folder_path", folder.path.clone())
                .map_err(|error| CliError::InvalidInput(error.to_string()))?,
            page_path: SafeRelativePath::new("page_path", page_path)
                .map_err(|error| CliError::InvalidInput(error.to_string()))?,
            markdown,
            revision: object.revision,
            key_version: envelope.key_version,
            content_type: "text/markdown".to_owned(),
        });
    }

    for folder in &export.folders {
        if local_keys.contains_key(&(folder.id.clone(), folder.current_key_version)) {
            readable_folder_ids.insert(folder.id.clone());
        }
    }

    let locked_folders = export
        .folders
        .iter()
        .filter(|folder| !readable_folder_ids.contains(&folder.id))
        .map(|folder| {
            Ok(OkfOmittedFolder {
                folder_id: FolderId::new(folder.id.clone())
                    .map_err(|error| CliError::InvalidInput(error.to_string()))?,
                display_path: SafeRelativePath::new("folder_path", folder.path.clone())
                    .map_err(|error| CliError::InvalidInput(error.to_string()))?,
                reason: if folder.accessible {
                    "missing-folder-key".to_owned()
                } else {
                    "no-folder-access".to_owned()
                },
            })
        })
        .collect::<Result<Vec<_>, CliError>>()?;

    let mut projection = materialize_vault_working_tree(WorkingTreeMaterializeInput {
        generated_at: timestamp(env),
        generated_by_npub: UserId::new(actor_npub.to_owned())
            .map_err(|error| CliError::InvalidInput(error.to_string()))?,
        vault,
        opened_pages,
        locked_folders,
        latest_sequence: bootstrap.latest_sequence,
    })
    .map_err(|error| CliError::InvalidInput(error.to_string()))?;
    add_empty_readable_folders(&mut projection, export, &readable_folder_ids)?;
    remove_stale_object_files(root, &prior_state.objects, &projection.state.objects)?;
    write_projection_files(root, &projection.files)?;
    Ok(())
}

fn add_empty_readable_folders(
    projection: &mut WorkingTreeProjection,
    export: &CliEncryptedVaultExport,
    readable_folder_ids: &BTreeSet<String>,
) -> Result<(), CliError> {
    let existing = projection
        .state
        .folder_roots
        .iter()
        .map(|root| root.folder_id.clone())
        .collect::<BTreeSet<_>>();
    for folder in export
        .folders
        .iter()
        .filter(|folder| readable_folder_ids.contains(&folder.id) && !existing.contains(&folder.id))
    {
        projection.state.folder_roots.push(WorkingTreeFolderRoot {
            folder_id: folder.id.clone(),
            path: folder.path.clone(),
            can_read: true,
            metadata_only: false,
        });
        projection.files.insert(
            format!("{}/AGENTS.md", folder.path),
            format!(
                "# Folder Agent Instructions\n\nFolder id: `{}`\n\nUse `raw/` for source captures, `compiled/` for curated wiki pages, and `output/` for generated artifacts.\n",
                folder.id
            ),
        );
        projection.files.insert(
            format!("{}/_index.md", folder.path),
            format!("# {}\n\n", folder.path),
        );
        projection.files.insert(
            format!("{}/_wiki/index.md", folder.path),
            format!(
                "# Folder Wiki\n\nFolder: {}\nReadable Pages: 0\n",
                folder.path
            ),
        );
        for convention in ["raw", "compiled", "output"] {
            projection.files.insert(
                format!("{}/{convention}/.keep", folder.path),
                format!(
                    "# {convention}\n\nAgent convention directory for Folder `{}`.\n",
                    folder.id
                ),
            );
        }
    }
    projection
        .state
        .folder_roots
        .sort_by(|left, right| left.path.cmp(&right.path));
    projection.files.insert(
        ".finitebrain/working-tree-state.json".to_owned(),
        serde_json::to_string_pretty(&projection.state)?,
    );
    Ok(())
}

fn vault_from_export(export: &CliEncryptedVaultExport) -> Result<Vault, CliError> {
    let kind = match export.vault.kind.as_str() {
        "personal" => VaultKind::Personal,
        "organization" => VaultKind::Organization,
        other => {
            return Err(CliError::InvalidInput(format!(
                "unknown vault kind {other}"
            )));
        }
    };
    Ok(Vault {
        id: VaultId::new(export.vault.id.clone())
            .map_err(|error| CliError::InvalidInput(error.to_string()))?,
        kind,
        name: DisplayName::new("vault_name", export.vault.name.clone())
            .map_err(|error| CliError::InvalidInput(error.to_string()))?,
        owner_user_id: export
            .vault
            .owner_user_id
            .clone()
            .map(UserId::new)
            .transpose()
            .map_err(|error| CliError::InvalidInput(error.to_string()))?,
        folders: export
            .folders
            .iter()
            .map(folder_from_export)
            .collect::<Result<Vec<_>, _>>()?,
        members: export
            .access_state
            .members
            .iter()
            .map(|member| {
                Ok(finite_brain_core::VaultMember {
                    user_id: UserId::new(member.clone())
                        .map_err(|error| CliError::InvalidInput(error.to_string()))?,
                    folder_access: BTreeSet::new(),
                })
            })
            .collect::<Result<Vec<_>, CliError>>()?,
        admins: export
            .access_state
            .admins
            .iter()
            .map(|admin| {
                UserId::new(admin.clone())
                    .map_err(|error| CliError::InvalidInput(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn folder_from_export(folder: &CliExportFolder) -> Result<Folder, CliError> {
    Ok(Folder {
        id: FolderId::new(folder.id.clone())
            .map_err(|error| CliError::InvalidInput(error.to_string()))?,
        name: DisplayName::new(
            "folder_name",
            folder
                .path
                .split('/')
                .next_back()
                .unwrap_or(folder.id.as_str())
                .to_owned(),
        )
        .map_err(|error| CliError::InvalidInput(error.to_string()))?,
        role: match folder.id.as_str() {
            "home" => FolderRole::PersonalHome,
            "vault-ops" => FolderRole::VaultOps,
            "general" => FolderRole::General,
            _ => FolderRole::Folder,
        },
        access: parse_folder_access(&folder.access)?,
        parent_folder_id: None,
        path: SafeRelativePath::new("folder_path", folder.path.clone())
            .map_err(|error| CliError::InvalidInput(error.to_string()))?,
        current_key_version: folder.current_key_version,
        shared_folder_source: folder.shared_folder_source,
    })
}

fn parse_folder_access(access: &str) -> Result<FolderAccessMode, CliError> {
    match access {
        "owner" => Ok(FolderAccessMode::Owner),
        "admin_only" => Ok(FolderAccessMode::AdminOnly),
        "all_members" => Ok(FolderAccessMode::AllMembers),
        "restricted" => Ok(FolderAccessMode::Restricted),
        other => Err(CliError::InvalidInput(format!(
            "unknown folder access mode {other}"
        ))),
    }
}

fn scan_working_tree_changes(
    root: &Path,
    state: &finite_brain_core::portability::VaultWorkingTreeStateManifest,
) -> Result<Vec<WorkingTreeChange>, CliError> {
    let mut changes = Vec::new();
    let known = state
        .objects
        .iter()
        .map(|object| {
            (
                format!(
                    "{}/{}",
                    folder_path_for_object(state, object).unwrap_or_default(),
                    object.path
                ),
                object,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut seen = BTreeSet::new();

    for folder in state.folder_roots.iter().filter(|folder| folder.can_read) {
        let folder_root = root.join(&folder.path);
        if !folder_root.exists() {
            continue;
        }
        let markdown_paths = collect_markdown_paths(root, &folder_root)?;
        for relative_path in markdown_paths {
            if is_generated_folder_file(&folder.path, &relative_path) {
                continue;
            }
            seen.insert(relative_path.clone());
            let body = fs::read_to_string(root.join(&relative_path))?;
            match known.get(&relative_path) {
                Some(object) if object.content_hash == sha256_hex(body.as_bytes()) => {}
                _ => changes.push(WorkingTreeChange::Upsert {
                    path: SafeRelativePath::new("change_path", relative_path)
                        .map_err(|error| CliError::InvalidInput(error.to_string()))?,
                    markdown: body,
                }),
            }
        }
    }

    for (relative_path, _) in known {
        if !seen.contains(&relative_path) && !root.join(&relative_path).exists() {
            changes.push(WorkingTreeChange::Delete {
                path: SafeRelativePath::new("change_path", relative_path)
                    .map_err(|error| CliError::InvalidInput(error.to_string()))?,
            });
        }
    }

    Ok(changes)
}

fn folder_path_for_object(
    state: &finite_brain_core::portability::VaultWorkingTreeStateManifest,
    object: &WorkingTreeObjectManifestEntry,
) -> Option<String> {
    state
        .folder_roots
        .iter()
        .find(|folder| folder.folder_id == object.folder_id)
        .map(|folder| folder.path.clone())
}

fn collect_markdown_paths(root: &Path, folder_root: &Path) -> Result<Vec<String>, CliError> {
    let mut paths = Vec::new();
    collect_markdown_paths_inner(root, folder_root, &mut paths)?;
    paths.sort();
    Ok(paths)
}

fn collect_markdown_paths_inner(
    root: &Path,
    directory: &Path,
    paths: &mut Vec<String>,
) -> Result<(), CliError> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_markdown_paths_inner(root, &path, paths)?;
        } else if file_type.is_file() && path.extension().is_some_and(|ext| ext == "md") {
            paths.push(relative_path_string(root, &path)?);
        }
    }
    Ok(())
}

fn relative_path_string(root: &Path, path: &Path) -> Result<String, CliError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|error| CliError::InvalidInput(error.to_string()))?;
    Ok(relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join("/"))
}

fn is_generated_folder_file(folder_path: &str, relative_path: &str) -> bool {
    let Some(local) = relative_path
        .strip_prefix(folder_path)
        .and_then(|rest| rest.strip_prefix('/'))
    else {
        return true;
    };
    local == "AGENTS.md" || local == "_index.md" || local.starts_with("_wiki/")
}

fn remove_stale_object_files(
    root: &Path,
    old_objects: &[WorkingTreeObjectManifestEntry],
    new_objects: &[WorkingTreeObjectManifestEntry],
) -> Result<(), CliError> {
    let new_paths = new_objects
        .iter()
        .map(|object| {
            (
                (object.folder_id.clone(), object.object_id.clone()),
                object.path.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for old in old_objects {
        let key = (old.folder_id.clone(), old.object_id.clone());
        let should_remove = match new_paths.get(&key) {
            Some(new_path) => new_path != &old.path,
            None => true,
        };
        if !should_remove {
            continue;
        }
        let Some(folder_path) = folder_path_for_removed_object(root, old)? else {
            continue;
        };
        let path = root.join(folder_path).join(&old.path);
        if path.exists() {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

fn folder_path_for_removed_object(
    root: &Path,
    object: &WorkingTreeObjectManifestEntry,
) -> Result<Option<PathBuf>, CliError> {
    let state = read_working_tree_state(root)?;
    Ok(state
        .folder_roots
        .iter()
        .find(|folder| folder.folder_id == object.folder_id)
        .map(|folder| PathBuf::from(&folder.path)))
}

fn write_projection_files(root: &Path, files: &BTreeMap<String, String>) -> Result<(), CliError> {
    for (relative_path, body) in files {
        let path = root.join(relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, body)?;
    }
    Ok(())
}

fn latest_local_key_by_folder(
    keys_by_folder: &BTreeMap<(String, u32), LocalFolderKey>,
) -> BTreeMap<String, LocalFolderKey> {
    let mut latest = BTreeMap::new();
    for ((folder_id, _), key) in keys_by_folder {
        let replace = latest
            .get(folder_id)
            .is_none_or(|existing: &LocalFolderKey| key.key_version > existing.key_version);
        if replace {
            latest.insert(folder_id.clone(), key.clone());
        }
    }
    latest
}

fn key_for_existing_object(
    keys_by_folder: &BTreeMap<(String, u32), LocalFolderKey>,
    folder_id: &str,
    intent: &WorkingTreeChangeIntent,
) -> Option<LocalFolderKey> {
    keys_by_folder
        .iter()
        .filter(|((key_folder_id, _), _)| key_folder_id == folder_id)
        .filter(|((_, key_version), _)| intent.base_revision.is_some_and(|_| *key_version > 0))
        .max_by_key(|((_, key_version), _)| *key_version)
        .map(|(_, key)| key.clone())
}

fn conflict_for_change(
    change: &WorkingTreeChange,
    intent: &WorkingTreeChangeIntent,
    reason: String,
    created_at: String,
) -> ConflictEntry {
    let path = match change {
        WorkingTreeChange::Upsert { path, .. } | WorkingTreeChange::Delete { path } => {
            Some(path.to_string())
        }
        WorkingTreeChange::Rename { from_path, to_path } => {
            Some(format!("{from_path} -> {to_path}"))
        }
    };
    let folder_id = intent.folder_id.as_ref().map(ToString::to_string);
    let id = deterministic_id(
        "conflict",
        &[
            folder_id.as_deref().unwrap_or("-"),
            path.as_deref().unwrap_or("-"),
            &reason,
        ],
    );
    ConflictEntry {
        id,
        folder_id,
        path,
        reason,
        state: ConflictState::Open,
        created_at,
        resolved_at: None,
    }
}

fn is_http_conflict(error: &CliError) -> bool {
    matches!(error, CliError::Http(message) if message.contains("409"))
}

fn mutate_agent_state_at_root<F>(root: &Path, now: String, f: F) -> Result<(), CliError>
where
    F: FnOnce(&mut AgentState, String),
{
    let mut state = read_agent_state(root)?;
    f(&mut state, now);
    write_agent_state(root, &state)
}

#[derive(Debug, Default)]
struct LocalSyncResult {
    pushed_count: usize,
    conflict_count: usize,
    path_overrides: BTreeMap<(String, String), String>,
    conflicted_markdown: BTreeMap<String, String>,
}

enum SubmitIntentOutcome {
    Submitted,
    Conflict(String),
}

fn preserve_conflicted_markdown(result: &mut LocalSyncResult, change: &WorkingTreeChange) {
    if let WorkingTreeChange::Upsert { path, markdown } = change {
        result
            .conflicted_markdown
            .insert(path.to_string(), markdown.clone());
    }
}

fn encode_folder_object_page_plaintext(
    path: &SafeRelativePath,
    markdown: &str,
) -> Result<String, CliError> {
    serde_json::to_string(&CliFolderObjectPagePlaintext {
        version: FOLDER_OBJECT_PAGE_VERSION.to_owned(),
        path: path.as_str().to_owned(),
        markdown: markdown.to_owned(),
    })
    .map_err(CliError::from)
}

fn decode_folder_object_page_plaintext(
    plaintext: Vec<u8>,
    fallback_path: String,
) -> Result<(String, String), CliError> {
    let text =
        String::from_utf8(plaintext).map_err(|error| CliError::InvalidInput(error.to_string()))?;
    let Ok(page) = serde_json::from_str::<CliFolderObjectPagePlaintext>(&text) else {
        return Ok((fallback_path, text));
    };
    if page.version != FOLDER_OBJECT_PAGE_VERSION {
        return Ok((fallback_path, text));
    }
    let page_path = SafeRelativePath::new("page_path", page.path)
        .map_err(|error| CliError::InvalidInput(error.to_string()))?;
    Ok((page_path.to_string(), page.markdown))
}

#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CliFolderObjectPagePlaintext {
    version: String,
    path: String,
    markdown: String,
}

#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CliEncryptedVaultExport {
    vault: CliExportVault,
    folders: Vec<CliExportFolder>,
    key_grants: Vec<CliFolderKeyGrant>,
    access_state: CliExportAccessState,
}

#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CliExportVault {
    id: String,
    kind: String,
    name: String,
    owner_user_id: Option<String>,
}

#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CliExportFolder {
    id: String,
    path: String,
    access: String,
    current_key_version: u32,
    shared_folder_source: bool,
    accessible: bool,
}

#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CliFolderKeyGrant {
    folder_id: String,
    key_version: u32,
    issuer_npub: String,
    recipient_npub: String,
    wrapped_event_json: String,
}

#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CliExportAccessState {
    members: Vec<String>,
    admins: Vec<String>,
}

#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CliSyncBootstrap {
    latest_sequence: u64,
    objects: Vec<CliSyncObject>,
}

#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CliSyncObject {
    folder_id: String,
    object_id: String,
    revision: u64,
    ciphertext: String,
    deleted: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CliFolderKeyGrantPlaintext {
    version: String,
    vault_id: String,
    folder_id: String,
    key_version: u32,
    folder_key: String,
    issuer_npub: String,
    recipient_npub: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use finite_brain_core::portability::{
        VaultDirectoryManifest, VaultDirectoryPath, VaultDirectoryPortability,
        VaultDirectoryVaultSummary, VaultWorkingTreeStateManifest, WorkingTreeSyncState,
    };
    use finite_brain_core::{DisplayName, validate_revision_event};
    use tempfile::TempDir;

    #[test]
    fn scan_detects_markdown_create_update_and_delete() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("General/_wiki")).unwrap();
        fs::write(root.join("General/existing.md"), "# Changed\n").unwrap();
        fs::write(root.join("General/new.md"), "# New\n").unwrap();
        fs::write(root.join("General/AGENTS.md"), "# Generated\n").unwrap();
        fs::write(root.join("General/_wiki/index.md"), "# Generated\n").unwrap();
        let state = VaultWorkingTreeStateManifest {
            version: "finite-vault-working-tree-state-v1".to_owned(),
            folder_roots: vec![WorkingTreeFolderRoot {
                folder_id: "general".to_owned(),
                path: "General".to_owned(),
                can_read: true,
                metadata_only: false,
            }],
            objects: vec![
                WorkingTreeObjectManifestEntry {
                    folder_id: "general".to_owned(),
                    path: "existing.md".to_owned(),
                    object_id: "obj_existing00000".to_owned(),
                    revision: 1,
                    key_version: 1,
                    content_type: "text/markdown".to_owned(),
                    content_hash: sha256_hex("# Old\n".as_bytes()),
                },
                WorkingTreeObjectManifestEntry {
                    folder_id: "general".to_owned(),
                    path: "deleted.md".to_owned(),
                    object_id: "obj_deleted000000".to_owned(),
                    revision: 1,
                    key_version: 1,
                    content_type: "text/markdown".to_owned(),
                    content_hash: sha256_hex("# Deleted\n".as_bytes()),
                },
            ],
            sync: WorkingTreeSyncState { latest_sequence: 1 },
        };

        let changes = scan_working_tree_changes(root, &state).unwrap();

        assert_eq!(changes.len(), 3);
        assert!(changes.iter().any(|change| matches!(
            change,
            WorkingTreeChange::Upsert { path, markdown }
                if path.as_str() == "General/existing.md" && markdown == "# Changed\n"
        )));
        assert!(changes.iter().any(|change| matches!(
            change,
            WorkingTreeChange::Upsert { path, markdown }
                if path.as_str() == "General/new.md" && markdown == "# New\n"
        )));
        assert!(changes.iter().any(|change| matches!(
            change,
            WorkingTreeChange::Delete { path } if path.as_str() == "General/deleted.md"
        )));
    }

    #[test]
    fn signed_revision_events_validate_against_core_contract() {
        let keys = Keys::parse("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap();
        let actor_npub = NostrPublicKey::from_protocol(keys.public_key())
            .to_npub()
            .unwrap();
        let folder_key = FolderKey::from_bytes([7; 32]);
        let aad = FolderObjectAad {
            vault_id: VaultId::new("vault").unwrap(),
            folder_id: FolderId::new("general").unwrap(),
            object_id: ObjectId::new("obj_000000000001").unwrap(),
            key_version: 1,
        };
        let envelope = encrypt_folder_object(&folder_key, &aad, "# Page\n").unwrap();
        let envelope_json = envelope.canonical_json();
        let event_json = signed_revision_event(
            &keys,
            RevisionEventInput {
                actor_npub: &actor_npub,
                vault_id: "vault",
                folder_id: &FolderId::new("general").unwrap(),
                object_id: &ObjectId::new("obj_000000000001").unwrap(),
                operation: FolderObjectOperation::Create,
                base_revision: None,
                key_version: 1,
                envelope_json: envelope_json.clone(),
            },
        )
        .unwrap();
        let event = Event::from_json(event_json.to_string()).unwrap();
        let expected = RevisionValidation {
            vault_id: VaultId::new("vault").unwrap(),
            folder_id: FolderId::new("general").unwrap(),
            object_id: ObjectId::new("obj_000000000001").unwrap(),
            operation: FolderObjectOperation::Create,
            revision: 1,
            base_revision: None,
            key_version: 1,
            envelope_json,
            author_npub: actor_npub,
            created_at: timestamp_from_unix(event.created_at.as_secs()),
        };

        validate_revision_event(&event, &expected).unwrap();
    }

    #[test]
    fn empty_readable_folders_stay_materialized() {
        let vault = Vault {
            id: VaultId::new("vault").unwrap(),
            kind: VaultKind::Personal,
            name: DisplayName::new("vault_name", "Vault").unwrap(),
            owner_user_id: Some(UserId::new("npub-owner").unwrap()),
            folders: vec![Folder {
                id: FolderId::new("home").unwrap(),
                name: DisplayName::new("folder_name", "home").unwrap(),
                role: FolderRole::PersonalHome,
                access: FolderAccessMode::Owner,
                parent_folder_id: None,
                path: SafeRelativePath::new("folder_path", "home").unwrap(),
                current_key_version: 1,
                shared_folder_source: false,
            }],
            members: Vec::new(),
            admins: Vec::new(),
        };
        let mut projection = materialize_vault_working_tree(WorkingTreeMaterializeInput {
            generated_at: "2026-06-26T23:30:00Z".to_owned(),
            generated_by_npub: UserId::new("npub-owner").unwrap(),
            vault,
            opened_pages: Vec::new(),
            locked_folders: Vec::new(),
            latest_sequence: 0,
        })
        .unwrap();
        let export = CliEncryptedVaultExport {
            vault: CliExportVault {
                id: "vault".to_owned(),
                kind: "personal".to_owned(),
                name: "Vault".to_owned(),
                owner_user_id: Some("npub-owner".to_owned()),
            },
            folders: vec![CliExportFolder {
                id: "home".to_owned(),
                path: "home".to_owned(),
                access: "owner".to_owned(),
                current_key_version: 1,
                shared_folder_source: false,
                accessible: true,
            }],
            key_grants: Vec::new(),
            access_state: CliExportAccessState {
                members: Vec::new(),
                admins: Vec::new(),
            },
        };
        let readable = BTreeSet::from(["home".to_owned()]);

        add_empty_readable_folders(&mut projection, &export, &readable).unwrap();

        assert_eq!(projection.state.folder_roots.len(), 1);
        assert_eq!(projection.state.folder_roots[0].folder_id, "home");
        assert!(projection.files.contains_key("home/AGENTS.md"));
        assert!(projection.files.contains_key("home/raw/.keep"));
    }

    #[test]
    fn stale_object_cleanup_removes_old_path_after_move() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join(".finitebrain")).unwrap();
        fs::create_dir_all(root.join("General")).unwrap();
        fs::write(root.join("General/old.md"), "# Old\n").unwrap();
        let state = VaultWorkingTreeStateManifest {
            version: "finite-vault-working-tree-state-v1".to_owned(),
            folder_roots: vec![WorkingTreeFolderRoot {
                folder_id: "general".to_owned(),
                path: "General".to_owned(),
                can_read: true,
                metadata_only: false,
            }],
            objects: vec![WorkingTreeObjectManifestEntry {
                folder_id: "general".to_owned(),
                path: "old.md".to_owned(),
                object_id: "obj_same0000000".to_owned(),
                revision: 1,
                key_version: 1,
                content_type: "text/markdown".to_owned(),
                content_hash: sha256_hex("# Old\n".as_bytes()),
            }],
            sync: WorkingTreeSyncState { latest_sequence: 1 },
        };
        write_json_file(&root.join(".finitebrain/working-tree-state.json"), &state).unwrap();
        let new_objects = vec![WorkingTreeObjectManifestEntry {
            folder_id: "general".to_owned(),
            path: "new.md".to_owned(),
            object_id: "obj_same0000000".to_owned(),
            revision: 2,
            key_version: 1,
            content_type: "text/markdown".to_owned(),
            content_hash: sha256_hex("# New\n".as_bytes()),
        }];

        remove_stale_object_files(root, &state.objects, &new_objects).unwrap();

        assert!(!root.join("General/old.md").exists());
    }

    #[test]
    fn materialize_remote_projection_uses_encrypted_page_path_without_prior_state() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join(".finitebrain")).unwrap();
        write_json_file(
            &root.join(".finitebrain/working-tree-state.json"),
            &VaultWorkingTreeStateManifest {
                version: "finite-vault-working-tree-state-v1".to_owned(),
                folder_roots: Vec::new(),
                objects: Vec::new(),
                sync: WorkingTreeSyncState { latest_sequence: 0 },
            },
        )
        .unwrap();
        let folder_key = FolderKey::from_bytes([3; 32]);
        let mut agent_state = AgentState::new("vault", "2026-06-26T23:30:00Z");
        agent_state.local_folder_keys.push(LocalFolderKey {
            folder_id: "home".to_owned(),
            key_version: 1,
            key_base64: folder_key.to_base64(),
            source: "test".to_owned(),
            opened_at: "2026-06-26T23:30:00Z".to_owned(),
        });
        write_agent_state(root, &agent_state).unwrap();
        let env = CliEnvironment {
            cwd: root.to_path_buf(),
            config_dir: root.join("config"),
            now: Some("2026-06-26T23:30:00Z".to_owned()),
        };
        let object_id = ObjectId::new("obj_remote000001").unwrap();
        let page_path = SafeRelativePath::new("page_path", "docs/from-envelope.md").unwrap();
        let plaintext = encode_folder_object_page_plaintext(&page_path, "# Remote\n").unwrap();
        let aad = FolderObjectAad {
            vault_id: VaultId::new("vault").unwrap(),
            folder_id: FolderId::new("home").unwrap(),
            object_id: object_id.clone(),
            key_version: 1,
        };
        let envelope = encrypt_folder_object(&folder_key, &aad, &plaintext).unwrap();
        let export = CliEncryptedVaultExport {
            vault: CliExportVault {
                id: "vault".to_owned(),
                kind: "personal".to_owned(),
                name: "Vault".to_owned(),
                owner_user_id: Some("npub-owner".to_owned()),
            },
            folders: vec![CliExportFolder {
                id: "home".to_owned(),
                path: "home".to_owned(),
                access: "owner".to_owned(),
                current_key_version: 1,
                shared_folder_source: false,
                accessible: true,
            }],
            key_grants: Vec::new(),
            access_state: CliExportAccessState {
                members: Vec::new(),
                admins: Vec::new(),
            },
        };
        let bootstrap = CliSyncBootstrap {
            latest_sequence: 7,
            objects: vec![CliSyncObject {
                folder_id: "home".to_owned(),
                object_id: object_id.as_str().to_owned(),
                revision: 2,
                ciphertext: envelope.canonical_json(),
                deleted: false,
            }],
        };

        materialize_remote_projection(
            &env,
            root,
            "npub-owner",
            &export,
            &bootstrap,
            &BTreeMap::new(),
        )
        .unwrap();

        assert_eq!(
            fs::read_to_string(root.join("home/docs/from-envelope.md")).unwrap(),
            "# Remote\n"
        );
        let state = read_working_tree_state(root).unwrap();
        assert_eq!(state.objects.len(), 1);
        assert_eq!(state.objects[0].path, "docs/from-envelope.md");
        assert_eq!(state.sync.latest_sequence, 7);
    }

    #[test]
    fn historical_local_keys_do_not_make_current_folder_readable() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join(".finitebrain")).unwrap();
        write_json_file(
            &root.join(".finitebrain/working-tree-state.json"),
            &VaultWorkingTreeStateManifest {
                version: "finite-vault-working-tree-state-v1".to_owned(),
                folder_roots: Vec::new(),
                objects: Vec::new(),
                sync: WorkingTreeSyncState { latest_sequence: 0 },
            },
        )
        .unwrap();
        let mut agent_state = AgentState::new("vault", "2026-06-26T23:30:00Z");
        agent_state.local_folder_keys.push(LocalFolderKey {
            folder_id: "home".to_owned(),
            key_version: 1,
            key_base64: FolderKey::from_bytes([1; 32]).to_base64(),
            source: "test".to_owned(),
            opened_at: "2026-06-26T23:30:00Z".to_owned(),
        });
        write_agent_state(root, &agent_state).unwrap();
        let env = CliEnvironment {
            cwd: root.to_path_buf(),
            config_dir: root.join("config"),
            now: Some("2026-06-26T23:30:00Z".to_owned()),
        };
        let export = CliEncryptedVaultExport {
            vault: CliExportVault {
                id: "vault".to_owned(),
                kind: "personal".to_owned(),
                name: "Vault".to_owned(),
                owner_user_id: Some("npub-owner".to_owned()),
            },
            folders: vec![CliExportFolder {
                id: "home".to_owned(),
                path: "home".to_owned(),
                access: "owner".to_owned(),
                current_key_version: 2,
                shared_folder_source: false,
                accessible: true,
            }],
            key_grants: Vec::new(),
            access_state: CliExportAccessState {
                members: Vec::new(),
                admins: Vec::new(),
            },
        };
        let bootstrap = CliSyncBootstrap {
            latest_sequence: 0,
            objects: Vec::new(),
        };

        materialize_remote_projection(
            &env,
            root,
            "npub-owner",
            &export,
            &bootstrap,
            &BTreeMap::new(),
        )
        .unwrap();

        let state = read_working_tree_state(root).unwrap();
        assert_eq!(state.folder_roots.len(), 1);
        assert_eq!(state.folder_roots[0].folder_id, "home");
        assert!(!state.folder_roots[0].can_read);
        assert!(state.folder_roots[0].metadata_only);
    }

    #[allow(dead_code)]
    fn _directory_manifest() -> VaultDirectoryManifest {
        VaultDirectoryManifest {
            version: "finite-vault-directory-v1".to_owned(),
            vault: VaultDirectoryVaultSummary {
                id: "vault".to_owned(),
                kind: "personal".to_owned(),
                name: "Vault".to_owned(),
                owner_npub: Some("npub-owner".to_owned()),
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
            created_at: "2026-06-26T23:30:00Z".to_owned(),
            updated_at: "2026-06-26T23:30:00Z".to_owned(),
        }
    }
}
