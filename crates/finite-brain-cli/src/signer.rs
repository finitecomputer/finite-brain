use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use finite_brain_core::sha256_hex;
use nostr::event::FinalizeEvent;
use nostr::{EventBuilder, Keys, Kind, Tag, Timestamp};

use crate::{
    CliEnvironment, CliError, PrototypeAuth, auth_nonce, read_auth_optional, tag_vec,
    unix_timestamp,
};

pub(crate) fn signed_http_auth_header(
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

pub(crate) fn sign_event(
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

pub(crate) fn read_auth_required(env: &CliEnvironment) -> Result<PrototypeAuth, CliError> {
    read_auth_optional(env)?.ok_or(CliError::MissingAuth)
}

pub(crate) fn signer_keys(env: &CliEnvironment) -> Result<Keys, CliError> {
    let auth = read_auth_required(env)?;
    Keys::parse(&auth.secret_key).map_err(|error| CliError::InvalidSigner(error.to_string()))
}
