use finite_nostr::{HttpAuthEventRequest, encode_http_auth_header, sign_http_auth_event};
use nostr::event::FinalizeEvent;
use nostr::{EventBuilder, Keys, Kind, Tag, Timestamp};

use crate::{
    CliEnvironment, CliError, PrototypeAuth, auth_nonce, read_auth_optional, unix_timestamp,
};

pub(crate) fn signed_http_auth_header(
    keys: &Keys,
    method: &str,
    url: &str,
    body: Option<&[u8]>,
) -> Result<String, CliError> {
    let mut request =
        HttpAuthEventRequest::new(method, url, unix_timestamp()).with_nonce(auth_nonce());
    if let Some(body) = body {
        request = request.with_body(body.to_vec());
    }
    let event = sign_http_auth_event(keys, &request)
        .map_err(|error| CliError::InvalidSigner(error.to_string()))?;
    Ok(encode_http_auth_header(&event))
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
