//! L7 protocol and payload bitmask parsers for CLI and TOML configuration.

/// Typed configuration parsing errors.
use crate::config::error::ConfigError;

/// Re-exported canonical L7 protocol/payload enums and mask matchers from `protocol::l7`.
pub use crate::protocol::l7::{
    ALL_L7_PAYLOADS, L7_PAYLOAD_NONE_MASK, L7Payload, L7Proto, l7_payload_matches, l7_payload_names,
    l7_payload_str_list, l7_proto_matches,
};

/// Parses comma-separated or list-separated L7 protocol names into a `filter_l7` bitmask (`0` = all).
pub fn parse_l7_proto_mask(items: &[String]) -> Result<u64, ConfigError>
{
    let mut mask = 0u64;
    for entry in items
    {
        for token in entry.split(',')
        {
            let trimmed = token.trim();
            if trimmed.is_empty()
            {
                continue;
            }
            let proto =
                L7Proto::from_name(trimmed).ok_or_else(|| ConfigError::InvalidL7Proto(trimmed.to_owned()))?;
            if proto == L7Proto::All
            {
                return Ok(0);
            }
            mask |= proto.bit();
        }
    }
    Ok(mask)
}

/// Parses comma-separated or list-separated L7 payload names into a 64-bit mask (`0` = all).
pub fn parse_l7_payload_mask(items: &[String]) -> Result<u64, ConfigError>
{
    let mut mask = 0u64;
    for entry in items
    {
        for token in entry.split(',')
        {
            let trimmed = token.trim();
            if trimmed.is_empty()
            {
                continue;
            }
            let payload = L7Payload::from_name(trimmed)
                .ok_or_else(|| ConfigError::InvalidL7Payload(trimmed.to_owned()))?;
            if payload == L7Payload::All
            {
                return Ok(0);
            }
            mask |= payload.bit();
        }
    }
    Ok(mask)
}

/// Parses `--payload-disable` / `--reasm-disable` lists (`empty` => [`L7_PAYLOAD_NONE_MASK`], `"all"` => `0`).
pub fn parse_l7_disable_mask(items: &[String]) -> Result<u64, ConfigError>
{
    let has_tokens = items
        .iter()
        .flat_map(|entry| entry.split(','))
        .any(|token| {
            !token
                .trim()
                .is_empty()
        });
    if !has_tokens
    {
        return Ok(L7_PAYLOAD_NONE_MASK);
    }
    parse_l7_payload_mask(items)
}
