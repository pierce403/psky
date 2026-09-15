//! Narrow syntax validation. This does not perform DID/handle resolution or
//! full Lexicon validation and never changes identifiers during replay.

use crate::Error;

pub(crate) fn path(path: &str) -> Result<(), Error> {
    let invalid = || Error::InvalidPath(path.into());
    let (nsid, key) = path.split_once('/').ok_or_else(invalid)?;
    if !nsid_valid(nsid)
        || key.is_empty()
        || key.len() > 512
        || key == "."
        || key == ".."
        || !key
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b".-_:~".contains(&c))
    {
        return Err(invalid());
    }
    Ok(())
}

fn nsid_valid(nsid: &str) -> bool {
    let Some((authority, name)) = nsid.rsplit_once('.') else {
        return false;
    };
    if nsid.len() > 317
        || authority.len() > 253
        || name.is_empty()
        || name.len() > 63
        || !name.as_bytes()[0].is_ascii_alphabetic()
        || !name.bytes().all(|c| c.is_ascii_alphanumeric())
    {
        return false;
    }
    let segments: Vec<_> = authority.split('.').collect();
    segments.len() >= 2
        && segments[0]
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_lowercase)
        && segments.iter().all(|s| {
            !s.is_empty()
                && s.len() <= 63
                && !s.starts_with('-')
                && !s.ends_with('-')
                && s.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
}

pub(crate) fn metadata(did: &str, rev: &str) -> Result<(), Error> {
    let valid_did = if let Some(id) = did.strip_prefix("did:plc:") {
        id.len() == 24
            && id
                .bytes()
                .all(|c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c))
    } else if let Some(domain) = did.strip_prefix("did:web:") {
        let local = domain == "localhost"
            || domain.strip_prefix("localhost%3A").is_some_and(|port| {
                port.parse::<u16>()
                    .is_ok_and(|number| number > 0 && number.to_string() == port)
            });
        local
            || domain.len() <= 253
                && domain.contains('.')
                && domain.split('.').all(|s| {
                    !s.is_empty()
                        && s.len() <= 63
                        && !s.starts_with('-')
                        && !s.ends_with('-')
                        && s.bytes()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
                })
                && domain
                    .rsplit('.')
                    .next()
                    .is_some_and(|s| s.bytes().any(|c| c.is_ascii_lowercase()))
    } else {
        false
    };
    if !valid_did {
        return Err(Error::InvalidMetadata(
            "expected normalized did:plc or hostname-only did:web".into(),
        ));
    }
    if rev.len() != 13
        || !b"234567abcdefghij".contains(&rev.as_bytes()[0])
        || !rev
            .bytes()
            .all(|c| b"234567abcdefghijklmnopqrstuvwxyz".contains(&c))
    {
        return Err(Error::InvalidMetadata(
            "revision must be a 13-character TID".into(),
        ));
    }
    Ok(())
}
