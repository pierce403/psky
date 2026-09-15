use crate::{AuthError, Challenge, MAX_CHALLENGE_SECONDS, SignedProof};
use sha3::{Digest, Keccak256};
use siwe::Message;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub(crate) const MAX_MESSAGE_BYTES: usize = 8192;
pub(crate) const MAX_SIGNATURE_BYTES: usize = 4096;
const MAX_FID: u64 = 9_007_199_254_740_991;
const CLOCK_SKEW_SECONDS: u64 = 60;

pub(crate) struct ParsedProof {
    pub message: Message,
    pub fid: u64,
    pub signature: Vec<u8>,
    pub digest: [u8; 32],
}

pub(crate) fn validate_challenge(challenge: &Challenge) -> Result<(), AuthError> {
    let valid_nonce = (16..=128).contains(&challenge.nonce.len())
        && challenge.nonce.bytes().all(|b| b.is_ascii_alphanumeric());
    let lifetime = challenge.expires_at.checked_sub(challenge.created_at);
    if !valid_nonce || !matches!(lifetime, Some(1..=MAX_CHALLENGE_SECONDS)) {
        return Err(AuthError::InvalidChallenge);
    }
    timestamp(challenge.created_at)?;
    timestamp(challenge.expires_at)?;
    Ok(())
}

pub(crate) fn timestamp(seconds: u64) -> Result<String, AuthError> {
    let seconds = i64::try_from(seconds).map_err(|_| AuthError::InvalidChallenge)?;
    OffsetDateTime::from_unix_timestamp(seconds)
        .map_err(|_| AuthError::InvalidChallenge)?
        .format(&Rfc3339)
        .map_err(|_| AuthError::InvalidChallenge)
}

pub(crate) fn parse(
    proof: &SignedProof,
    challenge: &Challenge,
    domain: &str,
    uri: &str,
    now: u64,
) -> Result<ParsedProof, AuthError> {
    validate_challenge(challenge)?;
    if now < challenge.created_at || now >= challenge.expires_at {
        return Err(AuthError::InvalidChallenge);
    }
    let parsed = parse_authority(proof, domain, uri)?;
    let message = &parsed.message;
    if message.nonce != challenge.nonce {
        return Err(AuthError::InvalidMessage);
    }
    let issued = message.issued_at.as_ref().unix_timestamp();
    let issued = u64::try_from(issued).map_err(|_| AuthError::InvalidMessage)?;
    if issued < challenge.created_at.saturating_sub(CLOCK_SKEW_SECONDS)
        || issued > now.saturating_add(CLOCK_SKEW_SECONDS)
        || issued >= challenge.expires_at
    {
        return Err(AuthError::InvalidMessage);
    }
    let expiry = message
        .expiration_time
        .as_ref()
        .ok_or(AuthError::InvalidMessage)?
        .as_ref();
    // We requested this exact expiration. Accepting an extended or missing
    // expiration would weaken the consent displayed by the signing client.
    if expiry.unix_timestamp() != challenge.expires_at as i64 || expiry.nanosecond() != 0 {
        return Err(AuthError::InvalidMessage);
    }
    if let Some(not_before) = &message.not_before {
        let value = not_before.as_ref();
        if value.unix_timestamp() != challenge.created_at as i64 || value.nanosecond() != 0 {
            return Err(AuthError::InvalidMessage);
        }
    }
    Ok(parsed)
}

pub(crate) fn parse_authority(
    proof: &SignedProof,
    domain: &str,
    uri: &str,
) -> Result<ParsedProof, AuthError> {
    if proof.message.len() > MAX_MESSAGE_BYTES || !proof.message.is_ascii() {
        return Err(AuthError::InvalidMessage);
    }
    let message: Message = proof
        .message
        .parse()
        .map_err(|_| AuthError::InvalidMessage)?;
    // The parser skips blank lines without checking their content. Exact
    // serialization closes that ambiguity and binds verification to raw bytes.
    if message.to_string() != proof.message
        || message.domain.as_str() != domain
        || message.uri.as_str() != uri
        || !(16..=128).contains(&message.nonce.len())
        || !message.nonce.bytes().all(|b| b.is_ascii_alphanumeric())
        || message.chain_id != 10
        || !matches!(
            message.statement.as_deref(),
            Some("Farcaster Auth" | "Farcaster Connect")
        )
        || message.request_id.is_some()
        || message.resources.len() != 1
    {
        return Err(AuthError::InvalidMessage);
    }
    let fid_resource = message.resources[0].as_str();
    let digits = fid_resource
        .strip_prefix("farcaster://fid/")
        .ok_or(AuthError::InvalidMessage)?;
    let digits = digits.strip_suffix('/').unwrap_or(digits);
    if digits.starts_with('0') || digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(AuthError::InvalidMessage);
    }
    let fid: u64 = digits.parse().map_err(|_| AuthError::InvalidMessage)?;
    if fid == 0 || fid > MAX_FID {
        return Err(AuthError::InvalidMessage);
    }
    let signature = proof
        .signature
        .strip_prefix("0x")
        .ok_or(AuthError::InvalidSignature)?;
    if signature.is_empty() || signature.len() > MAX_SIGNATURE_BYTES * 2 {
        return Err(AuthError::InvalidSignature);
    }
    let signature = hex::decode(signature).map_err(|_| AuthError::InvalidSignature)?;
    // ERC-6492 needs a universal counterfactual deployment validator. Never
    // interpret its wrapper as an EOA or ordinary ERC-1271 signature.
    if signature.ends_with(&[0x64, 0x92].repeat(16)) {
        return Err(AuthError::UnsupportedWallet);
    }
    let mut hasher = Keccak256::new();
    hasher.update(format!(
        "\x19Ethereum Signed Message:\n{}",
        proof.message.len()
    ));
    hasher.update(proof.message.as_bytes());
    Ok(ParsedProof {
        message,
        fid,
        signature,
        digest: hasher.finalize().into(),
    })
}

pub(crate) fn verify_eoa(proof: &ParsedProof) -> Result<(), AuthError> {
    let signature: [u8; 65] = proof
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| AuthError::InvalidSignature)?;
    if !matches!(signature[64], 0 | 1 | 27 | 28) {
        return Err(AuthError::InvalidSignature);
    }
    proof
        .message
        .verify_eip191(&signature)
        .map_err(|_| AuthError::InvalidSignature)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    const NOW: u64 = 1_770_000_000;
    const ADDRESS: &str = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf";

    fn challenge() -> Challenge {
        Challenge {
            nonce: "0123456789ABCDEF0123456789ABCDEF".into(),
            created_at: NOW,
            expires_at: NOW + 300,
        }
    }

    fn fixture() -> SignedProof {
        let challenge = challenge();
        let message = format!(
            "pds.example wants you to sign in with your Ethereum account:\n{ADDRESS}\n\nFarcaster Auth\n\nURI: https://pds.example/onboard\nVersion: 1\nChain ID: 10\nNonce: {}\nIssued At: {}\nExpiration Time: {}\nNot Before: {}\nResources:\n- farcaster://fid/8531",
            challenge.nonce,
            timestamp(NOW).unwrap(),
            timestamp(NOW + 300).unwrap(),
            timestamp(NOW).unwrap()
        );
        // Private scalar one is a published Ethereum test key, never a user key.
        let mut key = [0; 32];
        key[31] = 1;
        let key = SigningKey::from_bytes((&key).into()).unwrap();
        let input = format!("\x19Ethereum Signed Message:\n{}{message}", message.len());
        let (signature, recovery) = key
            .sign_digest_recoverable(Keccak256::new_with_prefix(input.as_bytes()))
            .unwrap();
        let mut signature = signature.to_bytes().to_vec();
        signature.push(recovery.to_byte() + 27);
        SignedProof {
            message,
            signature: format!("0x{}", hex::encode(signature)),
        }
    }

    fn parse_fixture(proof: &SignedProof) -> Result<ParsedProof, AuthError> {
        parse(
            proof,
            &challenge(),
            "pds.example",
            "https://pds.example/onboard",
            NOW + 1,
        )
    }

    #[test]
    fn deterministic_eoa_proof_verifies_raw_message() {
        let proof = fixture();
        let parsed = parse_fixture(&proof).unwrap();
        assert_eq!(parsed.fid, 8531);
        assert_eq!(
            hex::encode(parsed.message.address),
            ADDRESS[2..].to_lowercase()
        );
        assert!(verify_eoa(&parsed).is_ok());
        assert_eq!(parsed.digest, parsed.message.eip191_hash().unwrap());
    }

    #[test]
    fn independent_viem_message_and_signature_vector_verifies() {
        let value: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/siwf-eoa.json")).unwrap();
        let proof = SignedProof {
            message: value["message"].as_str().unwrap().into(),
            signature: value["signature"].as_str().unwrap().into(),
        };
        let parsed = parse_fixture(&proof).unwrap();
        assert!(verify_eoa(&parsed).is_ok());
        assert_eq!(
            format!("0x{}", hex::encode(parsed.message.address)),
            value["address"].as_str().unwrap().to_lowercase()
        );
    }

    #[test]
    fn challenge_requires_random_shape_and_bounded_lifetime() {
        for nonce in ["", "short", "0123456789ABCDEF!", "0123456789ABCDEF\n"] {
            let mut item = challenge();
            item.nonce = nonce.into();
            assert_eq!(validate_challenge(&item), Err(AuthError::InvalidChallenge));
        }
        for delta in [0, 601] {
            let mut item = challenge();
            item.expires_at = NOW + delta;
            assert_eq!(validate_challenge(&item), Err(AuthError::InvalidChallenge));
        }
        let mut item = challenge();
        item.created_at = u64::MAX;
        item.expires_at = 0;
        assert_eq!(validate_challenge(&item), Err(AuthError::InvalidChallenge));
    }

    #[test]
    fn exact_challenge_time_bounds() {
        for now in [NOW - 1, NOW + 300, u64::MAX] {
            assert_eq!(
                parse(
                    &fixture(),
                    &challenge(),
                    "pds.example",
                    "https://pds.example/onboard",
                    now
                )
                .err(),
                Some(AuthError::InvalidChallenge)
            );
        }
        assert!(
            parse(
                &fixture(),
                &challenge(),
                "pds.example",
                "https://pds.example/onboard",
                NOW + 299
            )
            .is_ok()
        );
    }

    #[test]
    fn nonce_domain_and_uri_cannot_be_substituted() {
        for (from, to) in [
            ("pds.example wants", "other.example wants"),
            ("https://pds.example/onboard", "https://pds.example/admin"),
            (
                "0123456789ABCDEF0123456789ABCDEF",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            ),
        ] {
            let mut proof = fixture();
            proof.message = proof.message.replace(from, to);
            assert_eq!(parse_fixture(&proof).err(), Some(AuthError::InvalidMessage));
        }
    }

    #[test]
    fn chain_statement_and_version_cannot_be_substituted() {
        for (from, to) in [
            ("Chain ID: 10", "Chain ID: 1"),
            ("Farcaster Auth", "Approve signer"),
            ("Version: 1", "Version: 2"),
        ] {
            let mut proof = fixture();
            proof.message = proof.message.replace(from, to);
            assert_eq!(parse_fixture(&proof).err(), Some(AuthError::InvalidMessage));
        }
    }

    #[test]
    fn parser_blank_line_skipping_is_closed_by_round_trip() {
        let mut proof = fixture();
        proof.message =
            proof
                .message
                .replacen("\n\nFarcaster", "\nHIDDEN INSTRUCTION\nFarcaster", 1);
        assert_eq!(parse_fixture(&proof).err(), Some(AuthError::InvalidMessage));
        let mut proof = fixture();
        proof.message.push('\n');
        assert_eq!(parse_fixture(&proof).err(), Some(AuthError::InvalidMessage));
    }

    #[test]
    fn exactly_one_unambiguous_positive_fid_resource() {
        for value in [
            "0",
            "08531",
            "-8531",
            "8531/extra",
            "9007199254740992",
            "18446744073709551616",
        ] {
            let mut proof = fixture();
            proof.message = proof.message.replace("fid/8531", &format!("fid/{value}"));
            assert_eq!(parse_fixture(&proof).err(), Some(AuthError::InvalidMessage));
        }
        let mut proof = fixture();
        proof.message.push_str("\n- farcaster://fid/1");
        assert_eq!(parse_fixture(&proof).err(), Some(AuthError::InvalidMessage));
        let mut proof = fixture();
        proof.message = proof
            .message
            .replace("farcaster://fid/8531", "https://evil.example/fid/8531");
        assert_eq!(parse_fixture(&proof).err(), Some(AuthError::InvalidMessage));
    }

    #[test]
    fn harmless_legacy_statement_and_trailing_fid_slash_parse_but_require_new_signature() {
        let mut proof = fixture();
        proof.message = proof.message.replace("Farcaster Auth", "Farcaster Connect");
        let parsed = parse_fixture(&proof).unwrap();
        assert!(verify_eoa(&parsed).is_err());
        let mut proof = fixture();
        proof.message.push('/');
        assert_eq!(parse_fixture(&proof).unwrap().fid, 8531);
    }

    #[test]
    fn expiry_must_match_requested_consent() {
        for expiry in [NOW + 299, NOW + 301, NOW - 1] {
            let mut proof = fixture();
            proof.message = proof
                .message
                .replace(&timestamp(NOW + 300).unwrap(), &timestamp(expiry).unwrap());
            assert_eq!(parse_fixture(&proof).err(), Some(AuthError::InvalidMessage));
        }
        let mut proof = fixture();
        proof.message = proof.message.replace(
            &format!("Expiration Time: {}\n", timestamp(NOW + 300).unwrap()),
            "",
        );
        assert_eq!(parse_fixture(&proof).err(), Some(AuthError::InvalidMessage));
    }

    #[test]
    fn issued_at_and_not_before_are_bounded() {
        for issued in [NOW - 61, NOW + 62] {
            let mut proof = fixture();
            proof.message = proof.message.replacen(
                &format!("Issued At: {}", timestamp(NOW).unwrap()),
                &format!("Issued At: {}", timestamp(issued).unwrap()),
                1,
            );
            assert_eq!(parse_fixture(&proof).err(), Some(AuthError::InvalidMessage));
        }
        let mut proof = fixture();
        proof.message = proof.message.replace(
            &format!("Not Before: {}", timestamp(NOW).unwrap()),
            &format!("Not Before: {}", timestamp(NOW + 1).unwrap()),
        );
        assert_eq!(parse_fixture(&proof).err(), Some(AuthError::InvalidMessage));
    }

    #[test]
    fn wrong_message_or_signature_does_not_verify() {
        let mut proof = fixture();
        proof.message = proof.message.replace("fid/8531", "fid/8532");
        assert_eq!(
            verify_eoa(&parse_fixture(&proof).unwrap()),
            Err(AuthError::InvalidSignature)
        );
        let mut proof = fixture();
        proof.signature.replace_range(4..6, "ff");
        assert_eq!(
            verify_eoa(&parse_fixture(&proof).unwrap()),
            Err(AuthError::InvalidSignature)
        );
    }

    #[test]
    fn malformed_or_unbounded_signature_is_rejected() {
        for signature in [
            String::new(),
            "0xzz".into(),
            "0xf".into(),
            "ff".into(),
            format!("0x{}", "ab".repeat(MAX_SIGNATURE_BYTES + 1)),
        ] {
            let mut proof = fixture();
            proof.signature = signature;
            assert_eq!(
                parse_fixture(&proof).err(),
                Some(AuthError::InvalidSignature)
            );
        }
        let mut proof = fixture();
        proof.signature = "0x00".into();
        assert_eq!(
            verify_eoa(&parse_fixture(&proof).unwrap()),
            Err(AuthError::InvalidSignature)
        );
    }

    #[test]
    fn counterfactual_wrapper_is_explicitly_unsupported() {
        let mut proof = fixture();
        proof.signature.push_str(&"6492".repeat(16));
        assert_eq!(
            parse_fixture(&proof).err(),
            Some(AuthError::UnsupportedWallet)
        );
    }

    #[test]
    fn bad_recovery_ids_are_not_accepted() {
        let mut proof = fixture();
        let end = proof.signature.len();
        proof.signature.replace_range(end - 2..end, "ff");
        assert_eq!(
            verify_eoa(&parse_fixture(&proof).unwrap()),
            Err(AuthError::InvalidSignature)
        );
    }

    #[test]
    fn recheck_can_parse_expired_consent_without_establishing_new_login() {
        let proof = fixture();
        assert!(parse_authority(&proof, "pds.example", "https://pds.example/onboard").is_ok());
        assert_eq!(
            parse(
                &proof,
                &challenge(),
                "pds.example",
                "https://pds.example/onboard",
                NOW + 600
            )
            .err(),
            Some(AuthError::InvalidChallenge)
        );
    }
}
