use super::*;
use tempfile::TempDir;

fn identity() -> Identity {
    Identity {
        handle: "alice.example.com".into(),
        did: "did:web:alice.example.com".into(),
        service_url: "https://pds.example.com".into(),
        service_did: "did:web:pds.example.com".into(),
    }
}

fn store() -> (TempDir, Store) {
    let directory = tempfile::tempdir().unwrap();
    let mut store = Store::open(directory.path()).unwrap();
    store.clock = Some(1_789_480_000);
    store.bind_verified(8531, "0xabc123", identity()).unwrap();
    (directory, store)
}

fn login(store: &mut Store) -> (IssuedPassword, Session) {
    let password = store.issue_password("Bluesky").unwrap();
    let session = store
        .authenticate("alice.example.com", &password.password)
        .unwrap();
    (password, session)
}

fn signed_custom(key: &[u8], header: Value, claims: Value) -> String {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(input.as_bytes());
    format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

fn decode(token: &str) -> Value {
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(token.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap()
}

#[test]
fn starts_unbound_and_never_issues_fixture_credentials() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = Store::open(directory.path()).unwrap();
    assert!(store.account().unwrap().is_none());
    assert_eq!(store.issue_password("Bluesky").err(), Some(Error::NotBound));
    assert_eq!(store.did_document().err(), Some(Error::NotBound));
    assert_eq!(store.empty_repository().err(), Some(Error::NotBound));
    assert_eq!(
        store
            .authenticate("alice.example.com", &format!("psky-{}", "a".repeat(43)))
            .err(),
        Some(Error::InvalidCredentials)
    );
}

#[test]
fn real_binding_has_stable_key_document_and_empty_repository() {
    let (directory, store) = store();
    let account = store.account().unwrap().unwrap();
    let doc = store.did_document().unwrap();
    assert_eq!(doc["id"], account.identity.did);
    assert_eq!(
        doc["verificationMethod"][0]["publicKeyMultibase"],
        account.public_key_multibase
    );
    assert_eq!(
        doc["service"][0]["serviceEndpoint"],
        account.identity.service_url
    );
    let public = bs58::decode(&account.public_key_multibase[1..])
        .into_vec()
        .unwrap();
    assert_eq!(&public[..2], &[0xe7, 0x01]);
    let repo = store.repository().unwrap();
    repo.verify(&public[2..]).unwrap();
    assert_eq!(repo.root().to_string(), account.repo_cid);
    let car = store.empty_repository().unwrap();
    drop(store);
    let store = Store::open(directory.path()).unwrap();
    assert_eq!(car, store.empty_repository().unwrap());
    assert_eq!(
        store.account().unwrap().unwrap().public_key_multibase,
        account.public_key_multibase
    );
}

#[test]
fn separate_stores_never_share_keys_or_accept_each_others_tokens() {
    let (_one_dir, mut one) = store();
    let (_two_dir, two) = store();
    assert_ne!(
        one.account().unwrap().unwrap().public_key_multibase,
        two.account().unwrap().unwrap().public_key_multibase
    );
    let (_, session) = login(&mut one);
    assert_eq!(
        two.get_session(&session.access_jwt).err(),
        Some(Error::InvalidToken)
    );
}

#[test]
fn binding_cannot_take_over_another_fid_or_identity() {
    let (_directory, mut store) = store();
    assert_eq!(
        store.bind_verified(42, "0xabc123", identity()).err(),
        Some(Error::BindingConflict)
    );
    let mut other = identity();
    other.did = "did:web:bob.example.com".into();
    other.handle = "bob.example.com".into();
    assert_eq!(
        store.bind_verified(8531, "0xabc123", other).err(),
        Some(Error::BindingConflict)
    );
    assert_eq!(
        store.bind_verified(8531, "0xdef456", identity()).err(),
        Some(Error::BindingConflict)
    );
    assert_eq!(store.account().unwrap().unwrap().authority, "0xabc123");
}

#[test]
fn invalid_binding_input_is_not_saved() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = Store::open(directory.path()).unwrap();
    assert_eq!(
        store.bind_verified(0, "0xabc", identity()).err(),
        Some(Error::InvalidInput)
    );
    assert_eq!(
        store.bind_verified(1, "a\nsecret", identity()).err(),
        Some(Error::InvalidInput)
    );
    assert_eq!(
        store.bind_verified(1, &"a".repeat(129), identity()).err(),
        Some(Error::InvalidInput)
    );
    assert!(store.account().unwrap().is_none());
}

#[test]
fn only_supported_identity_origins_and_hostname_dids_are_accepted() {
    for did in [
        "did:example:test",
        "did:web:pds.example.com:alice",
        "did:web:localhost",
        "did:web:alice.invalid",
        "did:web:127.0.0.1",
    ] {
        let mut value = identity();
        value.did = did.into();
        assert_eq!(value.validate(), Err(Error::InvalidInput));
    }
    for url in [
        "http://pds.example.com",
        "https://wrong.example.com",
        "https://user:password@pds.example.com",
        "https://pds.example.com/path",
        "https://pds.example.com/?secret=a",
        "https://pds.example.com/#fragment",
        "file:///tmp/pds",
    ] {
        let mut value = identity();
        value.service_url = url.into();
        assert_eq!(value.validate(), Err(Error::InvalidInput), "{url}");
    }
    let mut value = identity();
    value.service_url = "https://pds.example.com/".into();
    value.validate().unwrap();
    Identity {
        handle: "psky.test".into(),
        did: "did:web:localhost%3A8787".into(),
        service_url: "http://localhost:8787".into(),
        service_did: "did:web:localhost%3A8787".into(),
    }
    .validate()
    .unwrap();
}

#[test]
fn password_plaintext_never_appears_in_metadata_or_database() {
    let (directory, mut store) = store();
    let password = store.issue_password("Bluesky").unwrap();
    assert_eq!(password.password.len(), 48);
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(&password.password[5..])
            .unwrap()
            .len(),
        32
    );
    let serialized = serde_json::to_string(&store.list_passwords().unwrap()).unwrap();
    assert!(!serialized.contains(&password.password));
    let bytes = fs::read(directory.path().join("credentials/state.sqlite3")).unwrap();
    assert!(!bytes
        .windows(password.password.len())
        .any(|slice| slice == password.password.as_bytes()));
}

#[test]
fn issuance_names_and_password_count_are_bounded() {
    let (_directory, mut store) = store();
    for name in ["", " spaced", "spaced ", "a\nlog", "🔑"] {
        assert_eq!(store.issue_password(name).err(), Some(Error::InvalidInput));
    }
    assert_eq!(
        store.issue_password(&"x".repeat(65)).err(),
        Some(Error::InvalidInput)
    );
    store.issue_password("unique").unwrap();
    assert_eq!(
        store.issue_password("unique").err(),
        Some(Error::InvalidInput)
    );
    for n in 1..MAX_PASSWORDS {
        store.issue_password(&format!("password-{n}")).unwrap();
    }
    assert_eq!(store.issue_password("overflow").err(), Some(Error::Limit));
    store.revoke_password("unique").unwrap();
    store.issue_password("replacement").unwrap();
}

#[test]
fn login_fields_match_current_standard_schema_without_false_email_claims() {
    let (_directory, mut store) = store();
    let (_, session) = login(&mut store);
    let value = serde_json::to_value(&session).unwrap();
    assert!(value["accessJwt"].is_string());
    assert!(value["refreshJwt"].is_string());
    assert_eq!(value["did"], "did:web:alice.example.com");
    assert_eq!(value["handle"], "alice.example.com");
    assert_eq!(value["active"], true);
    assert_eq!(value["emailConfirmed"], false);
    assert_eq!(value["emailAuthFactor"], false);
    assert!(value.get("email").is_none());
    assert!(value.get("authority").is_none());
    let info = store.get_session(&session.access_jwt).unwrap();
    assert_eq!(info.did, session.info.did);
}

#[test]
fn wrong_identifier_password_and_secret_formats_fail_generically() {
    let (_directory, mut store) = store();
    let password = store.issue_password("Bluesky").unwrap();
    for identifier in ["8531", "deanpierce.eth", "bob.example.com", ""] {
        assert_eq!(
            store.authenticate(identifier, &password.password).err(),
            Some(Error::InvalidCredentials)
        );
    }
    for password in [
        "",
        "chosen-password",
        &format!("psky-{}", "a".repeat(43)),
        &"a".repeat(20_000),
    ] {
        assert_eq!(
            store.authenticate("alice.example.com", password).err(),
            Some(Error::InvalidCredentials)
        );
    }
    store
        .authenticate("did:web:alice.example.com", &password.password)
        .unwrap();
}

#[test]
fn password_prevalidation_is_read_only_and_rechecked_after_revocation() {
    let (_directory, mut store) = store();
    let password = store.issue_password("Bluesky").unwrap();
    for _ in 0..MAX_SESSIONS + 1 {
        store
            .validate_password("alice.example.com", &password.password)
            .unwrap();
    }
    let count: u64 = store
        .connection
        .query_row("SELECT COUNT(*) FROM sessions", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
    assert_eq!(
        store.validate_password("bob.example.com", &password.password),
        Err(Error::InvalidCredentials)
    );
    store.revoke_password("Bluesky").unwrap();
    assert_eq!(
        store.validate_password("alice.example.com", &password.password),
        Err(Error::InvalidCredentials)
    );
    assert_eq!(
        store
            .authenticate("alice.example.com", &password.password)
            .err(),
        Some(Error::InvalidCredentials)
    );
}

#[test]
fn token_kinds_are_domain_separated() {
    let (_directory, mut store) = store();
    let (_, session) = login(&mut store);
    assert_eq!(
        store.get_session(&session.refresh_jwt).err(),
        Some(Error::InvalidToken)
    );
    assert_eq!(
        store.refresh_session(&session.access_jwt).err(),
        Some(Error::InvalidToken)
    );
    assert_eq!(
        store.delete_session(&session.access_jwt),
        Err(Error::InvalidToken)
    );
    for (token, typ, scope) in [
        (&session.access_jwt, "at+jwt", "com.atproto.appPass"),
        (&session.refresh_jwt, "refresh+jwt", "com.atproto.refresh"),
    ] {
        let header: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(token.split('.').next().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(header["alg"], "HS256");
        assert_eq!(header["typ"], typ);
        assert_eq!(decode(token)["scope"], scope);
        assert_eq!(decode(token)["aud"], "did:web:pds.example.com");
    }
}

#[test]
fn refresh_prevalidation_does_not_consume_but_rejects_rotated_and_wrong_type() {
    let (_directory, mut store) = store();
    let (_, session) = login(&mut store);
    store.validate_refresh(&session.refresh_jwt).unwrap();
    store.validate_refresh(&session.refresh_jwt).unwrap();
    assert_eq!(
        store.validate_refresh(&session.access_jwt).err(),
        Some(Error::InvalidToken)
    );
    let fresh = store.refresh_session(&session.refresh_jwt).unwrap();
    assert_eq!(
        store.validate_refresh(&session.refresh_jwt).err(),
        Some(Error::InvalidToken)
    );
    store.validate_refresh(&fresh.refresh_jwt).unwrap();
}

#[test]
fn explicit_localhost_binding_has_real_empty_repository_and_valid_session() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = Store::open(directory.path()).unwrap();
    let identity = Identity {
        handle: "psky.test".into(),
        did: "did:web:localhost%3A8787".into(),
        service_url: "http://localhost:8787".into(),
        service_did: "did:web:localhost%3A8787".into(),
    };
    let account = store.bind_verified(8531, "0xabc123", identity).unwrap();
    let password = store.issue_password("Bluesky").unwrap();
    let session = store.authenticate("psky.test", &password.password).unwrap();
    assert_eq!(session.info.did, "did:web:localhost%3A8787");
    let public = bs58::decode(&account.public_key_multibase[1..])
        .into_vec()
        .unwrap();
    store.repository().unwrap().verify(&public[2..]).unwrap();
}

#[test]
fn refresh_rotates_once_and_survives_restart() {
    let (directory, mut store) = store();
    let (_, original) = login(&mut store);
    let fresh = store.refresh_session(&original.refresh_jwt).unwrap();
    assert_ne!(original.access_jwt, fresh.access_jwt);
    assert_ne!(original.refresh_jwt, fresh.refresh_jwt);
    assert_eq!(
        store.refresh_session(&original.refresh_jwt).err(),
        Some(Error::InvalidToken)
    );
    store.get_session(&fresh.access_jwt).unwrap();
    drop(store);
    let mut store = Store::open(directory.path()).unwrap();
    store.clock = Some(1_789_480_000);
    assert_eq!(
        store.refresh_session(&original.refresh_jwt).err(),
        Some(Error::InvalidToken)
    );
    store.refresh_session(&fresh.refresh_jwt).unwrap();
}

#[test]
fn simultaneous_stores_cannot_replay_refresh() {
    let (directory, mut first) = store();
    let (_, original) = login(&mut first);
    let mut second = Store::open(directory.path()).unwrap();
    second.clock = first.clock;
    first.refresh_session(&original.refresh_jwt).unwrap();
    assert_eq!(
        second.refresh_session(&original.refresh_jwt).err(),
        Some(Error::InvalidToken)
    );
}

#[test]
fn logout_revokes_both_kinds_without_revoking_other_sessions() {
    let (_directory, mut store) = store();
    let (password, first) = login(&mut store);
    let second = store
        .authenticate("alice.example.com", &password.password)
        .unwrap();
    store.delete_session(&first.refresh_jwt).unwrap();
    assert_eq!(
        store.get_session(&first.access_jwt).err(),
        Some(Error::InvalidToken)
    );
    assert_eq!(
        store.refresh_session(&first.refresh_jwt).err(),
        Some(Error::InvalidToken)
    );
    store.get_session(&second.access_jwt).unwrap();
}

#[test]
fn password_revocation_kills_all_derived_sessions_only() {
    let (_directory, mut store) = store();
    let (password, first) = login(&mut store);
    let second = store
        .authenticate("alice.example.com", &password.password)
        .unwrap();
    let other = store.issue_password("Other").unwrap();
    let keep = store
        .authenticate("alice.example.com", &other.password)
        .unwrap();
    store.revoke_password("Bluesky").unwrap();
    store.revoke_password("Bluesky").unwrap();
    for session in [first, second] {
        assert_eq!(
            store.get_session(&session.access_jwt).err(),
            Some(Error::InvalidToken)
        );
        assert_eq!(
            store.refresh_session(&session.refresh_jwt).err(),
            Some(Error::InvalidToken)
        );
    }
    assert_eq!(
        store
            .authenticate("alice.example.com", &password.password)
            .err(),
        Some(Error::InvalidCredentials)
    );
    store.get_session(&keep.access_jwt).unwrap();
}

#[test]
fn authority_invalidation_is_durable_and_requires_fresh_binding() {
    let (directory, mut store) = store();
    let (password, session) = login(&mut store);
    store.set_evidence("verified-proof").unwrap();
    store.invalidate_authority().unwrap();
    assert_eq!(store.issue_password("blocked").err(), Some(Error::Disabled));
    assert_eq!(
        store.get_session(&session.access_jwt).err(),
        Some(Error::InvalidToken)
    );
    assert!(store.evidence().unwrap().is_none());
    drop(store);
    let mut store = Store::open(directory.path()).unwrap();
    assert!(!store.account().unwrap().unwrap().enabled);
    store.bind_verified(8531, "0xdef456", identity()).unwrap();
    assert!(store.list_passwords().unwrap().is_empty());
    assert_eq!(
        store
            .authenticate("alice.example.com", &password.password)
            .err(),
        Some(Error::InvalidCredentials)
    );
    assert_eq!(store.account().unwrap().unwrap().authority, "0xdef456");
}

#[test]
fn expired_access_refresh_and_future_issued_tokens_are_rejected() {
    let (_directory, mut store) = store();
    let (_, session) = login(&mut store);
    let start = store.now();
    store.clock = Some(start + ACCESS_SECONDS);
    assert_eq!(
        store.get_session(&session.access_jwt).err(),
        Some(Error::ExpiredToken)
    );
    store.clock = Some(start + REFRESH_SECONDS);
    assert_eq!(
        store.refresh_session(&session.refresh_jwt).err(),
        Some(Error::ExpiredToken)
    );
    store.clock = Some(start - 1);
    assert_eq!(
        store.get_session(&session.access_jwt).err(),
        Some(Error::InvalidToken)
    );
}

#[test]
fn refresh_does_not_extend_absolute_session_expiry() {
    let (_directory, mut store) = store();
    let (_, first) = login(&mut store);
    let start = store.now();
    store.clock = Some(start + REFRESH_SECONDS - 20);
    let next = store.refresh_session(&first.refresh_jwt).unwrap();
    assert_eq!(
        decode(&first.refresh_jwt)["exp"],
        decode(&next.refresh_jwt)["exp"]
    );
    assert_eq!(decode(&next.access_jwt)["exp"], start + REFRESH_SECONDS);
    store.clock = Some(start + REFRESH_SECONDS);
    assert_eq!(
        store.get_session(&next.access_jwt).err(),
        Some(Error::ExpiredToken)
    );
}

#[test]
fn token_claims_are_strict_even_with_a_valid_signature() {
    let (_directory, mut store) = store();
    let (_, session) = login(&mut store);
    let header = json!({"alg":"HS256","typ":"at+jwt"});
    for (field, value) in [
        ("aud", json!("did:web:other.example.com")),
        ("sub", json!("did:web:bob.example.com")),
        ("scope", json!("com.atproto.access")),
        ("jti", json!("short")),
        ("sid", json!("a".repeat(64))),
        ("exp", json!(store.now() + ACCESS_SECONDS + 1)),
        ("iat", json!(store.now() + 1)),
        ("extra", json!("value")),
    ] {
        let mut claims = decode(&session.access_jwt);
        claims[field] = value;
        let token = signed_custom(&store.jwt_key, header.clone(), claims);
        assert_eq!(
            store.get_session(&token).err(),
            Some(Error::InvalidToken),
            "{field}"
        );
    }
    for header in [
        json!({"alg":"none","typ":"at+jwt"}),
        json!({"alg":"HS512","typ":"at+jwt"}),
        json!({"alg":"HS256","typ":"JWT"}),
        json!({"alg":"HS256","typ":"at+jwt","jku":"https://evil.example"}),
    ] {
        let token = signed_custom(&store.jwt_key, header, decode(&session.access_jwt));
        assert_eq!(store.get_session(&token).err(), Some(Error::InvalidToken));
    }
}

#[test]
fn token_structure_tampering_and_size_are_rejected() {
    let (_directory, mut store) = store();
    let (_, session) = login(&mut store);
    let altered = format!("{}x", session.access_jwt);
    let extra = format!("{}.extra", session.access_jwt);
    for token in ["", "a.b.c", &altered, &extra, &"a".repeat(4097)] {
        assert_eq!(store.get_session(token).err(), Some(Error::InvalidToken));
    }
}

#[test]
fn password_and_session_limits_recover_after_revocation_or_expiry() {
    let (_directory, mut store) = store();
    let password = store.issue_password("Bluesky").unwrap();
    for _ in 0..MAX_SESSIONS {
        store
            .authenticate("alice.example.com", &password.password)
            .unwrap();
    }
    assert_eq!(
        store
            .authenticate("alice.example.com", &password.password)
            .err(),
        Some(Error::Limit)
    );
    store.clock = Some(store.now() + REFRESH_SECONDS);
    store
        .authenticate("alice.example.com", &password.password)
        .unwrap();
}

#[test]
fn evidence_is_bounded_private_and_persistent() {
    let (directory, mut store) = store();
    assert_eq!(store.set_evidence(""), Err(Error::InvalidInput));
    assert_eq!(
        store.set_evidence(&"a".repeat(32 * 1024 + 1)),
        Err(Error::InvalidInput)
    );
    store
        .set_evidence("{\"proof\":\"signed-message\"}")
        .unwrap();
    assert!(!serde_json::to_string(&store.account().unwrap())
        .unwrap()
        .contains("signed-message"));
    drop(store);
    let store = Store::open(directory.path()).unwrap();
    assert_eq!(
        store.evidence().unwrap().as_deref(),
        Some("{\"proof\":\"signed-message\"}")
    );
}

#[test]
fn newer_or_corrupt_database_is_rejected() {
    let (directory, store) = store();
    store
        .connection
        .execute_batch("PRAGMA user_version=999")
        .unwrap();
    drop(store);
    assert_eq!(
        Store::open(directory.path()).err(),
        Some(Error::Persistence)
    );
    let fresh = tempfile::tempdir().unwrap();
    prepare_directory(&fresh.path().join("credentials")).unwrap();
    prepare_database(&fresh.path().join("credentials/state.sqlite3")).unwrap();
    fs::write(
        fresh.path().join("credentials/state.sqlite3"),
        b"not a database",
    )
    .unwrap();
    assert_eq!(Store::open(fresh.path()).err(), Some(Error::Persistence));
}

#[cfg(unix)]
#[test]
fn private_storage_permissions_and_symlink_rejection() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let (directory, store) = store();
    let private = directory.path().join("credentials");
    let db = private.join("state.sqlite3");
    assert_eq!(
        fs::metadata(&private).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&db).unwrap().permissions().mode() & 0o777,
        0o600
    );
    drop(store);
    fs::set_permissions(&db, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        Store::open(directory.path()).err(),
        Some(Error::Persistence)
    );
    fs::set_permissions(&db, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(&private, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        Store::open(directory.path()).err(),
        Some(Error::Persistence)
    );
    let link_dir = tempfile::tempdir().unwrap();
    symlink(&private, link_dir.path().join("credentials")).unwrap();
    assert_eq!(Store::open(link_dir.path()).err(), Some(Error::Persistence));
}

#[cfg(unix)]
#[test]
fn database_symlink_and_hardlink_are_rejected() {
    use std::os::unix::fs::symlink;
    let (directory, store) = store();
    drop(store);
    let fresh = tempfile::tempdir().unwrap();
    prepare_directory(&fresh.path().join("credentials")).unwrap();
    let linked = fresh.path().join("credentials/state.sqlite3");
    symlink(directory.path().join("credentials/state.sqlite3"), &linked).unwrap();
    assert_eq!(Store::open(fresh.path()).err(), Some(Error::Persistence));
    let hard = tempfile::tempdir().unwrap();
    prepare_directory(&hard.path().join("credentials")).unwrap();
    fs::hard_link(
        directory.path().join("credentials/state.sqlite3"),
        hard.path().join("credentials/state.sqlite3"),
    )
    .unwrap();
    assert_eq!(Store::open(hard.path()).err(), Some(Error::Persistence));
}

#[cfg(unix)]
#[test]
fn sqlite_rollback_journal_is_private_and_no_wal_is_created() {
    use std::os::unix::fs::PermissionsExt;
    let (directory, store) = store();
    store
        .connection
        .execute_batch("BEGIN IMMEDIATE; UPDATE secrets SET jwt_key=jwt_key WHERE id=1;")
        .unwrap();
    let private = directory.path().join("credentials");
    // A real mutation makes SQLite materialize its rollback journal.
    store
        .connection
        .execute("INSERT INTO evidence(id,document) VALUES(1,'test')", [])
        .unwrap();
    let journal = private.join("state.sqlite3-journal");
    assert_eq!(
        fs::metadata(journal).unwrap().permissions().mode() & 0o077,
        0
    );
    assert!(!private.join("state.sqlite3-wal").exists());
    store.connection.execute_batch("ROLLBACK;").unwrap();
}
