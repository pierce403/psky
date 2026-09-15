use super::*;
use proptest::prelude::*;
use serde_json::json;
use std::io::Cursor;

const DID: &str = "did:plc:abcdefghijklmnopqrstuvwx";
const REV: &str = "3jzfcijpj2z2a";
const PATH: &str = "app.bsky.feed.post/3jzfcijpj2z2a";

fn post(text: &str) -> Value {
    json!({"$type":"app.bsky.feed.post","text":text,"createdAt":"2026-09-15T00:00:00Z"})
}

fn signer() -> RepoSigner {
    RepoSigner::from_bytes([1; 32]).unwrap()
}

fn repo() -> Repository {
    let mut records = RecordSet::new();
    records.put(PATH, &post("Hello")).unwrap();
    Repository::build(DID, REV, &records, &signer()).unwrap()
}

fn vector_root(keys: &[&str]) -> String {
    // Upstream @atproto/repo vectors at commit 2e1787c2bf5bd47b55c3df930d688bb40b5ae63d.
    let cid: Cid = "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454"
        .parse()
        .unwrap();
    let map = keys
        .iter()
        .map(|k| (format!("com.example.record/{k}"), cid))
        .collect();
    mst::build(&map, &mut BTreeMap::new()).unwrap().to_string()
}

#[test]
fn official_mst_known_maps() {
    for (keys, expected) in [
        (
            vec![],
            "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm",
        ),
        (
            vec!["3jqfcqzm3fo2j"],
            "bafyreibj4lsc3aqnrvphp5xmrnfoorvru4wynt6lwidqbm2623a6tatzdu",
        ),
        (
            vec!["3jqfcqzm3fx2j"],
            "bafyreih7wfei65pxzhauoibu3ls7jgmkju4bspy4t2ha2qdjnzqvoy33ai",
        ),
        (
            vec![
                "3jqfcqzm3fp2j",
                "3jqfcqzm3fr2j",
                "3jqfcqzm3fs2j",
                "3jqfcqzm3ft2j",
                "3jqfcqzm4fc2j",
            ],
            "bafyreicmahysq4n6wfuxo522m6dpiy7z7qzym3dzs756t5n7nfdgccwq7m",
        ),
    ] {
        assert_eq!(vector_root(&keys), expected, "{keys:?}");
    }
}

#[test]
fn official_mst_empty_intermediate_nodes_and_root_trimming() {
    for (keys, expected) in [
        (
            vec!["3jqfcqzm3ft2j", "3jqfcqzm3fz2j"],
            "bafyreidfcktqnfmykz2ps3dbul35pepleq7kvv526g47xahuz3rqtptmky",
        ),
        (
            vec!["3jqfcqzm3ft2j", "3jqfcqzm3fx2j", "3jqfcqzm3fz2j"],
            "bafyreiavxaxdz7o7rbvr3zg2liox2yww46t7g6hkehx4i4h3lwudly7dhy",
        ),
        (
            vec![
                "3jqfcqzm3ft2j",
                "3jqfcqzm3fx2j",
                "3jqfcqzm3fz2j",
                "3jqfcqzm4fd2j",
            ],
            "bafyreig4jv3vuajbsybhyvb7gggvpwh2zszwfyttjrj6qwvcsp24h6popu",
        ),
        (
            vec![
                "3jqfcqzm3fn2j",
                "3jqfcqzm3fo2j",
                "3jqfcqzm3fp2j",
                "3jqfcqzm3fs2j",
                "3jqfcqzm3ft2j",
                "3jqfcqzm3fu2j",
            ],
            "bafyreifnqrwbk6ffmyaz5qtujqrzf5qmxf7cbxvgzktl4e3gabuxbtatv4",
        ),
        (
            vec![
                "3jqfcqzm3fn2j",
                "3jqfcqzm3fo2j",
                "3jqfcqzm3fp2j",
                "3jqfcqzm3ft2j",
                "3jqfcqzm3fu2j",
            ],
            "bafyreie4kjuxbwkhzg2i5dljaswcroeih4dgiqq6pazcmunwt2byd725vi",
        ),
    ] {
        assert_eq!(vector_root(&keys), expected, "{keys:?}");
    }
}

#[test]
fn official_mst_split_two_layers() {
    let mut keys = vec![
        "3jqfcqzm3fo2j",
        "3jqfcqzm3fp2j",
        "3jqfcqzm3fr2j",
        "3jqfcqzm3fs2j",
        "3jqfcqzm3ft2j",
        "3jqfcqzm3fz2j",
        "3jqfcqzm4fc2j",
        "3jqfcqzm4fd2j",
        "3jqfcqzm4ff2j",
        "3jqfcqzm4fg2j",
        "3jqfcqzm4fh2j",
    ];
    assert_eq!(
        vector_root(&keys),
        "bafyreiettyludka6fpgp33stwxfuwhkzlur6chs4d2v4nkmq2j3ogpdjem"
    );
    keys.push("3jqfcqzm3fx2j");
    assert_eq!(
        vector_root(&keys),
        "bafyreid2x5eqs4w4qxvc5jiwda4cien3gw2q6cshofxwnvv7iucrmfohpm"
    );
}

#[test]
fn official_key_depth_examples() {
    for (key, depth) in [
        ("2653ae71", 0),
        ("blue", 1),
        ("app.bsky.feed.post/454397e440ec", 4),
        ("app.bsky.feed.post/9adeb165882c", 8),
    ] {
        assert_eq!(mst::layer(key.as_bytes()), depth);
    }
}

#[test]
fn json_key_order_does_not_change_record_cid() {
    let mut a = RecordSet::new();
    let mut b = RecordSet::new();
    let first: Value =
        serde_json::from_str(r#"{"$type":"app.bsky.feed.post","text":"x","createdAt":"now"}"#)
            .unwrap();
    let second: Value =
        serde_json::from_str(r#"{"createdAt":"now","text":"x","$type":"app.bsky.feed.post"}"#)
            .unwrap();
    assert_eq!(a.put(PATH, &first).unwrap(), b.put(PATH, &second).unwrap());
}

#[test]
fn canonical_cbor_orders_by_utf8_key_length_then_bytes() {
    let map = Ipld::Map(BTreeMap::from([
        ("aa".into(), Ipld::Integer(2)),
        ("b".into(), Ipld::Integer(1)),
    ]));
    assert_eq!(
        encode(&map).unwrap(),
        vec![0xa2, 0x61, b'b', 1, 0x62, b'a', b'a', 2]
    );
}

#[test]
fn cids_are_v1_dag_cbor_sha256() {
    let r = repo();
    for cid in r.blocks.keys() {
        assert_eq!(cid.version(), cid::Version::V1);
        assert_eq!(cid.codec(), 0x71);
        assert_eq!(cid.hash().code(), 0x12);
        assert_eq!(cid.hash().size(), 32);
    }
}

#[test]
fn signing_is_deterministic_and_low_s() {
    let a = repo();
    let b = repo();
    assert_eq!(a.root(), b.root());
    assert_eq!(a.to_car().unwrap(), b.to_car().unwrap());
    assert_eq!(a.commit.sig.len(), 64);
    assert!(Signature::from_slice(&a.commit.sig)
        .unwrap()
        .normalize_s()
        .is_none());
    a.verify(&signer().public_key_sec1()).unwrap();
}

#[test]
fn changing_rev_changes_commit_but_not_mst() {
    let a = repo();
    let b = Repository::build(DID, "3jzfcijpj2z2b", a.records(), &signer()).unwrap();
    assert_ne!(a.root(), b.root());
    assert_eq!(a.mst_root(), b.mst_root());
}

#[test]
fn changing_did_changes_commit() {
    let a = repo();
    let b = Repository::build("did:web:example.com", REV, a.records(), &signer()).unwrap();
    assert_ne!(a.root(), b.root());
    assert_eq!(a.mst_root(), b.mst_root());
}

#[test]
fn changing_key_changes_commit_but_not_mst() {
    let a = repo();
    let key = RepoSigner::from_bytes([2; 32]).unwrap();
    let b = Repository::build(DID, REV, a.records(), &key).unwrap();
    assert_ne!(a.root(), b.root());
    assert_eq!(a.mst_root(), b.mst_root());
    assert!(a.verify(&key.public_key_sec1()).is_err());
}

#[test]
fn commit_contains_required_null_prev_and_no_extra_fields() {
    let r = repo();
    let Ipld::Map(map) = decode(r.block(&r.root()).unwrap()).unwrap() else {
        panic!("commit object");
    };
    assert_eq!(map.len(), 6);
    assert_eq!(map.get("prev"), Some(&Ipld::Null));
    assert_eq!(map.get("version"), Some(&Ipld::Integer(3)));
    assert_eq!(map.get("data"), Some(&Ipld::Link(r.mst_root())));
}

#[test]
fn tampered_and_missing_blocks_fail_verification() {
    let original = repo();
    for cid in original.blocks.keys() {
        let mut damaged = original.clone();
        damaged.blocks.get_mut(cid).unwrap()[0] ^= 1;
        assert!(damaged.verify(&signer().public_key_sec1()).is_err());
        let mut missing = original.clone();
        missing.blocks.remove(cid);
        assert!(missing.verify(&signer().public_key_sec1()).is_err());
    }
}

#[test]
fn malformed_secret_scalars_are_rejected() {
    assert!(RepoSigner::from_bytes([0; 32]).is_err());
    assert!(RepoSigner::from_bytes([255; 32]).is_err());
}

#[test]
fn invalid_path_cannot_mutate_projection() {
    let mut records = RecordSet::new();
    records.put(PATH, &post("before")).unwrap();
    let original = records.clone();
    for path in [
        "",
        "app.bsky.feed.post",
        "/abc",
        "app.bsky.feed.post/",
        "app.bsky.feed.post/a/b",
        "app.bsky.feed.post/..",
        "app.bsky.feed.post/.",
        "app.bsky.feed.post/☃",
        "app.bsky.feed.post/a b",
        "app.bsky.feed.post/%00",
        "1com.example.record/x",
        "com.example.0record/x",
        "com.-example.record/x",
        "COM.example.record/x",
    ] {
        assert!(records.put(path, &post("changed")).is_err(), "{path}");
        assert!(records.delete(path).is_err(), "{path}");
        assert_eq!(records, original);
    }
}

#[test]
fn valid_record_key_punctuation_and_case_are_preserved() {
    let mut records = RecordSet::new();
    for key in ["self", "A", "a", "example.com", "~1.2-3_", "pre:fix", "_"] {
        let path = format!("app.bsky.feed.post/{key}");
        records.put(&path, &post(key)).unwrap();
        assert!(records.get(&path).is_some());
    }
    assert_eq!(records.len(), 7);
}

#[test]
fn path_length_boundaries() {
    let mut records = RecordSet::new();
    assert!(records
        .put(
            &format!("app.bsky.feed.post/{}", "a".repeat(512)),
            &post("x")
        )
        .is_ok());
    assert!(records
        .put(
            &format!("app.bsky.feed.post/{}", "a".repeat(513)),
            &post("x")
        )
        .is_err());
}

#[test]
fn invalid_dids_and_tids_are_rejected() {
    for did in [
        "",
        "did:farcaster:123",
        "did:plc:abc",
        "did:plc:ABCDEFGHIJKLMNOPQRSTUVWX",
        "did:web:example.com:users:a",
        "did:web:EXAMPLE.com",
        "did:web:127.0.0.1",
        "did:web:example..com",
    ] {
        assert!(
            Repository::build(did, REV, &RecordSet::new(), &signer()).is_err(),
            "{did}"
        );
    }
    for rev in [
        "",
        "222",
        "0000000000000",
        "3JZFCIJPJ2Z2A",
        "zzzzzzzzzzzzz",
        "kjzfcijpj2z2a",
        "3jzf-cij-pj2z-2a",
    ] {
        assert!(
            Repository::build(DID, rev, &RecordSet::new(), &signer()).is_err(),
            "{rev}"
        );
    }
}

#[test]
fn wrong_type_and_unsupported_values_leave_existing_record_unchanged() {
    let mut records = RecordSet::new();
    records.put(PATH, &post("old")).unwrap();
    let old = records.clone();
    for value in [
        json!({"text":"missing type"}),
        json!({"$type":"app.bsky.actor.profile"}),
        json!({"$type":"app.bsky.feed.post","n":1.5}),
        json!({"$type":"app.bsky.feed.post","n":9007199254740992u64}),
        json!({"$type":"app.bsky.feed.post","n":-9007199254740992i64}),
    ] {
        assert!(records.put(PATH, &value).is_err());
        assert_eq!(records, old);
    }
}

#[test]
fn size_and_depth_limits_reject_before_mutation() {
    let mut records = RecordSet::new();
    assert!(records
        .put(PATH, &post(&"x".repeat(MAX_RECORD_BYTES)))
        .is_err());
    let mut nested = Value::Null;
    for _ in 0..MAX_RECORD_DEPTH + 1 {
        nested = json!([nested]);
    }
    assert!(records
        .put(PATH, &json!({"$type":"app.bsky.feed.post","nested":nested}))
        .is_err());
    assert!(records.is_empty());
}

#[test]
fn aggregate_bytes_limit_accounts_for_replacements_and_deletions() {
    let value = post(&"x".repeat(MAX_RECORD_BYTES / 2));
    let mut records = RecordSet::new();
    records.put(PATH, &value).unwrap();
    let bytes_per_record = records.get(PATH).unwrap().bytes().len();
    let capacity = MAX_TOTAL_RECORD_BYTES / bytes_per_record;
    for n in 1..capacity {
        records
            .put(&format!("app.bsky.feed.post/k{n}"), &value)
            .unwrap();
    }
    assert_eq!(records.encoded_bytes(), capacity * bytes_per_record);
    let additional = "app.bsky.feed.post/overflow";
    assert!(matches!(
        records.put(additional, &value),
        Err(Error::Limit("aggregate record bytes"))
    ));
    assert_eq!(records.len(), capacity);
    assert!(records.get(additional).is_none());
    assert_eq!(records.encoded_bytes(), capacity * bytes_per_record);

    // Replacement must subtract the old value before checking the new budget.
    records.put(PATH, &value).unwrap();
    assert_eq!(records.encoded_bytes(), capacity * bytes_per_record);
    let old_cid = records.get(PATH).unwrap().cid();
    assert!(matches!(
        records.put(PATH, &post(&"x".repeat(MAX_RECORD_BYTES - 200))),
        Err(Error::Limit("aggregate record bytes"))
    ));
    assert_eq!(records.get(PATH).unwrap().cid(), old_cid);
    assert_eq!(records.encoded_bytes(), capacity * bytes_per_record);

    records.put(PATH, &post("small")).unwrap();
    let smaller_bytes = records.get(PATH).unwrap().bytes().len();
    assert_eq!(
        records.encoded_bytes(),
        (capacity - 1) * bytes_per_record + smaller_bytes
    );
    records.put(additional, &value).unwrap();
    assert_eq!(
        records.encoded_bytes(),
        capacity * bytes_per_record + smaller_bytes
    );
    records.delete(additional).unwrap();
    assert_eq!(
        records.encoded_bytes(),
        (capacity - 1) * bytes_per_record + smaller_bytes
    );
    assert!(!records.delete(additional).unwrap());
    assert_eq!(
        records.encoded_bytes(),
        records.iter().map(|(_, r)| r.bytes().len()).sum::<usize>()
    );
    for (path, _) in records.clone().iter() {
        records.delete(path).unwrap();
    }
    assert_eq!(records.encoded_bytes(), 0);
    assert!(records.is_empty());
}

#[test]
fn native_cid_links_and_bytes_are_encoded_as_ipld() {
    let link = repo().root();
    let mut records = RecordSet::new();
    records.put(PATH,&json!({"$type":"app.bsky.feed.post","reference":{"$link":link.to_string()},"raw":{"$bytes":"AAEC"}})).unwrap();
    let Ipld::Map(map) = decode(records.get(PATH).unwrap().bytes()).unwrap() else {
        panic!("record map");
    };
    assert_eq!(map.get("reference"), Some(&Ipld::Link(link)));
    assert_eq!(map.get("raw"), Some(&Ipld::Bytes(vec![0, 1, 2])));
}

#[test]
fn malformed_special_wrappers_are_rejected() {
    let mut records = RecordSet::new();
    for wrapper in [
        json!({"$link":"bad"}),
        json!({"$link":23}),
        json!({"$bytes":"?"}),
        json!({"$bytes":23}),
        json!({"$bytes":"AAEC","extra":true}),
    ] {
        assert!(records
            .put(PATH, &json!({"$type":"app.bsky.feed.post","v":wrapper}))
            .is_err());
    }
    assert!(records.is_empty());
}

#[test]
fn padded_and_unpadded_base64_produce_identical_records() {
    for (padded, unpadded, expected) in [
        ("", "", vec![]),
        ("AA==", "AA", vec![0]),
        ("AAE=", "AAE", vec![0, 1]),
        ("AAEC", "AAEC", vec![0, 1, 2]),
        ("+/8=", "+/8", vec![251, 255]),
    ] {
        let mut a = RecordSet::new();
        let mut b = RecordSet::new();
        let first = a
            .put(
                PATH,
                &json!({"$type":"app.bsky.feed.post","raw":{"$bytes":padded}}),
            )
            .unwrap();
        let second = b
            .put(
                PATH,
                &json!({"$type":"app.bsky.feed.post","raw":{"$bytes":unpadded}}),
            )
            .unwrap();
        assert_eq!(first, second);
        let Ipld::Map(map) = decode(a.get(PATH).unwrap().bytes()).unwrap() else {
            panic!("record");
        };
        assert_eq!(map.get("raw"), Some(&Ipld::Bytes(expected)));
    }
}

#[test]
fn base64_rejects_wrong_alphabet_trailing_bits_and_invalid_padding() {
    let mut records = RecordSet::new();
    records.put(PATH, &post("original")).unwrap();
    let original = records.clone();
    for encoded in [
        "-_8=", "_w", "-w", "AA\n", "AA ", "AB", "AB==", "AAF", "AAF=", "A", "A===", "AA===",
        "=AA", "AA=E",
    ] {
        assert!(
            records
                .put(
                    PATH,
                    &json!({"$type":"app.bsky.feed.post","raw":{"$bytes":encoded}})
                )
                .is_err(),
            "{encoded}"
        );
        assert_eq!(records, original);
    }
}

#[test]
fn blessed_raw_and_dag_cbor_links_are_accepted() {
    let hash = cid::multihash::Multihash::<64>::wrap(0x12, &[7; 32]).unwrap();
    for codec in [0x55, 0x71] {
        let cid = Cid::new_v1(codec, hash);
        let mut records = RecordSet::new();
        records
            .put(
                PATH,
                &json!({"$type":"app.bsky.feed.post","ref":{"$link":cid.to_string()}}),
            )
            .unwrap();
        let Ipld::Map(map) = decode(records.get(PATH).unwrap().bytes()).unwrap() else {
            panic!("record");
        };
        assert_eq!(map.get("ref"), Some(&Ipld::Link(cid)));
    }
}

#[test]
fn non_blessed_link_encodings_are_rejected_without_mutation() {
    let hash = cid::multihash::Multihash::<64>::wrap(0x12, &[7; 32]).unwrap();
    let cid = Cid::new_v1(0x71, hash);
    let mut records = RecordSet::new();
    records.put(PATH, &post("original")).unwrap();
    let original = records.clone();
    let invalid = [
        Cid::new_v0(hash).unwrap().to_string(),
        format!("/ipfs/{cid}"),
        cid.to_string().to_uppercase(),
        cid.to_string_of_base(cid::multibase::Base::Base58Btc)
            .unwrap(),
        cid.to_string_of_base(cid::multibase::Base::Base64).unwrap(),
        Cid::new_v1(0x70, hash).to_string(),
        Cid::new_v1(
            0x71,
            cid::multihash::Multihash::<64>::wrap(0x13, &[7; 64]).unwrap(),
        )
        .to_string(),
        Cid::new_v1(
            0x71,
            cid::multihash::Multihash::<64>::wrap(0x12, &[7; 16]).unwrap(),
        )
        .to_string(),
        Cid::new_v1(
            0x71,
            cid::multihash::Multihash::<64>::wrap(0x00, &[7; 32]).unwrap(),
        )
        .to_string(),
    ];
    for encoded in invalid {
        assert!(
            records
                .put(
                    PATH,
                    &json!({"$type":"app.bsky.feed.post","ref":{"$link":encoded}})
                )
                .is_err(),
            "{encoded}"
        );
        assert_eq!(records, original);
    }
}

#[test]
fn deleted_records_are_not_leaked_in_current_car() {
    let mut records = RecordSet::new();
    let gone = records.put(PATH, &post("secret gone")).unwrap();
    assert!(records.delete(PATH).unwrap());
    assert!(!records.delete(PATH).unwrap());
    let r = Repository::build(DID, REV, &records, &signer()).unwrap();
    assert!(r.block(&gone).is_none());
    assert_eq!(r.block_count(), 2);
    r.verify(&signer().public_key_sec1()).unwrap();
}

fn read_varint(bytes: &[u8], cursor: &mut usize) -> usize {
    let mut value = 0;
    let mut shift = 0;
    loop {
        let byte = bytes[*cursor];
        *cursor += 1;
        value |= usize::from(byte & 127) << shift;
        if byte < 128 {
            return value;
        }
        shift += 7;
    }
}

#[test]
fn car_framing_root_hashes_and_duplicate_elision() {
    let mut records = RecordSet::new();
    for key in ["one", "two"] {
        records
            .put(&format!("app.bsky.feed.post/{key}"), &post("identical"))
            .unwrap();
    }
    let r = Repository::build(DID, REV, &records, &signer()).unwrap();
    let bytes = r.to_car().unwrap();
    let mut offset = 0;
    let header_len = read_varint(&bytes, &mut offset);
    let Ipld::Map(header) = decode(&bytes[offset..offset + header_len]).unwrap() else {
        panic!("header");
    };
    assert_eq!(header.get("version"), Some(&Ipld::Integer(1)));
    assert_eq!(
        header.get("roots"),
        Some(&Ipld::List(vec![Ipld::Link(r.root())]))
    );
    offset += header_len;
    let mut found = BTreeMap::new();
    while offset < bytes.len() {
        let len = read_varint(&bytes, &mut offset);
        let mut cursor = Cursor::new(&bytes[offset..offset + len]);
        let cid = Cid::read_bytes(&mut cursor).unwrap();
        if found.is_empty() {
            assert_eq!(cid, r.root());
        }
        let data = &bytes[offset + cursor.position() as usize..offset + len];
        assert_eq!(cid, cid_for(data));
        assert!(found.insert(cid, data.to_vec()).is_none());
        offset += len;
    }
    assert_eq!(found, r.blocks);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn arbitrary_insert_order_reconstructs_identical_repo(keys in prop::collection::btree_set(0u16..500,0..75)) {
        let mut a = RecordSet::new();
        let mut b = RecordSet::new();
        for key in &keys { a.put(&format!("app.bsky.feed.post/k{key}"),&post(&key.to_string())).unwrap(); }
        for key in keys.iter().rev() { b.put(&format!("app.bsky.feed.post/k{key}"),&post(&key.to_string())).unwrap(); }
        let a = Repository::build(DID,REV,&a,&signer()).unwrap();
        let b = Repository::build(DID,REV,&b,&signer()).unwrap();
        prop_assert_eq!(a.root(),b.root());
        prop_assert_eq!(a.to_car().unwrap(),b.to_car().unwrap());
        a.verify(&signer().public_key_sec1()).unwrap();
    }

    #[test]
    fn arbitrary_updates_then_deletes_match_fresh_state(ops in prop::collection::vec((0u8..20,any::<bool>()),0..80)) {
        let mut changed = RecordSet::new();
        let mut expected = BTreeMap::new();
        for (key,delete) in ops {
            let path = format!("app.bsky.feed.post/k{key}");
            if delete { changed.delete(&path).unwrap(); expected.remove(&path); }
            else { let value = post(&key.to_string()); changed.put(&path,&value).unwrap(); expected.insert(path,value); }
        }
        let mut fresh = RecordSet::new();
        for (path,value) in expected { fresh.put(&path,&value).unwrap(); }
        let changed = Repository::build(DID,REV,&changed,&signer()).unwrap();
        let fresh = Repository::build(DID,REV,&fresh,&signer()).unwrap();
        prop_assert_eq!(changed.root(),fresh.root());
        prop_assert_eq!(changed.to_car().unwrap(),fresh.to_car().unwrap());
    }

    #[test]
    fn utf8_record_text_roundtrips(text in ".{0,400}") {
        let mut records = RecordSet::new();
        records.put(PATH,&post(&text)).unwrap();
        let Ipld::Map(map) = decode(records.get(PATH).unwrap().bytes()).unwrap() else { panic!("map"); };
        prop_assert_eq!(map.get("text"),Some(&Ipld::String(text)));
    }
}
