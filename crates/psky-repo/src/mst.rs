//! Batch MST construction. Links always descend exactly one layer, retaining
//! empty intermediate nodes. The root is at the highest occupied layer.

use crate::{cid_for, encode, Cid, Error};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Serialize)]
struct Node {
    l: Option<Cid>,
    e: Vec<Entry>,
}

#[derive(Serialize)]
struct Entry {
    p: usize,
    #[serde(with = "serde_bytes")]
    k: Vec<u8>,
    v: Cid,
    t: Option<Cid>,
}

pub(crate) fn layer(key: &[u8]) -> usize {
    let mut zeros = 0;
    for byte in Sha256::digest(key) {
        zeros += byte.leading_zeros() as usize;
        if byte != 0 {
            break;
        }
    }
    zeros / 2
}

pub(crate) fn build(
    mapping: &BTreeMap<String, Cid>,
    blocks: &mut BTreeMap<Cid, Vec<u8>>,
) -> Result<Cid, Error> {
    let entries: Vec<_> = mapping
        .iter()
        .map(|(k, v)| (k.as_bytes(), *v, layer(k.as_bytes())))
        .collect();
    let top = entries
        .iter()
        .map(|(_, _, layer)| *layer)
        .max()
        .unwrap_or(0);
    subtree(&entries, top, blocks)
}

fn subtree(
    entries: &[(&[u8], Cid, usize)],
    at: usize,
    blocks: &mut BTreeMap<Cid, Vec<u8>>,
) -> Result<Cid, Error> {
    let anchors: Vec<_> = entries
        .iter()
        .enumerate()
        .filter_map(|(i, (_, _, layer))| (*layer == at).then_some(i))
        .collect();
    let left_end = anchors.first().copied().unwrap_or(entries.len());
    let left = child(&entries[..left_end], at, blocks)?;
    let mut encoded_entries = Vec::with_capacity(anchors.len());
    let mut previous: &[u8] = &[];
    for (index, start) in anchors.iter().copied().enumerate() {
        let (key, value, _) = entries[start];
        let end = anchors.get(index + 1).copied().unwrap_or(entries.len());
        let tree = child(&entries[start + 1..end], at, blocks)?;
        let prefix = previous.iter().zip(key).take_while(|(a, b)| a == b).count();
        encoded_entries.push(Entry {
            p: prefix,
            k: key[prefix..].to_vec(),
            v: value,
            t: tree,
        });
        previous = key;
    }
    let bytes = encode(&Node {
        l: left,
        e: encoded_entries,
    })?;
    let cid = cid_for(&bytes);
    blocks.insert(cid, bytes);
    Ok(cid)
}

fn child(
    entries: &[(&[u8], Cid, usize)],
    parent_layer: usize,
    blocks: &mut BTreeMap<Cid, Vec<u8>>,
) -> Result<Option<Cid>, Error> {
    if entries.is_empty() {
        return Ok(None);
    }
    let at = parent_layer
        .checked_sub(1)
        .ok_or_else(|| Error::Verification("MST layer underflow".into()))?;
    subtree(entries, at, blocks).map(Some)
}
