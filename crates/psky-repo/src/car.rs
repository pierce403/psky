//! CARv1 export only. Untrusted CAR import is intentionally out of scope.

use crate::{encode, Cid, Error};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Serialize)]
struct Header {
    roots: Vec<Cid>,
    version: u64,
}

pub(crate) fn export(root: Cid, blocks: &BTreeMap<Cid, Vec<u8>>) -> Result<Vec<u8>, Error> {
    let header = encode(&Header {
        roots: vec![root],
        version: 1,
    })?;
    let mut out = Vec::new();
    varint(header.len(), &mut out);
    out.extend(header);
    let root_bytes = blocks
        .get(&root)
        .ok_or_else(|| Error::Verification("missing CAR root".into()))?;
    block(root, root_bytes, &mut out);
    for (cid, bytes) in blocks {
        if *cid != root {
            block(*cid, bytes, &mut out);
        }
    }
    Ok(out)
}

fn block(cid: Cid, bytes: &[u8], out: &mut Vec<u8>) {
    let encoded = cid.to_bytes();
    varint(encoded.len() + bytes.len(), out);
    out.extend(encoded);
    out.extend(bytes);
}

fn varint(mut n: usize, out: &mut Vec<u8>) {
    while n >= 128 {
        out.push((n as u8 & 0x7f) | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}
