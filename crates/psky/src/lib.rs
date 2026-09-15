//! PurpleSky's operator tools and **offline** reconstruction laboratory.
//!
//! No network write path or Farcaster login is implemented yet. The public
//! listener rejects production PDS operations. [`lab`] exercises standard
//! repository construction with synthetic records; it does not claim that
//! Hypersnap can persist these records. See `docs/storage-feasibility.md`.
//!
//! Run `cargo doc --workspace --no-deps` to generate the API reference from
//! these module comments and public item documentation.

#![deny(missing_docs)]

pub mod journal;
pub mod lab;
pub mod server;
pub mod settings;
