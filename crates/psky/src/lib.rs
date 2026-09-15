//! PurpleSky's operator tools and **offline** reconstruction laboratory.
//!
//! [`account`] supports Farcaster sign-in and revocable ATProto password
//! sessions. No content write path is enabled. [`lab`] exercises standard
//! repository construction with synthetic records; it does not claim that
//! Hypersnap can persist these records. See `docs/storage-feasibility.md`.
//!
//! Run `cargo doc --workspace --no-deps` to generate the API reference from
//! these module comments and public item documentation.

#![deny(missing_docs)]

pub mod account;
pub mod journal;
pub mod lab;
pub mod server;
pub mod settings;
