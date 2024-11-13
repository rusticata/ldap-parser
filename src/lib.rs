//! [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
//! [![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
//! [![docs.rs](https://docs.rs/ldap-parser/badge.svg)](https://docs.rs/ldap-parser)
//! [![crates.io](https://img.shields.io/crates/v/ldap-parser.svg)](https://crates.io/crates/ldap-parser)
//! [![Github CI](https://github.com/rusticata/ldap-parser/workflows/Continuous%20integration/badge.svg)](https://github.com/rusticata/ldap-parser/actions)
//! [![Minimum rustc version](https://img.shields.io/badge/rustc-1.44.0+-lightgray.svg)](#rust-version-requirements)
//!
//! # LDAP Parser
//!
//! A Lightweight Directory Access Protocol (LDAP) ([RFC4511]) parser, implemented with the
//! [nom](https://github.com/Geal/nom) parser combinator framework.
//!
//! It is written in pure Rust, fast, and makes extensive use of zero-copy. A lot of care is taken
//! to ensure security and safety of this crate, including design (recursion limit, defensive
//! programming), tests, and fuzzing. It also aims to be panic-free.
//!
//! The code is available on [Github](https://github.com/rusticata/ldap-parser)
//! and is part of the [Rusticata](https://github.com/rusticata) project.
//!
//! # Examples
//!
//! Parsing an LDAP message (in BER format):
//!
//! ```rust
//! use ldap_parser::FromBer;
//! use ldap_parser::ldap::{LdapMessage, MessageID, ProtocolOp, ProtocolOpTag};
//!
//! static DATA: &[u8] = include_bytes!("../assets/message-search-request-01.bin");
//!
//! # fn main() {
//! let res = LdapMessage::from_ber(DATA);
//! match res {
//!     Ok((rem, msg)) => {
//!         assert!(rem.is_empty());
//!         //
//!         assert_eq!(msg.message_id, MessageID(4));
//!         assert_eq!(msg.protocol_op.tag(), ProtocolOpTag::SearchRequest);
//!         match msg.protocol_op {
//!             ProtocolOp::SearchRequest(req) => {
//!                 assert_eq!(req.base_object.0, "dc=rccad,dc=net");
//!             },
//!             _ => panic!("Unexpected message type"),
//!         }
//!     },
//!     _ => panic!("LDAP parsing failed: {:?}", res),
//! }
//! # }
//! ```
//!
//! [RFC4511]: https://tools.ietf.org/html/rfc4511

#![deny(/*missing_docs,*/
        unstable_features,
        unused_import_braces, unused_qualifications)]
#![warn(
    missing_debug_implementations,
    /* missing_docs,
    rust_2018_idioms,*/
    unreachable_pub
)]
#![forbid(unsafe_code)]
#![deny(rustdoc::broken_intra_doc_links)]
#![doc(test(
    no_crate_inject,
    attr(deny(warnings, rust_2018_idioms), allow(dead_code, unused_variables))
))]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod error;
pub mod filter;
mod filter_parser;
pub mod ldap;
mod parser;

pub use parser::*;

pub use asn1_rs;
pub use asn1_rs::nom::{Err, IResult};
pub use asn1_rs::FromBer;
