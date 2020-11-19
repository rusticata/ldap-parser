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
#![deny(broken_intra_doc_links)]
#![doc(test(
    no_crate_inject,
    attr(deny(warnings, rust_2018_idioms), allow(dead_code, unused_variables))
))]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod filter_parser;
pub mod error;
pub mod filter;
pub mod ldap;
pub mod ldap_parser;

pub extern crate nom;
pub use nom::{Err, IResult};
