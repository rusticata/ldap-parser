<!-- cargo-sync-readme start -->

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
[![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
[![docs.rs](https://docs.rs/ldap-parser/badge.svg)](https://docs.rs/ldap-parser)
[![crates.io](https://img.shields.io/crates/v/ldap-parser.svg)](https://crates.io/crates/ldap-parser)
[![Github CI](https://github.com/rusticata/ldap-parser/workflows/Continuous%20integration/badge.svg)](https://github.com/rusticata/ldap-parser/actions)
[![Minimum rustc version](https://img.shields.io/badge/rustc-1.44.0+-lightgray.svg)](#rust-version-requirements)

# LDAP Parser

A Lightweight Directory Access Protocol (LDAP) ([RFC4511]) parser, implemented with the
[nom](https://github.com/Geal/nom) parser combinator framework.

It is written in pure Rust, fast, and makes extensive use of zero-copy. A lot of care is taken
to ensure security and safety of this crate, including design (recursion limit, defensive
programming), tests, and fuzzing. It also aims to be panic-free.

The code is available on [Github](https://github.com/rusticata/ldap-parser)
and is part of the [Rusticata](https://github.com/rusticata) project.

# Examples

Parsing an LDAP message (in BER format):

```rust
use ldap_parser::parse_ldap_message;
use ldap_parser::ldap::{MessageID, ProtocolOp, ProtocolOpTag};

static DATA: &[u8] = include_bytes!("../assets/message-search-request-01.bin");

let res = parse_ldap_message(DATA);
match res {
    Ok((rem, msg)) => {
        assert!(rem.is_empty());
        //
        assert_eq!(msg.message_id, MessageID(4));
        assert_eq!(msg.protocol_op.tag(), ProtocolOpTag::SearchRequest);
        match msg.protocol_op {
            ProtocolOp::SearchRequest(req) => {
                assert_eq!(req.base_object.0, "dc=rccad,dc=net");
            },
            _ => panic!("Unexpected message type"),
        }
    },
    _ => panic!("LDAP parsing failed: {:?}", res),
}
```

[RFC4511]: https://tools.ietf.org/html/rfc4511
<!-- cargo-sync-readme end -->

## Changes

See [CHANGELOG.md](CHANGELOG.md)

# License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
