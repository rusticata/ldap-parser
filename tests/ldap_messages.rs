use ldap_parser::ldap::{LdapMessage, ProtocolOp, SearchScope};
use ldap_parser::FromBer;

#[test]
fn test_malformed_empty() {
    const DATA: &[u8] = include_bytes!("../assets/malformed-message-empty.bin");

    LdapMessage::from_ber(DATA).expect_err("expected error");
}

#[test]
fn test_parse_msg_search_request_01() {
    const DATA: &[u8] = include_bytes!("../assets/message-search-request-01.bin");
    let (rem, msg) = LdapMessage::from_ber(DATA).expect("parsing failed");
    //
    // dbg!(&msg);
    //
    assert!(rem.is_empty());
    if let ProtocolOp::SearchRequest(req) = msg.protocol_op {
        assert_eq!(&req.base_object.0, "dc=rccad,dc=net");
        assert_eq!(req.scope, SearchScope::WholeSubtree);
        assert_eq!(req.size_limit, 10);
        assert_eq!(req.attributes.len(), 22);
    }
}
