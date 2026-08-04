use asn1_rs::FromBer;
use ldap_parser::{filter::Filter, ldap::MAX_FILTER_DEPTH};

fn encode_recursive_filter(depth: usize) -> Vec<u8> {
    // manually encoded Filter::Present("test")
    let f0 = b"\xA7\x04test";

    // Wrap in "Not" until depth is reached
    (1..depth).fold(f0.to_vec(), |acc, _| {
        let len = acc.len();
        assert!(len < 127);
        let mut v = vec![0xA2, len as u8];
        v.extend(acc);
        v
    })
}

#[test]
fn ldap_filter_recursion() {
    // Allowed depth
    let d = encode_recursive_filter(MAX_FILTER_DEPTH);
    let _ = Filter::from_ber(&d).expect("Valid Filter depth");

    // Invalid depth (above limit)
    let d = encode_recursive_filter(MAX_FILTER_DEPTH + 1);
    let _ = Filter::from_ber(&d).expect_err("Above max Filter depth");
}
