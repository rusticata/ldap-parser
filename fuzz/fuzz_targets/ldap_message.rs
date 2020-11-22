#![no_main]
use libfuzzer_sys::fuzz_target;
use ldap_parser::parse_ldap_message;

fuzz_target!(|data: &[u8]| {
    let _ = parse_ldap_message(data);
});
