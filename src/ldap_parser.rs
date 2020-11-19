// DEFINITIONS
// IMPLICIT TAGS
// EXTENSIBILITY IMPLIED

use crate::error::*;
use crate::filter::*;
use crate::filter_parser::*;
use crate::ldap::*;
use der_parser::ber::*;
use nom::bytes::streaming::take;
use nom::combinator::{complete, map, map_res, opt, verify};
use nom::dbg_dmp;
use nom::multi::{many0, many1};
use nom::{Err, Needed};
use std::borrow::Cow;

// // maxInt INTEGER ::= 2147483647 -- (2^^31 - 1) --
// const MAX_INT: u32 = 2_147_483_647;

// MessageID ::= INTEGER (0 ..  maxInt)
fn parse_message_id(i: &[u8]) -> Result<MessageID> {
    map(parse_ber_u32, MessageID)(i).map_err(Err::convert)
}

// LDAPString ::= OCTET STRING -- UTF-8 encoded,
//                             -- [ISO10646] characters
pub(crate) fn parse_ldap_string(i: &[u8]) -> Result<LdapString> {
    let (i, b) = parse_ldap_octet_string_as_slice(i)?;
    // convert to UTF-8
    let s = std::str::from_utf8(b).or(Err(Err::Error(LdapError::InvalidString)))?;
    Ok((i, LdapString(Cow::Borrowed(s))))
}

#[inline]
fn parse_ldap_octet_string(i: &[u8]) -> Result<BerObject> {
    parse_ber_octetstring(i).map_err(Err::convert)
}

#[inline]
pub(crate) fn parse_ldap_octet_string_as_slice(i: &[u8]) -> Result<&[u8]> {
    map_res(parse_ldap_octet_string, |o| o.as_slice())(i)
}

#[inline]
fn parse_ldap_int_as_u32(i: &[u8]) -> Result<u32> {
    let (i, res) = parse_ber_u32(i).map_err(Err::convert)?;
    Ok((i, res))
}
#[inline]
fn parse_ldap_enum_as_u32(i: &[u8]) -> Result<u32> {
    let (i, obj) = parse_ber_enum(i).map_err(Err::convert)?;
    let scope = obj.as_u32().map_err(|e| Err::Error(LdapError::Ber(e)))?;
    Ok((i, scope))
}

// LDAPDN ::= LDAPString -- Constrained to <distinguishedName>
//                       -- [RFC4514]
fn parse_ldap_dn(i: &[u8]) -> Result<LdapDN> {
    // read bytes
    let (i, obj) = parse_ber_octetstring(i).map_err(Err::convert)?;
    let b = obj.as_slice().or(Err(Err::Error(LdapError::InvalidDN)))?;
    // convert to UTF-8
    let s = std::str::from_utf8(b).or(Err(Err::Error(LdapError::InvalidDN)))?;
    Ok((i, LdapDN(Cow::Borrowed(s))))
}

// RelativeLDAPDN ::= LDAPString -- Constrained to <name-component>
//                               -- [RFC4514]
fn parse_relative_ldap_dn(i: &[u8]) -> Result<RelativeLdapDN> {
    // read bytes
    let (i, obj) = parse_ber_octetstring(i).map_err(Err::convert)?;
    let b = obj.as_slice().or(Err(Err::Error(LdapError::InvalidDN)))?;
    // convert to UTF-8
    let s = std::str::from_utf8(b).or(Err(Err::Error(LdapError::InvalidDN)))?;
    Ok((i, RelativeLdapDN(Cow::Borrowed(s))))
}

// LDAPOID ::= OCTET STRING -- Constrained to <numericoid>
//                          -- [RFC4512]
fn parse_ldap_oid(i: &[u8]) -> Result<LdapOID> {
    // read bytes
    let (i, obj) = parse_ber_octetstring(i).map_err(Err::convert)?;
    let b = obj.as_slice().or(Err(Err::Error(LdapError::InvalidDN)))?;
    // convert to UTF-8
    let s = std::str::from_utf8(b).or(Err(Err::Error(LdapError::InvalidDN)))?;
    Ok((i, LdapOID(Cow::Borrowed(s))))
}

// URI ::= LDAPString     -- limited to characters permitted in
//                                -- URIs
#[inline]
fn parse_ldap_uri(i: &[u8]) -> Result<LdapString> {
    parse_ldap_string(i)
}

//
//
//
//
//
// ----------------------- LDAP OBJECTS -----------------------
//
//
//
//
//
//

// LDAPResult ::= SEQUENCE {
//      resultCode         ENUMERATED {
//           success                      (0),
//           operationsError              (1),
//           protocolError                (2),
//           timeLimitExceeded            (3),
//           sizeLimitExceeded            (4),
//           compareFalse                 (5),
//           compareTrue                  (6),
//           authMethodNotSupported       (7),
//           strongerAuthRequired         (8),
//                -- 9 reserved --
//           referral                     (10),
//           adminLimitExceeded           (11),
//           unavailableCriticalExtension (12),
//           confidentialityRequired      (13),
//           saslBindInProgress           (14),
//           noSuchAttribute              (16),
//           undefinedAttributeType       (17),
//           inappropriateMatching        (18),
//           constraintViolation          (19),
//           attributeOrValueExists       (20),
//           invalidAttributeSyntax       (21),
//                -- 22-31 unused --
//           noSuchObject                 (32),
//           aliasProblem                 (33),
//           invalidDNSyntax              (34),
//                -- 35 reserved for undefined isLeaf --
//           aliasDereferencingProblem    (36),
//                -- 37-47 unused --
//           inappropriateAuthentication  (48),
//           invalidCredentials           (49),
//           insufficientAccessRights     (50),
//           busy                         (51),
//           unavailable                  (52),
//           unwillingToPerform           (53),
//           loopDetect                   (54),
//                -- 55-63 unused --
//           namingViolation              (64),
//           objectClassViolation         (65),
//           notAllowedOnNonLeaf          (66),
//           notAllowedOnRDN              (67),
//           entryAlreadyExists           (68),
//           objectClassModsProhibited    (69),
//                -- 70 reserved for CLDAP --
//           affectsMultipleDSAs          (71),
//                -- 72-79 unused --
//           other                        (80),
//           ...  },
//      matchedDN          LDAPDN,
//      diagnosticMessage  LDAPString,
//      referral           [3] Referral OPTIONAL }
fn parse_ldap_result_content(i: &[u8]) -> Result<LdapResult> {
    let (i, result_code) = map(parse_ldap_enum_as_u32, ResultCode)(i)?;
    let (i, matched_dn) = parse_ldap_dn(i)?;
    let (i, diagnostic_message) = parse_ldap_string(i)?;
    let result = LdapResult {
        result_code,
        matched_dn,
        diagnostic_message,
    };
    Ok((i, result))
}

// LDAPMessage ::= SEQUENCE {
//      messageID       MessageID,
//      protocolOp      CHOICE {
//           bindRequest           BindRequest,
//           bindResponse          BindResponse,
//           unbindRequest         UnbindRequest,
//           searchRequest         SearchRequest,
//           searchResEntry        SearchResultEntry,
//           searchResDone         SearchResultDone,
//           searchResRef          SearchResultReference,
//           modifyRequest         ModifyRequest,
//           modifyResponse        ModifyResponse,
//           addRequest            AddRequest,
//           addResponse           AddResponse,
//           delRequest            DelRequest,
//           delResponse           DelResponse,
//           modDNRequest          ModifyDNRequest,
//           modDNResponse         ModifyDNResponse,
//           compareRequest        CompareRequest,
//           compareResponse       CompareResponse,
//           abandonRequest        AbandonRequest,
//           extendedReq           ExtendedRequest,
//           extendedResp          ExtendedResponse,
//           ...,
//           intermediateResponse  IntermediateResponse },
//      controls       [0] Controls OPTIONAL }
pub fn parse_ldap_message(i: &[u8]) -> Result<LdapMessage> {
    // print_hex_dump(i, 32);
    parse_ber_sequence_defined_g(|_, i| {
        let (i, message_id) = parse_message_id(i)?;
        // read header of next element and look tag value
        let (_, header) = ber_read_element_header(i).map_err(Err::convert)?;
        let (i, protocol_op) = match header.tag.0 {
            0 => map(parse_ldap_bind_request, ProtocolOp::BindRequest)(i),
            1 => map(parse_ldap_bind_response, ProtocolOp::BindResponse)(i),
            2 => parse_ldap_unbind_request(i),
            3 => map(parse_ldap_search_request, ProtocolOp::SearchRequest)(i),
            4 => map(
                parse_ldap_search_result_entry,
                ProtocolOp::SearchResultEntry,
            )(i),
            5 => map(parse_ldap_search_result_done, ProtocolOp::SearchResultDone)(i),
            6 => map(parse_ldap_modify_request, ProtocolOp::ModifyRequest)(i),
            7 => map(parse_ldap_modify_response, ProtocolOp::ModifyResponse)(i),
            8 => map(parse_ldap_add_request, ProtocolOp::AddRequest)(i),
            9 => map(parse_ldap_add_response, ProtocolOp::AddResponse)(i),
            10 => map(parse_ldap_del_request, ProtocolOp::DelRequest)(i),
            11 => map(parse_ldap_del_response, ProtocolOp::DelResponse)(i),
            12 => map(parse_ldap_moddn_request, ProtocolOp::ModDnRequest)(i),
            13 => map(parse_ldap_moddn_response, ProtocolOp::ModDnResponse)(i),
            14 => map(parse_ldap_compare_request, ProtocolOp::CompareRequest)(i),
            15 => map(parse_ldap_compare_response, ProtocolOp::CompareResponse)(i),
            16 => map(parse_ldap_abandon_request, ProtocolOp::AbandonRequest)(i),
            19 => map(
                parse_ldap_search_result_ref,
                ProtocolOp::SearchResultReference,
            )(i),
            23 => map(parse_ldap_extended_request, ProtocolOp::ExtendedRequest)(i),
            24 => map(parse_ldap_extended_response, ProtocolOp::ExtendedResponse)(i),
            _ => {
                // print_hex_dump(i, 32);
                // panic!("Protocol op {} not yet implemented", header.tag.0);
                Err(Err::Error(LdapError::InvalidMessageType))
            }
        }?;
        let (i, controls) = opt(complete(parse_ber_tagged_implicit_g(
            0,
            |i, _hdr, _depth| many0(complete(parse_ldap_control))(i),
        )))(i)?;
        assert!(i.is_empty() || "error" == "remaining bytes"); // XXX remove me
        let msg = LdapMessage {
            message_id,
            protocol_op,
            controls,
        };
        Ok((i, msg))
    })(i)
}

pub fn parse_ldap_messages(i: &[u8]) -> Result<Vec<LdapMessage>> {
    // println!("parse_ldap_message: len={}", i.len());
    // print_hex_dump(i, 32);
    many1(complete(dbg_dmp(
        |d| parse_ldap_message(d),
        "parse_ldap_message",
    )))(i)
}

// BindRequest ::= [APPLICATION 0] SEQUENCE {
//      version                 INTEGER (1 ..  127),
//      name                    LDAPDN,
//      authentication          AuthenticationChoice }
fn parse_ldap_bind_request(i: &[u8]) -> Result<BindRequest> {
    parse_ber_tagged_implicit_g(0, |content, _hdr, _depth| {
        let i = content;
        let (i, version) = verify(parse_ber_u32, |&n| n < 128)(i).map_err(Err::convert)?;
        let version = version as u8;
        let (i, name) = parse_ldap_dn(i)?;
        let (i, authentication) = parse_authentication_choice(i)?;
        let req = BindRequest {
            version,
            name,
            authentication,
        };
        Ok((i, req))
    })(i)
}

// BindResponse ::= [APPLICATION 1] SEQUENCE {
//      COMPONENTS OF LDAPResult,
//      serverSaslCreds    [7] OCTET STRING OPTIONAL }
fn parse_ldap_bind_response(i: &[u8]) -> Result<BindResponse> {
    parse_ber_tagged_implicit_g(1, |content, _hdr, _depth| {
        let i = content;
        let (i, result) = parse_ldap_result_content(i)?;
        let (i, server_sasl_creds) =
            opt(complete(parse_ber_tagged_implicit_g(7, |content, _, _| {
                Ok((&b""[..], Cow::Borrowed(content)))
            })))(i)?;
        assert!(i.is_empty() || "error" == "serverSaslCreds NYI"); // XXX remove me
        let req = BindResponse {
            result,
            server_sasl_creds,
        };
        Ok((i, req))
    })(i)
}

// UnbindRequest ::= [APPLICATION 2] NULL
fn parse_ldap_unbind_request(i: &[u8]) -> Result<ProtocolOp> {
    parse_ber_tagged_implicit_g(2, |content, _hdr, _depth| {
        let i = content;
        // accept empty input, otherwise expect NULL
        if !i.is_empty() {
            let (_, _) = parse_ber_null(i).map_err(Err::convert)?;
        }
        Ok((i, ProtocolOp::UnbindRequest))
    })(i)
}

// SearchRequest ::= [APPLICATION 3] SEQUENCE {
//      baseObject      LDAPDN,
//      scope           ENUMERATED {
//           baseObject              (0),
//           singleLevel             (1),
//           wholeSubtree            (2),
//           ...  },
//      derefAliases    ENUMERATED {
//           neverDerefAliases       (0),
//           derefInSearching        (1),
//           derefFindingBaseObj     (2),
//           derefAlways             (3) },
//      sizeLimit       INTEGER (0 ..  maxInt),
//      timeLimit       INTEGER (0 ..  maxInt),
//      typesOnly       BOOLEAN,
//      filter          Filter,
//      attributes      AttributeSelection }
fn parse_ldap_search_request(i: &[u8]) -> Result<SearchRequest> {
    parse_ber_tagged_implicit_g(3, |content, _hdr, _depth| {
        let i = content;
        let (i, base_object) = parse_ldap_dn(i)?;
        let (i, scope) = map(parse_ldap_enum_as_u32, SearchScope)(i)?;
        let (i, deref_aliases) = map(parse_ldap_enum_as_u32, DerefAliases)(i)?;
        let (i, size_limit) = parse_ldap_int_as_u32(i)?;
        let (i, time_limit) = parse_ldap_int_as_u32(i)?;
        let (i, types_only) = map_res(parse_ber_bool, |o| o.as_bool())(i).map_err(Err::convert)?;
        let (i, filter) = parse_ldap_filter(i)?;
        let (i, attributes) = parse_attribute_selection(i)?;
        // assert!(i.is_empty() || "error" == "remaining bytes"); // XXX remove me
        let req = SearchRequest {
            base_object,
            scope,
            deref_aliases,
            size_limit,
            time_limit,
            types_only,
            filter,
            attributes,
        };
        Ok((i, req))
    })(i)
}

// SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
//     objectName      LDAPDN,
//     attributes      PartialAttributeList }
fn parse_ldap_search_result_entry(i: &[u8]) -> Result<SearchResultEntry> {
    parse_ber_tagged_implicit_g(4, |i, _hdr, _depth| {
        let (i, object_name) = parse_ldap_dn(i)?;
        let (i, attributes) = parse_partial_attribute_list(i)?;
        assert!(i.is_empty() || "error" == "remaining bytes"); // XXX remove me
        let res = SearchResultEntry {
            object_name,
            attributes,
        };
        Ok((i, res))
    })(i)
}

// SearchResultDone ::= [APPLICATION 5] LDAPResult
fn parse_ldap_search_result_done(i: &[u8]) -> Result<LdapResult> {
    parse_ber_tagged_implicit_g(5, |i, _, _| parse_ldap_result_content(i))(i)
}

// ModifyRequest ::= [APPLICATION 6] SEQUENCE {
//     object          LDAPDN,
//     changes         SEQUENCE OF change SEQUENCE {
//          operation       ENUMERATED {
//               add     (0),
//               delete  (1),
//               replace (2),
//               ...  },
//          modification    PartialAttribute } }
fn parse_ldap_modify_request(i: &[u8]) -> Result<ModifyRequest> {
    parse_ber_tagged_implicit_g(6, |i, _hdr, _depth| {
        let (i, object) = parse_ldap_dn(i)?;
        let (i, changes) =
            parse_ber_sequence_defined_g(|_, i| many1(complete(parse_ldap_change))(i))(i)?;
        assert!(i.is_empty() || "error" == "remaining bytes"); // XXX remove me
        let res = ModifyRequest { object, changes };
        Ok((i, res))
    })(i)
}

// ModifyResponse ::= [APPLICATION 7] LDAPResult
fn parse_ldap_modify_response(i: &[u8]) -> Result<ModifyResponse> {
    parse_ber_tagged_implicit_g(7, |i, _hdr, _depth| {
        let (i, result) = parse_ldap_result_content(i)?;
        assert!(i.is_empty() || "error" == "remaining bytes"); // XXX remove me
        let res = ModifyResponse { result };
        Ok((i, res))
    })(i)
}

// AddRequest ::= [APPLICATION 8] SEQUENCE {
//     entry           LDAPDN,
//     attributes      AttributeList }
fn parse_ldap_add_request(i: &[u8]) -> Result<AddRequest> {
    parse_ber_tagged_implicit_g(8, |i, _hdr, _depth| {
        let (i, entry) = parse_ldap_dn(i)?;
        let (i, attributes) = parse_attribute_list(i)?;
        assert!(i.is_empty() || "error" == "remaining bytes"); // XXX remove me
        let res = AddRequest { entry, attributes };
        Ok((i, res))
    })(i)
}

// AddResponse ::= [APPLICATION 9] LDAPResult
fn parse_ldap_add_response(i: &[u8]) -> Result<LdapResult> {
    parse_ber_tagged_implicit_g(9, |i, _, _| parse_ldap_result_content(i))(i)
}

// DelRequest ::= [APPLICATION 10] LDAPDN
fn parse_ldap_del_request(i: &[u8]) -> Result<LdapDN> {
    parse_ber_tagged_implicit_g(10, |i, _hdr, _depth| {
        let s = std::str::from_utf8(i).or(Err(Err::Error(LdapError::InvalidDN)))?;
        let oid = LdapDN(Cow::Borrowed(s));
        Ok((&b""[..], oid))
    })(i)
}

// DelResponse ::= [APPLICATION 11] LDAPResult
fn parse_ldap_del_response(i: &[u8]) -> Result<LdapResult> {
    parse_ber_tagged_implicit_g(11, |i, _, _| parse_ldap_result_content(i))(i)
}

// ModifyDNRequest ::= [APPLICATION 12] SEQUENCE {
//     entry           LDAPDN,
//     newrdn          RelativeLDAPDN,
//     deleteoldrdn    BOOLEAN,
//     newSuperior     [0] LDAPDN OPTIONAL }
fn parse_ldap_moddn_request(i: &[u8]) -> Result<ModDnRequest> {
    parse_ber_tagged_implicit_g(12, |i, _hdr, _depth| {
        let (i, entry) = parse_ldap_dn(i)?;
        let (i, newrdn) = parse_relative_ldap_dn(i)?;
        let (i, deleteoldrdn) =
            map_res(parse_ber_bool, |o| o.as_bool())(i).map_err(Err::convert)?;
        let (i, newsuperior) = opt(complete(parse_ber_tagged_implicit_g(
            0,
            |i, _hdr, _depth| {
                let s = std::str::from_utf8(i).or(Err(Err::Error(LdapError::InvalidDN)))?;
                let oid = LdapDN(Cow::Borrowed(s));
                Ok((&b""[..], oid))
            },
        )))(i)?;
        assert!(i.is_empty() || "error" == "remaining bytes"); // XXX remove me
        let res = ModDnRequest {
            entry,
            newrdn,
            deleteoldrdn,
            newsuperior,
        };
        Ok((i, res))
    })(i)
}

// ModifyDNResponse ::= [APPLICATION 13] LDAPResult
fn parse_ldap_moddn_response(i: &[u8]) -> Result<LdapResult> {
    parse_ber_tagged_implicit_g(13, |i, _, _| parse_ldap_result_content(i))(i)
}

// CompareRequest ::= [APPLICATION 14] SEQUENCE {
//     entry           LDAPDN,
//     ava             AttributeValueAssertion }
fn parse_ldap_compare_request(i: &[u8]) -> Result<CompareRequest> {
    parse_ber_tagged_implicit_g(14, |i, _hdr, _depth| {
        let (i, entry) = parse_ldap_dn(i)?;
        let (i, ava) = parse_ldap_attribute_value_assertion(i)?;
        assert!(i.is_empty() || "error" == "remaining bytes"); // XXX remove me
        let res = CompareRequest { entry, ava };
        Ok((i, res))
    })(i)
}

// CompareResponse ::= [APPLICATION 15] LDAPResult
fn parse_ldap_compare_response(i: &[u8]) -> Result<LdapResult> {
    parse_ber_tagged_implicit_g(15, |i, _, _| parse_ldap_result_content(i))(i)
}

// AbandonRequest ::= [APPLICATION 16] MessageID
fn parse_ldap_abandon_request(i: &[u8]) -> Result<MessageID> {
    parse_ber_tagged_implicit_g(16, |i, _hdr, _depth| {
        if i.is_empty() {
            return Err(Err::Incomplete(Needed::new(1)));
        }
        let obj = BerObject::from_int_slice(i);
        let id = obj.as_u32().map_err(|e| Err::Error(LdapError::Ber(e)))?;
        Ok((i, MessageID(id)))
    })(i)
}

// SearchResultReference ::= [APPLICATION 19] SEQUENCE
//                                   SIZE (1..MAX) OF uri URI
fn parse_ldap_search_result_ref(i: &[u8]) -> Result<Vec<LdapString>> {
    parse_ber_tagged_implicit_g(19, |i, _hdr, _depth| many1(complete(parse_ldap_uri))(i))(i)
}

// ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
//     requestName      [0] LDAPOID,
//     requestValue     [1] OCTET STRING OPTIONAL }
fn parse_ldap_extended_request(i: &[u8]) -> Result<ExtendedRequest> {
    parse_ber_tagged_implicit_g(23, |i, _hdr, _depth| {
        let (i, request_name) = parse_ber_tagged_implicit_g(0, |i, _hdr, _depth| {
            let s = std::str::from_utf8(i).or(Err(Err::Error(LdapError::InvalidDN)))?;
            let oid = LdapOID(Cow::Borrowed(s));
            Ok((&b""[..], oid))
        })(i)?;
        let (i, request_value) = opt(complete(parse_ber_tagged_implicit_g(
            1,
            |i, _hdr, _depth| Ok((&b""[..], Cow::Borrowed(i))),
        )))(i)?;
        let req = ExtendedRequest {
            request_name,
            request_value,
        };
        Ok((i, req))
    })(i)
}

// ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
//     COMPONENTS OF LDAPResult,
//     responseName     [10] LDAPOID OPTIONAL,
//     responseValue    [11] OCTET STRING OPTIONAL }
fn parse_ldap_extended_response(i: &[u8]) -> Result<ExtendedResponse> {
    parse_ber_tagged_implicit_g(24, |i, _hdr, _depth| {
        let (i, result) = parse_ldap_result_content(i)?;
        let (i, request_name) = opt(complete(parse_ber_tagged_implicit_g(
            10,
            |i, _hdr, _depth| {
                let s = std::str::from_utf8(i).or(Err(Err::Error(LdapError::InvalidDN)))?;
                let oid = LdapOID(Cow::Borrowed(s));
                Ok((&b""[..], oid))
            },
        )))(i)?;
        let (i, request_value) = opt(complete(parse_ber_tagged_implicit_g(
            11,
            |i, _hdr, _depth| Ok((&b""[..], Cow::Borrowed(i))),
        )))(i)?;
        let resp = ExtendedResponse {
            result,
            request_name,
            request_value,
        };
        Ok((i, resp))
    })(i)
}

// AuthenticationChoice ::= CHOICE {
//      simple                  [0] OCTET STRING,
//                              -- 1 and 2 reserved
//      sasl                    [3] SaslCredentials,
//      ...  }
fn parse_authentication_choice(i: &[u8]) -> Result<AuthenticationChoice> {
    let (rem, header) = ber_read_element_header(i).map_err(Err::convert)?;
    match header.tag.0 {
        0 => {
            // assume len is primitive, and just take bytes
            let sz = header
                .len
                .primitive()
                .map_err(|e| Err::Error(LdapError::Ber(e)))?;
            let (i, b) = take(sz)(rem)?;
            // // other solution: read content as octetstring and get slice
            // let (i, b) = map_res(
            //     |d| {
            //         ber_read_element_content_as(
            //             d,
            //             BerTag::OctetString,
            //             header.len,
            //             header.is_constructed(),
            //             1,
            //         )
            //     },
            //     |o| o.as_slice(),
            // )(rem)
            // .map_err(Err::convert)?;
            Ok((i, AuthenticationChoice::Simple(Cow::Borrowed(b))))
        }
        3 => map(parse_sasl_credentials, AuthenticationChoice::Sasl)(rem),
        _ => unimplemented!(),
    }
}

// SaslCredentials ::= SEQUENCE {
//      mechanism               LDAPString,
//      credentials             OCTET STRING OPTIONAL }
fn parse_sasl_credentials(i: &[u8]) -> Result<SaslCredentials> {
    let (i, mechanism) = parse_ldap_string(i)?;
    let (i, credentials) = opt(complete(map(
        parse_ldap_octet_string_as_slice,
        Cow::Borrowed,
    )))(i)?;
    let credentials = SaslCredentials {
        mechanism,
        credentials,
    };
    Ok((i, credentials))
}

// AttributeSelection ::= SEQUENCE OF selector LDAPString
//      -- The LDAPString is constrained to
//      -- <attributeSelector> in Section 4.5.1.8
fn parse_attribute_selection(i: &[u8]) -> Result<Vec<LdapString>> {
    parse_ber_sequence_defined_g(|_, i| many0(complete(parse_ldap_string))(i))(i)
}

// PartialAttributeList ::= SEQUENCE OF partialAttribute PartialAttribute
fn parse_partial_attribute_list(i: &[u8]) -> Result<Vec<PartialAttribute>> {
    parse_ber_sequence_defined_g(|_, i| many0(complete(parse_ldap_partial_attribute))(i))(i)
}

// AttributeList ::= SEQUENCE OF attribute Attribute
fn parse_attribute_list(i: &[u8]) -> Result<Vec<Attribute>> {
    parse_ber_sequence_defined_g(|_, i| many0(complete(parse_ldap_attribute))(i))(i)
}

// change SEQUENCE {
//          operation       ENUMERATED {
//               add     (0),
//               delete  (1),
//               replace (2),
//               ...  },
//          modification    PartialAttribute }
fn parse_ldap_change(i: &[u8]) -> Result<Change> {
    parse_ber_sequence_defined_g(|_, i| {
        let (i, operation) = map(parse_ldap_enum_as_u32, Operation)(i)?;
        let (i, modification) = parse_ldap_partial_attribute(i)?;
        let change = Change {
            operation,
            modification,
        };
        Ok((i, change))
    })(i)
}

// Control ::= SEQUENCE {
//     controlType             LDAPOID,
//     criticality             BOOLEAN DEFAULT FALSE,
//     controlValue            OCTET STRING OPTIONAL }
fn parse_ldap_control(i: &[u8]) -> Result<Control> {
    parse_ber_sequence_defined_g(|_, i| {
        let (i, control_type) = parse_ldap_oid(i)?;
        let (i, maybe_critical) =
            opt(complete(map_res(parse_ber_bool, |o| o.as_bool())))(i).map_err(Err::convert)?;
        let criticality = maybe_critical.unwrap_or(false);
        let (i, control_value) = opt(complete(map(
            parse_ldap_octet_string_as_slice,
            Cow::Borrowed,
        )))(i)?;
        assert!(i.is_empty() || "error" == "remaining bytes"); // XXX remove me
        let control = Control {
            control_type,
            criticality,
            control_value,
        };
        Ok((i, control))
    })(i)
}

//
//
//
//
//
// ----------------------- TESTS -----------------------
//
//
//
//
//
//

#[cfg(test)]
mod tests {
    use super::*;
    use der_parser::oid;
    use hex_literal::hex;

    #[test]
    fn test_parse_bind_request() {
        const DATA: &[u8] = include_bytes!("../assets/bind_request.bin");

        let (rem, req) = parse_ldap_bind_request(DATA).expect("parsing failed");
        //
        // dbg!(&req);
        //
        assert!(rem.is_empty());
        assert_eq!(&req.name.0, "xxxxxxxxxxx@xx.xxx.xxxxx.net");
        assert_eq!(
            req.authentication,
            AuthenticationChoice::Simple(Cow::Borrowed(b"passwor8d1"))
        );
    }

    #[test]
    fn test_parse_bind_request_sasl() {
        const DATA: &[u8] = include_bytes!("../assets/bind_request_sasl.bin");

        let (rem, req) = parse_ldap_bind_request(DATA).expect("parsing failed");
        //
        // dbg!(&req);
        //
        assert!(rem.is_empty());
        assert_eq!(&req.name.0, "");
        if let AuthenticationChoice::Sasl(sasl_credentials) = &req.authentication {
            assert_eq!(&sasl_credentials.mechanism.0, "GSS-SPNEGO");
        } else {
            panic!("wrong authentication type");
        }
    }

    #[test]
    fn test_parse_bind_response_minimal() {
        const DATA: &[u8] = &hex!("61 84 00 00 00 07 0a 01 00 04 00 04 00");
        let (rem, resp) = parse_ldap_bind_response(DATA).expect("parsing failed");
        //
        // dbg!(&resp);
        //
        assert!(rem.is_empty());
        assert_eq!(resp.result.result_code, ResultCode::Success);
    }

    #[test]
    fn test_parse_bind_response_sasl() {
        const DATA: &[u8] = include_bytes!("../assets/bind_response_sasl.bin");
        let (rem, resp) = parse_ldap_bind_response(DATA).expect("parsing failed");
        //
        // dbg!(&resp);
        //
        assert!(rem.is_empty());
        assert_eq!(resp.result.result_code, ResultCode::Success);
        assert!(resp.server_sasl_creds.is_some());
    }

    #[test]
    fn test_parse_unbind_request() {
        const DATA: &[u8] = &hex!("42 00");

        let (rem, req) = parse_ldap_unbind_request(DATA).expect("parsing failed");
        //
        // dbg!(&req);
        //
        assert!(rem.is_empty());
        assert_eq!(req, ProtocolOp::UnbindRequest);
    }

    #[test]
    fn test_parse_search_request() {
        const DATA: &[u8] = include_bytes!("../assets/search_request.bin");
        let (rem, resp) = parse_ldap_search_request(DATA).expect("parsing failed");
        //
        // dbg!(&resp);
        //
        assert!(rem.is_empty());
        assert_eq!(&resp.base_object.0, "DC=xx,DC=xxx,DC=xxxxx,DC=net");
        assert_eq!(resp.scope, SearchScope::WholeSubtree);
        assert_eq!(resp.attributes.len(), 1);
    }

    #[test]
    fn test_parse_search_result_entry() {
        const DATA: &[u8] = include_bytes!("../assets/search_result_entry.bin");
        let (rem, resp) = parse_ldap_search_result_entry(DATA).expect("parsing failed");
        //
        // dbg!(&resp);
        //
        assert!(rem.is_empty());
        assert_eq!(resp.attributes.len(), 1);
    }

    #[test]
    fn test_parse_search_result_done() {
        const DATA: &[u8] = include_bytes!("../assets/search_result_done.bin");
        let (rem, resp) = parse_ldap_search_result_done(DATA).expect("parsing failed");
        //
        // dbg!(&resp);
        //
        assert!(rem.is_empty());
        assert_eq!(resp.result_code, ResultCode::Success);
    }

    #[test]
    fn test_parse_search_result_ref() {
        const DATA: &[u8] = include_bytes!("../assets/search_result_ref.bin");
        let (rem, v) = parse_ldap_search_result_ref(DATA).expect("parsing failed");
        //
        // dbg!(&v);
        //
        assert!(rem.is_empty());
        assert_eq!(v.len(), 1);
        assert_eq!(
            &v[0].0,
            "ldap://DomainDnsZones.rccad.net/DC=DomainDnsZones,DC=rccad,DC=net"
        );
    }

    #[test]
    fn test_parse_extended_req() {
        const DATA: &[u8] = include_bytes!("../assets/extended-req.bin");
        let (rem, req) = parse_ldap_extended_request(DATA).expect("parsing failed");
        //
        // dbg!(&req);
        //
        assert!(rem.is_empty());
        assert_eq!(req.request_name.0, oid!(1.3.6.1.4.1.1466.20037).to_string());
        assert!(req.request_value.is_none());
    }

    #[test]
    fn test_parse_extended_response() {
        const DATA: &[u8] = &hex!("78 07 0a 01 00 04 00 04 00");
        let (rem, resp) = parse_ldap_extended_response(DATA).expect("parsing failed");
        //
        // dbg!(&resp);
        //
        assert!(rem.is_empty());
        assert_eq!(resp.result.result_code, ResultCode::Success);
    }

    #[test]
    fn test_parse_modify_request() {
        const DATA: &[u8] = include_bytes!("../assets/modify-request.bin");
        let (rem, req) = parse_ldap_modify_request(DATA).expect("parsing failed");
        //
        // dbg!(&req);
        //
        assert!(rem.is_empty());
        assert_eq!(&req.object.0, "cn=username1,ou=users,dc=xxx,dc=internet");
        assert_eq!(req.changes.len(), 1);
        assert_eq!(req.changes[0].modification.attr_type.0, "description");
    }

    #[test]
    fn test_parse_modify_response() {
        const DATA: &[u8] = include_bytes!("../assets/modify-response.bin");
        let (rem, resp) = parse_ldap_modify_response(DATA).expect("parsing failed");
        //
        // dbg!(&resp);
        //
        assert!(rem.is_empty());
        assert_eq!(resp.result.result_code, ResultCode::Success);
    }

    #[test]
    fn test_parse_add_request() {
        const DATA: &[u8] = include_bytes!("../assets/add-request.bin");
        let (rem, req) = parse_ldap_add_request(DATA).expect("parsing failed");
        //
        // dbg!(&req);
        //
        assert!(rem.is_empty());
        assert_eq!(&req.entry.0, "cn=username1,ou=users,dc=xxx,dc=internet");
        assert_eq!(req.attributes.len(), 4);
    }

    #[test]
    fn test_parse_add_response() {
        const DATA: &[u8] = include_bytes!("../assets/add-response.bin");
        let (rem, resp) = parse_ldap_add_response(DATA).expect("parsing failed");
        //
        // dbg!(&resp);
        //
        assert!(rem.is_empty());
        assert_eq!(resp.result_code, ResultCode::Success);
    }

    #[test]
    fn test_parse_del_request() {
        const DATA: &[u8] = include_bytes!("../assets/del-request.bin");
        let (rem, req) = parse_ldap_del_request(DATA).expect("parsing failed");
        //
        // dbg!(&req);
        //
        assert!(rem.is_empty());
        assert_eq!(&req.0, "cn=username2,ou=users2,dc=xxx,dc=internet");
    }

    #[test]
    fn test_parse_del_response() {
        const DATA: &[u8] = include_bytes!("../assets/del-response.bin");
        let (rem, resp) = parse_ldap_del_response(DATA).expect("parsing failed");
        //
        // dbg!(&resp);
        //
        assert!(rem.is_empty());
        assert_eq!(resp.result_code, ResultCode::Success);
    }

    #[test]
    fn test_parse_moddn_request() {
        const DATA: &[u8] = include_bytes!("../assets/moddn-request.bin");
        let (rem, req) = parse_ldap_moddn_request(DATA).expect("parsing failed");
        //
        // dbg!(&req);
        //
        assert!(rem.is_empty());
        assert_eq!(&req.entry.0, "cn=username1,ou=users,dc=xxx,dc=internet");
        assert_eq!(&req.newrdn.0, "cn=username2");
        assert!(req.deleteoldrdn);
        assert_eq!(&req.newsuperior.unwrap().0, "ou=users,dc=xxx,dc=internet");
    }

    #[test]
    fn test_parse_moddn_response() {
        const DATA: &[u8] = include_bytes!("../assets/moddn-response.bin");
        let (rem, resp) = parse_ldap_moddn_response(DATA).expect("parsing failed");
        //
        // dbg!(&resp);
        //
        assert!(rem.is_empty());
        assert_eq!(resp.result_code, ResultCode::Success);
    }

    #[test]
    fn test_parse_compare_request() {
        const DATA: &[u8] = include_bytes!("../assets/compare-request.bin");
        let (rem, req) = parse_ldap_compare_request(DATA).expect("parsing failed");
        //
        // dbg!(&req);
        //
        assert!(rem.is_empty());
        assert_eq!(&req.entry.0, "cn=username2,ou=users2,dc=xxx,dc=internet");
        assert_eq!(&req.ava.attribute_desc.0, "cn");
    }

    #[test]
    fn test_parse_compare_response() {
        const DATA: &[u8] = include_bytes!("../assets/compare-response.bin");
        let (rem, resp) = parse_ldap_compare_response(DATA).expect("parsing failed");
        //
        // dbg!(&resp);
        //
        assert!(rem.is_empty());
        assert_eq!(resp.result_code, ResultCode::CompareTrue);
    }
}
