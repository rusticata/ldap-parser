// DEFINITIONS
// IMPLICIT TAGS
// EXTENSIBILITY IMPLIED

use crate::error::*;
use crate::filter::*;
use crate::ldap::*;
use asn1_rs::nom;
use asn1_rs::{
    Class, Enumerated, FromBer, Header, Implicit, OptTaggedParser, ParseResult, Sequence, Tag,
    TaggedParser, TaggedValue,
};
use nom::bytes::streaming::take;
use nom::combinator::{complete, map, opt, verify};
use nom::multi::{many0, many1};
use nom::Err;
use std::borrow::Cow;

// // maxInt INTEGER ::= 2147483647 -- (2^^31 - 1) --
// const MAX_INT: u32 = 2_147_483_647;

// MessageID ::= INTEGER (0 ..  maxInt)
impl<'a> FromBer<'a, LdapError> for MessageID {
    fn from_ber(bytes: &'a [u8]) -> ParseResult<'a, Self, LdapError> {
        map(u32::from_ber, MessageID)(bytes).map_err(Err::convert)
    }
}

// LDAPString ::= OCTET STRING -- UTF-8 encoded,
//                             -- [ISO10646] characters
impl<'a> FromBer<'a, LdapError> for LdapString<'a> {
    fn from_ber(bytes: &'a [u8]) -> ParseResult<'a, Self, LdapError> {
        let (i, b) = parse_ldap_octet_string_as_slice(bytes)?;
        // convert to UTF-8
        let s = std::str::from_utf8(b).or(Err(Err::Error(LdapError::InvalidString)))?;
        Ok((i, LdapString(Cow::Borrowed(s))))
    }
}

#[inline]
pub(crate) fn parse_ldap_octet_string_as_slice(i: &[u8]) -> Result<&[u8]> {
    <&[u8]>::from_ber(i).map_err(Err::convert)
}

#[inline]
fn parse_ldap_int_as_u32(i: &[u8]) -> Result<u32> {
    <u32>::from_ber(i).map_err(Err::convert)
}

#[inline]
fn parse_ldap_enum_as_u32(i: &[u8]) -> Result<u32> {
    let (i, obj) = Enumerated::from_ber(i).map_err(Err::convert)?;
    Ok((i, obj.0))
}

// LDAPDN ::= LDAPString -- Constrained to <distinguishedName>
//                       -- [RFC4514]
impl<'a> FromBer<'a, LdapError> for LdapDN<'a> {
    fn from_ber(bytes: &'a [u8]) -> ParseResult<'a, Self, LdapError> {
        // read bytes
        let (i, b) = <&[u8]>::from_ber(bytes).map_err(Err::convert)?;
        // convert to UTF-8
        let s = std::str::from_utf8(b).or(Err(Err::Error(LdapError::InvalidDN)))?;
        Ok((i, LdapDN(Cow::Borrowed(s))))
    }
}

// RelativeLDAPDN ::= LDAPString -- Constrained to <name-component>
//                               -- [RFC4514]
impl<'a> FromBer<'a, LdapError> for RelativeLdapDN<'a> {
    fn from_ber(bytes: &'a [u8]) -> ParseResult<'a, Self, LdapError> {
        // read bytes
        let (i, b) = <&[u8]>::from_ber(bytes).map_err(Err::convert)?;
        // convert to UTF-8
        let s = std::str::from_utf8(b).or(Err(Err::Error(LdapError::InvalidDN)))?;
        Ok((i, RelativeLdapDN(Cow::Borrowed(s))))
    }
}

// LDAPOID ::= OCTET STRING -- Constrained to <numericoid>
//                          -- [RFC4512]
impl<'a> FromBer<'a, LdapError> for LdapOID<'a> {
    fn from_ber(bytes: &'a [u8]) -> ParseResult<'a, Self, LdapError> {
        // read bytes
        let (i, b) = <&[u8]>::from_ber(bytes).map_err(Err::convert)?;
        // convert to UTF-8
        let s = std::str::from_utf8(b).or(Err(Err::Error(LdapError::InvalidDN)))?;
        Ok((i, LdapOID(Cow::Borrowed(s))))
    }
}

// URI ::= LDAPString     -- limited to characters permitted in
//                                -- URIs
#[inline]
fn parse_ldap_uri(i: &[u8]) -> Result<LdapString> {
    LdapString::from_ber(i)
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
    let (i, matched_dn) = LdapDN::from_ber(i)?;
    let (i, diagnostic_message) = LdapString::from_ber(i)?;
    // TODO: referral
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
/// Parse a single LDAP message and return a structure borrowing fields from the input buffer
///
/// ```rust
/// use ldap_parser::FromBer;
/// use ldap_parser::ldap::{LdapMessage, MessageID, ProtocolOp, ProtocolOpTag};
///
/// static DATA: &[u8] = include_bytes!("../assets/message-search-request-01.bin");
///
/// # fn main() {
/// let res = LdapMessage::from_ber(DATA);
/// match res {
///     Ok((rem, msg)) => {
///         assert!(rem.is_empty());
///         //
///         assert_eq!(msg.message_id, MessageID(4));
///         assert_eq!(msg.protocol_op.tag(), ProtocolOpTag::SearchRequest);
///         match msg.protocol_op {
///             ProtocolOp::SearchRequest(req) => {
///                 assert_eq!(req.base_object.0, "dc=rccad,dc=net");
///             },
///             _ => panic!("Unexpected message type"),
///         }
///     },
///     _ => panic!("LDAP parsing failed: {:?}", res),
/// }
/// # }
/// ```
impl<'a> FromBer<'a, LdapError> for LdapMessage<'a> {
    fn from_ber(bytes: &'a [u8]) -> ParseResult<'a, Self, LdapError> {
        Sequence::from_ber_and_then(bytes, |i| {
            let (i, message_id) = MessageID::from_ber(i)?;
            // read header of next element and look tag value
            let (_, header) = Header::from_ber(i).map_err(Err::convert)?;
            let (i, protocol_op) = match header.tag().0 {
                0 => map(BindRequest::from_ber, ProtocolOp::BindRequest)(i),
                1 => map(BindResponse::from_ber, ProtocolOp::BindResponse)(i),
                2 => parse_ldap_unbind_request(i),
                3 => map(SearchRequest::from_ber, ProtocolOp::SearchRequest)(i),
                4 => map(SearchResultEntry::from_ber, ProtocolOp::SearchResultEntry)(i),
                5 => map(parse_ldap_search_result_done, ProtocolOp::SearchResultDone)(i),
                6 => map(ModifyRequest::from_ber, ProtocolOp::ModifyRequest)(i),
                7 => map(parse_ldap_modify_response, ProtocolOp::ModifyResponse)(i),
                8 => map(AddRequest::from_ber, ProtocolOp::AddRequest)(i),
                9 => map(parse_ldap_add_response, ProtocolOp::AddResponse)(i),
                10 => map(parse_ldap_del_request, ProtocolOp::DelRequest)(i),
                11 => map(parse_ldap_del_response, ProtocolOp::DelResponse)(i),
                12 => map(ModDnRequest::from_ber, ProtocolOp::ModDnRequest)(i),
                13 => map(parse_ldap_moddn_response, ProtocolOp::ModDnResponse)(i),
                14 => map(CompareRequest::from_ber, ProtocolOp::CompareRequest)(i),
                15 => map(parse_ldap_compare_response, ProtocolOp::CompareResponse)(i),
                16 => map(parse_ldap_abandon_request, ProtocolOp::AbandonRequest)(i),
                19 => map(
                    parse_ldap_search_result_ref,
                    ProtocolOp::SearchResultReference,
                )(i),
                23 => map(ExtendedRequest::from_ber, ProtocolOp::ExtendedRequest)(i),
                24 => map(ExtendedResponse::from_ber, ProtocolOp::ExtendedResponse)(i),
                25 => map(
                    IntermediateResponse::from_ber,
                    ProtocolOp::IntermediateResponse,
                )(i),
                _ => {
                    // print_hex_dump(i, 32);
                    // panic!("Protocol op {} not yet implemented", header.tag.0);
                    Err(Err::Error(LdapError::InvalidMessageType))
                }
            }?;
            let (i, controls) = OptTaggedParser::new(Class::ContextSpecific, Tag(0))
                .parse_ber(i, |_, i| many0(complete(Control::from_ber))(i))?;
            let msg = LdapMessage {
                message_id,
                protocol_op,
                controls,
            };
            Ok((i, msg))
        })
    }
}

#[deprecated(
    since = "0.3.0",
    note = "Parsing functions are deprecated. Users should instead use the FromBer trait"
)]
#[inline]
pub fn parse_ldap_message(i: &[u8]) -> Result<LdapMessage> {
    LdapMessage::from_ber(i)
}

/// Parse a list of LDAP messages and return a structure borrowing fields from the input buffer
// Note: we don't use the trait because Vec<_>::from_ber forces the Error type
pub fn parse_ldap_messages(i: &[u8]) -> Result<Vec<LdapMessage>> {
    // println!("parse_ldap_message: len={}", i.len());
    // print_hex_dump(i, 32);
    many1(complete(LdapMessage::from_ber))(i)
}

// BindRequest ::= [APPLICATION 0] SEQUENCE {
//      version                 INTEGER (1 ..  127),
//      name                    LDAPDN,
//      authentication          AuthenticationChoice }
impl<'a> FromBer<'a, LdapError> for BindRequest<'a> {
    fn from_ber(bytes: &'a [u8]) -> ParseResult<'a, Self, LdapError> {
        TaggedParser::from_ber_and_then(Class::Application, 0, bytes, |i| {
            // Sequence::from_ber_and_then(bytes, |i| {
            let (i, version) = verify(u8::from_ber, |&n| n < 128)(i).map_err(Err::convert)?;
            let (i, name) = LdapDN::from_ber(i)?;
            let (i, authentication) = AuthenticationChoice::from_ber(i)?;
            let req = BindRequest {
                version,
                name,
                authentication,
            };
            Ok((i, req))
            // })
        })
    }
}

// BindResponse ::= [APPLICATION 1] SEQUENCE {
//      COMPONENTS OF LDAPResult,
//      serverSaslCreds    [7] OCTET STRING OPTIONAL }
impl<'a> FromBer<'a, LdapError> for BindResponse<'a> {
    fn from_ber(bytes: &'a [u8]) -> ParseResult<'a, Self, LdapError> {
        TaggedParser::from_ber_and_then(Class::Application, 1, bytes, |i| {
            let (i, result) = parse_ldap_result_content(i)?;
            let (i, server_sasl_creds) = OptTaggedParser::new(Class::ContextSpecific, Tag(7))
                .parse_ber(i, |_, data| Ok((&b""[..], Cow::Borrowed(data))))?;

            // opt(complete(parse_ber_tagged_implicit_g(7, |content, _, _| {
            // Ok((&b""[..], Cow::Borrowed(content)))
            // })))(i)?;
            let req = BindResponse {
                result,
                server_sasl_creds,
            };
            Ok((i, req))
        })
    }
}

// UnbindRequest ::= [APPLICATION 2] NULL
fn parse_ldap_unbind_request(bytes: &[u8]) -> Result<ProtocolOp> {
    TaggedParser::from_ber_and_then(Class::Application, 2, bytes, |i| {
        // accept empty input, otherwise expect NULL
        if !i.is_empty() {
            let (_, _) = <()>::from_ber(i).map_err(Err::convert)?;
        }
        Ok((i, ProtocolOp::UnbindRequest))
    })
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
impl<'a> FromBer<'a, LdapError> for SearchRequest<'a> {
    fn from_ber(bytes: &'a [u8]) -> ParseResult<'a, Self, LdapError> {
        TaggedParser::from_ber_and_then(Class::Application, 3, bytes, |i| {
            let (i, base_object) = LdapDN::from_ber(i)?;
            let (i, scope) = map(parse_ldap_enum_as_u32, SearchScope)(i)?;
            let (i, deref_aliases) = map(parse_ldap_enum_as_u32, DerefAliases)(i)?;
            let (i, size_limit) = parse_ldap_int_as_u32(i)?;
            let (i, time_limit) = parse_ldap_int_as_u32(i)?;
            let (i, types_only) = <bool>::from_ber(i).map_err(Err::convert)?;
            let (i, filter) = Filter::from_ber(i)?;
            let (i, attributes) = parse_attribute_selection(i)?;
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
        })
    }
}

// SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
//     objectName      LDAPDN,
//     attributes      PartialAttributeList }
impl<'a> FromBer<'a, LdapError> for SearchResultEntry<'a> {
    fn from_ber(bytes: &'a [u8]) -> ParseResult<'a, Self, LdapError> {
        TaggedParser::from_ber_and_then(Class::Application, 4, bytes, |i| {
            let (i, object_name) = LdapDN::from_ber(i)?;
            let (i, attributes) = parse_partial_attribute_list(i)?;
            let res = SearchResultEntry {
                object_name,
                attributes,
            };
            Ok((i, res))
        })
    }
}

// SearchResultDone ::= [APPLICATION 5] LDAPResult
fn parse_ldap_search_result_done(bytes: &[u8]) -> Result<LdapResult> {
    TaggedParser::from_ber_and_then(Class::Application, 5, bytes, parse_ldap_result_content)
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
impl<'a> FromBer<'a, LdapError> for ModifyRequest<'a> {
    fn from_ber(bytes: &'a [u8]) -> ParseResult<'a, Self, LdapError> {
        TaggedParser::from_ber_and_then(Class::Application, 6, bytes, |i| {
            let (i, object) = LdapDN::from_ber(i)?;
            let (i, changes) = Sequence::from_ber_and_then(i, many1(complete(Change::from_ber)))?;
            let res = ModifyRequest { object, changes };
            Ok((i, res))
        })
    }
}

// ModifyResponse ::= [APPLICATION 7] LDAPResult
fn parse_ldap_modify_response(bytes: &[u8]) -> Result<ModifyResponse> {
    TaggedParser::from_ber_and_then(Class::Application, 7, bytes, |i| {
        let (i, result) = parse_ldap_result_content(i)?;
        let res = ModifyResponse { result };
        Ok((i, res))
    })
}

// AddRequest ::= [APPLICATION 8] SEQUENCE {
//     entry           LDAPDN,
//     attributes      AttributeList }
impl<'a> FromBer<'a, LdapError> for AddRequest<'a> {
    fn from_ber(bytes: &'a [u8]) -> ParseResult<'a, Self, LdapError> {
        TaggedParser::from_ber_and_then(Class::Application, 8, bytes, |i| {
            let (i, entry) = LdapDN::from_ber(i)?;
            let (i, attributes) = parse_attribute_list(i)?;
            let res = AddRequest { entry, attributes };
            Ok((i, res))
        })
    }
}

// AddResponse ::= [APPLICATION 9] LDAPResult
fn parse_ldap_add_response(bytes: &[u8]) -> Result<LdapResult> {
    TaggedParser::from_ber_and_then(Class::Application, 9, bytes, parse_ldap_result_content)
}

// DelRequest ::= [APPLICATION 10] LDAPDN
fn parse_ldap_del_request(bytes: &[u8]) -> Result<LdapDN> {
    TaggedParser::from_ber_and_then(Class::Application, 10, bytes, |i| {
        let s = std::str::from_utf8(i).or(Err(Err::Error(LdapError::InvalidDN)))?;
        let oid = LdapDN(Cow::Borrowed(s));
        Ok((&b""[..], oid))
    })
}

// DelResponse ::= [APPLICATION 11] LDAPResult
fn parse_ldap_del_response(bytes: &[u8]) -> Result<LdapResult> {
    TaggedParser::from_ber_and_then(Class::Application, 11, bytes, parse_ldap_result_content)
}

// ModifyDNRequest ::= [APPLICATION 12] SEQUENCE {
//     entry           LDAPDN,
//     newrdn          RelativeLDAPDN,
//     deleteoldrdn    BOOLEAN,
//     newSuperior     [0] LDAPDN OPTIONAL }
impl<'a> FromBer<'a, LdapError> for ModDnRequest<'a> {
    fn from_ber(bytes: &'a [u8]) -> ParseResult<'a, Self, LdapError> {
        TaggedParser::from_ber_and_then(Class::Application, 12, bytes, |i| {
            let (i, entry) = LdapDN::from_ber(i)?;
            let (i, newrdn) = RelativeLdapDN::from_ber(i)?;
            let (i, deleteoldrdn) = <bool>::from_ber(i).map_err(Err::convert)?;
            let (i, newsuperior) =
                OptTaggedParser::new(Class::ContextSpecific, Tag(0)).parse_ber(i, |_, i| {
                    let s = std::str::from_utf8(i).or(Err(Err::Error(LdapError::InvalidDN)))?;
                    let oid = LdapDN(Cow::Borrowed(s));
                    Ok((&b""[..], oid))
                })?;
            let res = ModDnRequest {
                entry,
                newrdn,
                deleteoldrdn,
                newsuperior,
            };
            Ok((i, res))
        })
    }
}

// ModifyDNResponse ::= [APPLICATION 13] LDAPResult
fn parse_ldap_moddn_response(bytes: &[u8]) -> Result<LdapResult> {
    TaggedParser::from_ber_and_then(Class::Application, 13, bytes, parse_ldap_result_content)
}

// CompareRequest ::= [APPLICATION 14] SEQUENCE {
//     entry           LDAPDN,
//     ava             AttributeValueAssertion }
impl<'a> FromBer<'a, LdapError> for CompareRequest<'a> {
    fn from_ber(bytes: &'a [u8]) -> ParseResult<'a, Self, LdapError> {
        TaggedParser::from_ber_and_then(Class::Application, 14, bytes, |i| {
            let (i, entry) = LdapDN::from_ber(i)?;
            let (i, ava) = AttributeValueAssertion::from_ber(i)?;
            let res = CompareRequest { entry, ava };
            Ok((i, res))
        })
    }
}

// CompareResponse ::= [APPLICATION 15] LDAPResult
fn parse_ldap_compare_response(bytes: &[u8]) -> Result<LdapResult> {
    TaggedParser::from_ber_and_then(Class::Application, 15, bytes, parse_ldap_result_content)
}

// AbandonRequest ::= [APPLICATION 16] MessageID
fn parse_ldap_abandon_request(bytes: &[u8]) -> Result<MessageID> {
    let (rem, id) = TaggedValue::<u32, _, Implicit, { Class::APPLICATION }, 16>::from_ber(bytes)
        .map_err(Err::convert)?;
    Ok((rem, MessageID(id.into_inner())))
}

// SearchResultReference ::= [APPLICATION 19] SEQUENCE
//                                   SIZE (1..MAX) OF uri URI
fn parse_ldap_search_result_ref(bytes: &[u8]) -> Result<Vec<LdapString>> {
    TaggedParser::from_ber_and_then(
        Class::Application,
        19,
        bytes,
        many1(complete(parse_ldap_uri)),
    )
}

// ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
//     requestName      [0] LDAPOID,
//     requestValue     [1] OCTET STRING OPTIONAL }
impl<'a> FromBer<'a, LdapError> for ExtendedRequest<'a> {
    fn from_ber(bytes: &'a [u8]) -> ParseResult<'a, Self, LdapError> {
        TaggedParser::from_ber_and_then(Class::Application, 23, bytes, |i| {
            let (i, request_name) =
                TaggedParser::from_ber_and_then(Class::ContextSpecific, 0, i, |i| {
                    let s = std::str::from_utf8(i).or(Err(Err::Error(LdapError::InvalidDN)))?;
                    let oid = LdapOID(Cow::Borrowed(s));
                    Ok((&b""[..], oid))
                })?;
            let (i, request_value) = OptTaggedParser::new(Class::ContextSpecific, Tag(1))
                .parse_ber(i, |_, data| Ok((&b""[..], Cow::Borrowed(data))))?;
            let req = ExtendedRequest {
                request_name,
                request_value,
            };
            Ok((i, req))
        })
    }
}

// ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
//     COMPONENTS OF LDAPResult,
//     responseName     [10] LDAPOID OPTIONAL,
//     responseValue    [11] OCTET STRING OPTIONAL }
impl<'a> FromBer<'a, LdapError> for ExtendedResponse<'a> {
    fn from_ber(bytes: &'a [u8]) -> ParseResult<'a, Self, LdapError> {
        TaggedParser::from_ber_and_then(Class::Application, 24, bytes, |i| {
            let (i, result) = parse_ldap_result_content(i)?;
            let (i, response_name) = OptTaggedParser::new(Class::ContextSpecific, Tag(10))
                .parse_ber(i, |_, i| {
                    let s = std::str::from_utf8(i).or(Err(Err::Error(LdapError::InvalidDN)))?;
                    let oid = LdapOID(Cow::Borrowed(s));
                    Ok((&b""[..], oid))
                })?;
            let (i, response_value) = OptTaggedParser::new(Class::ContextSpecific, Tag(11))
                .parse_ber(i, |_, data| Ok((&b""[..], Cow::Borrowed(data))))?;
            let resp = ExtendedResponse {
                result,
                response_name,
                response_value,
            };
            Ok((i, resp))
        })
    }
}

// IntermediateResponse ::= [APPLICATION 25] SEQUENCE {
//      responseName     [0] LDAPOID OPTIONAL,
//      responseValue    [1] OCTET STRING OPTIONAL }
impl<'a> FromBer<'a, LdapError> for IntermediateResponse<'a> {
    fn from_ber(bytes: &'a [u8]) -> ParseResult<'a, Self, LdapError> {
        TaggedParser::from_ber_and_then(Class::Application, 25, bytes, |i| {
            let (i, response_name) = OptTaggedParser::new(Class::ContextSpecific, Tag(0))
                .parse_ber(i, |_, i| {
                    let s = std::str::from_utf8(i).or(Err(Err::Error(LdapError::InvalidDN)))?;
                    let oid = LdapOID(Cow::Borrowed(s));
                    Ok((&b""[..], oid))
                })?;
            let (i, response_value) = OptTaggedParser::new(Class::ContextSpecific, Tag(1))
                .parse_ber(i, |_, data| Ok((&b""[..], Cow::Borrowed(data))))?;
            let resp = IntermediateResponse {
                response_name,
                response_value,
            };
            Ok((i, resp))
        })
    }
}

// AuthenticationChoice ::= CHOICE {
//      simple                  [0] OCTET STRING,
//                              -- 1 and 2 reserved
//      sasl                    [3] SaslCredentials,
//      ...  }
impl<'a> FromBer<'a, LdapError> for AuthenticationChoice<'a> {
    fn from_ber(bytes: &'a [u8]) -> ParseResult<'a, Self, LdapError> {
        let (rem, header) = Header::from_ber(bytes).map_err(Err::convert)?;
        match header.tag().0 {
            0 => {
                // assume len is primitive, and just take bytes
                let sz = header
                    .length()
                    .definite()
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
            _ => Err(Err::Error(LdapError::InvalidAuthenticationType)),
        }
    }
}

// SaslCredentials ::= SEQUENCE {
//      mechanism               LDAPString,
//      credentials             OCTET STRING OPTIONAL }
fn parse_sasl_credentials(i: &[u8]) -> Result<SaslCredentials> {
    let (i, mechanism) = LdapString::from_ber(i)?;
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
fn parse_attribute_selection(bytes: &[u8]) -> Result<Vec<LdapString>> {
    Sequence::from_ber_and_then(bytes, many0(complete(LdapString::from_ber)))
}

// PartialAttributeList ::= SEQUENCE OF partialAttribute PartialAttribute
fn parse_partial_attribute_list(bytes: &[u8]) -> Result<Vec<PartialAttribute>> {
    Sequence::from_ber_and_then(bytes, many0(complete(PartialAttribute::from_ber)))
}

// AttributeList ::= SEQUENCE OF attribute Attribute
fn parse_attribute_list(bytes: &[u8]) -> Result<Vec<Attribute>> {
    Sequence::from_ber_and_then(bytes, many0(complete(Attribute::from_ber)))
}

// change SEQUENCE {
//          operation       ENUMERATED {
//               add     (0),
//               delete  (1),
//               replace (2),
//               ...  },
//          modification    PartialAttribute }
impl<'a> FromBer<'a, LdapError> for Change<'a> {
    fn from_ber(bytes: &'a [u8]) -> ParseResult<'a, Self, LdapError> {
        Sequence::from_ber_and_then(bytes, |i| {
            let (i, operation) = map(parse_ldap_enum_as_u32, Operation)(i)?;
            let (i, modification) = PartialAttribute::from_ber(i)?;
            let change = Change {
                operation,
                modification,
            };
            Ok((i, change))
        })
    }
}

// Control ::= SEQUENCE {
//     controlType             LDAPOID,
//     criticality             BOOLEAN DEFAULT FALSE,
//     controlValue            OCTET STRING OPTIONAL }
impl<'a> FromBer<'a, LdapError> for Control<'a> {
    fn from_ber(bytes: &'a [u8]) -> ParseResult<'a, Self, LdapError> {
        Sequence::from_ber_and_then(bytes, |i| {
            let (i, control_type) = LdapOID::from_ber(i)?;
            let (i, maybe_critical) = <Option<bool>>::from_ber(i).map_err(Err::convert)?;
            // opt(complete(bool::from_ber))(i).map_err(Err::convert)?;
            let criticality = maybe_critical.unwrap_or(false);
            let (i, control_value) = opt(complete(map(
                parse_ldap_octet_string_as_slice,
                Cow::Borrowed,
            )))(i)?;
            let control = Control {
                control_type,
                criticality,
                control_value,
            };
            Ok((i, control))
        })
    }
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
    use asn1_rs::oid;
    use hex_literal::hex;

    #[test]
    fn test_parse_bind_request() {
        const DATA: &[u8] = include_bytes!("../assets/bind_request.bin");

        let (rem, req) = BindRequest::from_ber(DATA).expect("parsing failed");
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

        let (rem, req) = BindRequest::from_ber(DATA).expect("parsing failed");
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
        let (rem, resp) = BindResponse::from_ber(DATA).expect("parsing failed");
        //
        // dbg!(&resp);
        //
        assert!(rem.is_empty());
        assert_eq!(resp.result.result_code, ResultCode::Success);
    }

    #[test]
    fn test_parse_bind_response_sasl() {
        const DATA: &[u8] = include_bytes!("../assets/bind_response_sasl.bin");
        let (rem, resp) = BindResponse::from_ber(DATA).expect("parsing failed");
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
        let (rem, resp) = SearchRequest::from_ber(DATA).expect("parsing failed");
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
        let (rem, resp) = SearchResultEntry::from_ber(DATA).expect("parsing failed");
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
        let (rem, req) = ExtendedRequest::from_ber(DATA).expect("parsing failed");
        //
        // dbg!(&req);
        //
        assert!(rem.is_empty());
        assert_eq!(
            req.request_name.0,
            oid!(1.3.6 .1 .4 .1 .1466 .20037).to_string()
        );
        assert!(req.request_value.is_none());
    }

    #[test]
    fn test_parse_extended_response() {
        const DATA: &[u8] = &hex!("78 07 0a 01 00 04 00 04 00");
        let (rem, resp) = ExtendedResponse::from_ber(DATA).expect("parsing failed");
        //
        // dbg!(&resp);
        //
        assert!(rem.is_empty());
        assert_eq!(resp.result.result_code, ResultCode::Success);
    }

    #[test]
    fn test_parse_modify_request() {
        const DATA: &[u8] = include_bytes!("../assets/modify-request.bin");
        let (rem, req) = ModifyRequest::from_ber(DATA).expect("parsing failed");
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
        let (rem, req) = AddRequest::from_ber(DATA).expect("parsing failed");
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
        let (rem, req) = ModDnRequest::from_ber(DATA).expect("parsing failed");
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
        let (rem, req) = CompareRequest::from_ber(DATA).expect("parsing failed");
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

    #[test]
    fn test_parse_abandon_request() {
        const DATA: &[u8] = &[0x30, 0x06, 0x02, 0x01, 0x06, 0x50, 0x01, 0x05];

        let (rem, msg) = LdapMessage::from_ber(DATA).expect("parsing failed");
        assert!(rem.is_empty());
        assert_eq!(msg.message_id, MessageID(6));
        assert!(matches!(
            msg.protocol_op,
            ProtocolOp::AbandonRequest(MessageID(5))
        ))
    }
}
