//! Definitions for LDAP types

use crate::error::Result;
use crate::filter::*;
use asn1_rs::FromBer;
use rusticata_macros::newtype_enum;
use std::borrow::Cow;

#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct ProtocolOpTag(pub u32);

newtype_enum! {
impl display ProtocolOpTag {
    BindRequest = 0,
    BindResponse = 1,
    UnbindRequest = 2,
    SearchRequest = 3,
    SearchResultEntry = 4,
    SearchResultDone = 5,
    ModifyRequest = 6,
    ModifyResponse = 7,
    AddRequest = 8,
    AddResponse = 9,
    DelRequest = 10,
    DelResponse = 11,
    ModDnRequest = 12,
    ModDnResponse = 13,
    CompareRequest = 14,
    CompareResponse = 15,
    AbandonRequest = 16,
    SearchResultReference = 19,
    ExtendedRequest = 23,
    ExtendedResponse = 24,
    IntermediateResponse = 25,
}
}

#[derive(Default, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct ResultCode(pub u32);

newtype_enum! {
impl debug ResultCode {
    Success = 0,
    OperationsError = 1,
    ProtocolError = 2,
    TimeLimitExceeded = 3,
    SizeLimitExceeded = 4,
    CompareFalse = 5,
    CompareTrue = 6,
    AuthMethodNotSupported = 7,
    StrongerAuthRequired = 8,
    // -- 9 reserved --
    Referral = 10,
    AdminLimitExceeded = 11,
    UnavailableCriticalExtension = 12,
    ConfidentialityRequired = 13,
    SaslBindInProgress = 14,
    NoSuchAttribute = 16,
    UndefinedAttributeType = 17,
    InappropriateMatching = 18,
    ConstraintViolation = 19,
    AttributeOrValueExists = 20,
    InvalidAttributeSyntax = 21,
    // -- 22-31 unused --
    NoSuchObject = 32,
    AliasProblem = 33,
    InvalidDNSyntax = 34,
    // -- 35 reserved for undefined isLeaf --
    AliasDereferencingProblem = 36,
    // -- 37-47 unused --
    InappropriateAuthentication = 48,
    InvalidCredentials = 49,
    InsufficientAccessRights = 50,
    Busy = 51,
    Unavailable = 52,
    UnwillingToPerform = 53,
    LoopDetect = 54,
    // -- 55-63 unused --
    NamingViolation = 64,
    ObjectClassViolation = 65,
    NotAllowedOnNonLeaf = 66,
    NotAllowedOnRDN = 67,
    EntryAlreadyExists = 68,
    ObjectClassModsProhibited = 69,
    // -- 70 reserved for CLDAP --
    AffectsMultipleDSAs = 71,
    // -- 72-79 unused --
    Other = 80,
}
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct MessageID(pub u32);

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct SearchScope(pub u32);

newtype_enum! {
impl debug SearchScope {
    BaseObject = 0,
    SingleLevel = 1,
    WholeSubtree = 2,
}
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct DerefAliases(pub u32);

newtype_enum! {
impl debug DerefAliases {
    NeverDerefAliases = 0,
    DerefInSearching = 1,
    DerefFindingBaseObj = 2,
    DerefAlways = 3,
}
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct Operation(pub u32);

newtype_enum! {
impl debug Operation {
    Add = 0,
    Delete = 1,
    Replace = 2,
}
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LdapString<'a>(pub Cow<'a, str>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LdapDN<'a>(pub Cow<'a, str>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelativeLdapDN<'a>(pub Cow<'a, str>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LdapOID<'a>(pub Cow<'a, str>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LdapResult<'a> {
    pub result_code: ResultCode,
    pub matched_dn: LdapDN<'a>,
    pub diagnostic_message: LdapString<'a>,
    // referral           [3] Referral OPTIONAL
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindRequest<'a> {
    pub version: u8,
    pub name: LdapDN<'a>,
    pub authentication: AuthenticationChoice<'a>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SaslCredentials<'a> {
    pub mechanism: LdapString<'a>,
    pub credentials: Option<Cow<'a, [u8]>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthenticationChoice<'a> {
    Simple(Cow<'a, [u8]>),
    Sasl(SaslCredentials<'a>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindResponse<'a> {
    pub result: LdapResult<'a>,
    pub server_sasl_creds: Option<Cow<'a, [u8]>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchRequest<'a> {
    pub base_object: LdapDN<'a>,
    pub scope: SearchScope,
    pub deref_aliases: DerefAliases,
    pub size_limit: u32,
    pub time_limit: u32,
    pub types_only: bool,
    pub filter: Filter<'a>,
    pub attributes: Vec<LdapString<'a>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchResultEntry<'a> {
    pub object_name: LdapDN<'a>,
    pub attributes: Vec<PartialAttribute<'a>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModifyRequest<'a> {
    pub object: LdapDN<'a>,
    pub changes: Vec<Change<'a>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModifyResponse<'a> {
    pub result: LdapResult<'a>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Change<'a> {
    pub operation: Operation,
    pub modification: PartialAttribute<'a>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddRequest<'a> {
    pub entry: LdapDN<'a>,
    pub attributes: Vec<Attribute<'a>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModDnRequest<'a> {
    pub entry: LdapDN<'a>,
    pub newrdn: RelativeLdapDN<'a>,
    pub deleteoldrdn: bool,
    pub newsuperior: Option<LdapDN<'a>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompareRequest<'a> {
    pub entry: LdapDN<'a>,
    pub ava: AttributeValueAssertion<'a>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtendedRequest<'a> {
    pub request_name: LdapOID<'a>,
    pub request_value: Option<Cow<'a, [u8]>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtendedResponse<'a> {
    pub result: LdapResult<'a>,
    pub response_name: Option<LdapOID<'a>>,
    pub response_value: Option<Cow<'a, [u8]>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntermediateResponse<'a> {
    pub response_name: Option<LdapOID<'a>>,
    pub response_value: Option<Cow<'a, [u8]>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolOp<'a> {
    BindRequest(BindRequest<'a>),
    BindResponse(BindResponse<'a>),
    UnbindRequest,
    SearchRequest(SearchRequest<'a>),
    SearchResultEntry(SearchResultEntry<'a>),
    SearchResultDone(LdapResult<'a>),
    SearchResultReference(Vec<LdapString<'a>>),
    ModifyRequest(ModifyRequest<'a>),
    ModifyResponse(ModifyResponse<'a>),
    AddRequest(AddRequest<'a>),
    AddResponse(LdapResult<'a>),
    DelRequest(LdapDN<'a>),
    DelResponse(LdapResult<'a>),
    ModDnRequest(ModDnRequest<'a>),
    ModDnResponse(LdapResult<'a>),
    CompareRequest(CompareRequest<'a>),
    CompareResponse(LdapResult<'a>),
    //
    AbandonRequest(MessageID),
    ExtendedRequest(ExtendedRequest<'a>),
    ExtendedResponse(ExtendedResponse<'a>),
    IntermediateResponse(IntermediateResponse<'a>),
}

impl ProtocolOp<'_> {
    /// Get tag number associated with the operation
    pub fn tag(&self) -> ProtocolOpTag {
        let op = match self {
            ProtocolOp::BindRequest(_) => 0,
            ProtocolOp::BindResponse(_) => 1,
            ProtocolOp::UnbindRequest => 2,
            ProtocolOp::SearchRequest(_) => 3,
            ProtocolOp::SearchResultEntry(_) => 4,
            ProtocolOp::SearchResultDone(_) => 5,
            ProtocolOp::ModifyRequest(_) => 6,
            ProtocolOp::ModifyResponse(_) => 7,
            ProtocolOp::AddRequest(_) => 8,
            ProtocolOp::AddResponse(_) => 9,
            ProtocolOp::DelRequest(_) => 10,
            ProtocolOp::DelResponse(_) => 11,
            ProtocolOp::ModDnRequest(_) => 12,
            ProtocolOp::ModDnResponse(_) => 13,
            ProtocolOp::CompareRequest(_) => 14,
            ProtocolOp::CompareResponse(_) => 15,
            ProtocolOp::AbandonRequest(_) => 16,
            ProtocolOp::SearchResultReference(_) => 19,
            ProtocolOp::ExtendedRequest(_) => 23,
            ProtocolOp::ExtendedResponse(_) => 24,
            ProtocolOp::IntermediateResponse(_) => 25,
        };
        ProtocolOpTag(op)
    }

    /// Get the LDAP result, if present
    pub fn result(&self) -> Option<&LdapResult> {
        match self {
            ProtocolOp::BindResponse(r) => Some(&r.result),
            ProtocolOp::ModifyResponse(r) => Some(&r.result),
            ProtocolOp::ExtendedResponse(r) => Some(&r.result),
            ProtocolOp::SearchResultDone(ref r)
            | ProtocolOp::AddResponse(ref r)
            | ProtocolOp::DelResponse(ref r)
            | ProtocolOp::ModDnResponse(ref r)
            | ProtocolOp::CompareResponse(ref r) => Some(r),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Control<'a> {
    pub control_type: LdapOID<'a>,
    pub criticality: bool,
    pub control_value: Option<Cow<'a, [u8]>>,
}

/// An LDAP Message according to RFC4511
///
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LdapMessage<'a> {
    /// Message Identifier (32-bits unsigned integer)
    ///
    /// The messageID of a request MUST have a non-zero value different from the messageID of any
    /// other request in progress in the same LDAP session.  The zero value is reserved for the
    /// unsolicited notification message.
    pub message_id: MessageID,
    /// The LDAP operation from this LDAP message
    pub protocol_op: ProtocolOp<'a>,
    /// Message controls (optional)
    ///
    /// Controls provide a mechanism whereby the semantics and arguments of existing LDAP
    /// operations may be extended.  One or more controls may be attached to a single LDAP message.
    /// A control only affects the semantics of the message it is attached to.
    pub controls: Option<Vec<Control<'a>>>,
}

impl<'a> LdapMessage<'a> {
    /// Parse a single LDAP message and return a structure borrowing fields from the input buffer
    #[deprecated(
        since = "0.3.0",
        note = "Parsing functions are deprecated. Users should instead use the FromBer trait"
    )]
    #[inline]
    pub fn parse(i: &'a [u8]) -> Result<'a, LdapMessage<'a>> {
        Self::from_ber(i)
    }
}
