use crate::filter::*;
use rusticata_macros::newtype_enum;
use std::borrow::Cow;

#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
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
}
}

#[derive(Default, PartialEq, Eq, Clone, Copy)]
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

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
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

#[derive(Debug, PartialEq)]
pub struct LdapString<'a>(pub Cow<'a, str>);

#[derive(Debug, PartialEq)]
pub struct LdapDN<'a>(pub Cow<'a, str>);

#[derive(Debug, PartialEq)]
pub struct RelativeLdapDN<'a>(pub Cow<'a, str>);

#[derive(Debug, PartialEq)]
pub struct LdapOID<'a>(pub Cow<'a, str>);

#[derive(Debug, PartialEq)]
pub struct LdapResult<'a> {
    pub result_code: ResultCode,
    pub matched_dn: LdapDN<'a>,
    pub diagnostic_message: LdapString<'a>,
    // referral           [3] Referral OPTIONAL
}

#[derive(Debug, PartialEq)]
pub struct BindRequest<'a> {
    pub version: u8,
    pub name: LdapDN<'a>,
    pub authentication: AuthenticationChoice<'a>,
}

#[derive(Debug, PartialEq)]
pub struct SaslCredentials<'a> {
    pub mechanism: LdapString<'a>,
    pub credentials: Option<Cow<'a, [u8]>>,
}

#[derive(Debug, PartialEq)]
pub enum AuthenticationChoice<'a> {
    Simple(Cow<'a, [u8]>),
    Sasl(SaslCredentials<'a>),
}

#[derive(Debug, PartialEq)]
pub struct BindResponse<'a> {
    pub result: LdapResult<'a>,
    pub server_sasl_creds: Option<Cow<'a, [u8]>>,
}

#[derive(Debug, PartialEq)]
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

#[derive(Debug, PartialEq)]
pub struct SearchResultEntry<'a> {
    pub object_name: LdapDN<'a>,
    pub attributes: Vec<PartialAttribute<'a>>,
}

#[derive(Debug, PartialEq)]
pub struct ModifyRequest<'a> {
    pub object: LdapDN<'a>,
    pub changes: Vec<Change<'a>>,
}

#[derive(Debug, PartialEq)]
pub struct ModifyResponse<'a> {
    pub result: LdapResult<'a>,
}

#[derive(Debug, PartialEq)]
pub struct Change<'a> {
    pub operation: Operation,
    pub modification: PartialAttribute<'a>,
}

#[derive(Debug, PartialEq)]
pub struct AddRequest<'a> {
    pub entry: LdapDN<'a>,
    pub attributes: Vec<Attribute<'a>>,
}

#[derive(Debug, PartialEq)]
pub struct ModDnRequest<'a> {
    pub entry: LdapDN<'a>,
    pub newrdn: RelativeLdapDN<'a>,
    pub deleteoldrdn: bool,
    pub newsuperior: Option<LdapDN<'a>>,
}

#[derive(Debug, PartialEq)]
pub struct CompareRequest<'a> {
    pub entry: LdapDN<'a>,
    pub ava: AttributeValueAssertion<'a>,
}

#[derive(Debug, PartialEq)]
pub struct ExtendedRequest<'a> {
    pub request_name: LdapOID<'a>,
    pub request_value: Option<Cow<'a, [u8]>>,
}

#[derive(Debug, PartialEq)]
pub struct ExtendedResponse<'a> {
    pub result: LdapResult<'a>,
    pub request_name: Option<LdapOID<'a>>,
    pub request_value: Option<Cow<'a, [u8]>>,
}

#[derive(Debug, PartialEq)]
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
}

impl<'a> ProtocolOp<'a> {
    // Get tag number associated with the operation
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
        };
        ProtocolOpTag(op)
    }
}

#[derive(Debug, PartialEq)]
pub struct Control<'a> {
    pub control_type: LdapOID<'a>,
    pub criticality: bool,
    pub control_value: Option<Cow<'a, [u8]>>,
}

#[derive(Debug, PartialEq)]
pub struct LdapMessage<'a> {
    pub message_id: MessageID,
    pub protocol_op: ProtocolOp<'a>,
    pub controls: Option<Vec<Control<'a>>>,
}
