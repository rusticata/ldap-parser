//! Definition for types used in LDAP filters

use crate::ldap::LdapString;
use asn1_rs::ToStatic;
use std::borrow::Cow;

#[derive(Clone, Debug, Eq, PartialEq, ToStatic)]
pub enum Filter<'a> {
    And(Vec<Filter<'a>>),
    Or(Vec<Filter<'a>>),
    Not(Box<Filter<'a>>),
    EqualityMatch(AttributeValueAssertion<'a>),
    Substrings(SubstringFilter<'a>),
    GreaterOrEqual(AttributeValueAssertion<'a>),
    LessOrEqual(AttributeValueAssertion<'a>),
    Present(LdapString<'a>),
    ApproxMatch(AttributeValueAssertion<'a>),
    ExtensibleMatch(MatchingRuleAssertion<'a>),
}

#[derive(Clone, Debug, Eq, PartialEq, ToStatic)]
pub struct PartialAttribute<'a> {
    pub attr_type: LdapString<'a>,
    pub attr_vals: Vec<AttributeValue<'a>>,
}

#[derive(Clone, Debug, Eq, PartialEq, ToStatic)]
pub struct Attribute<'a> {
    pub attr_type: LdapString<'a>,
    pub attr_vals: Vec<AttributeValue<'a>>,
}

#[derive(Clone, Debug, Eq, PartialEq, ToStatic)]
pub struct AttributeValueAssertion<'a> {
    pub attribute_desc: LdapString<'a>,
    pub assertion_value: Cow<'a, [u8]>,
}

#[derive(Clone, Debug, Eq, PartialEq, ToStatic)]
pub struct AttributeDescription<'a>(pub Cow<'a, str>);

#[derive(Clone, Debug, Eq, PartialEq, ToStatic)]
pub struct MatchingRuleAssertion<'a> {
    pub matching_rule: Option<LdapString<'a>>,
    pub rule_type: Option<AttributeDescription<'a>>,
    pub assertion_value: AssertionValue<'a>,
    pub dn_attributes: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq, ToStatic)]
pub struct MatchingRuleId<'a>(pub Cow<'a, str>);

#[derive(Clone, Debug, Eq, PartialEq, ToStatic)]
pub struct SubstringFilter<'a> {
    pub filter_type: LdapString<'a>,
    pub substrings: Vec<Substring<'a>>,
}

#[derive(Clone, Debug, Eq, PartialEq, ToStatic)]
pub enum Substring<'a> {
    Initial(AssertionValue<'a>),
    Any(AssertionValue<'a>),
    Final(AssertionValue<'a>),
}

#[derive(Clone, Debug, Eq, PartialEq, ToStatic)]
pub struct AssertionValue<'a>(pub Cow<'a, [u8]>);

#[derive(Clone, Debug, Eq, PartialEq, ToStatic)]
pub struct AttributeValue<'a>(pub Cow<'a, [u8]>);
