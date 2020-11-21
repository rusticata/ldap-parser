//! Definition for types used in LDAP filters

use crate::ldap::LdapString;
use std::borrow::Cow;

#[derive(Debug, PartialEq)]
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

#[derive(Debug, PartialEq)]
pub struct PartialAttribute<'a> {
    pub attr_type: LdapString<'a>,
    pub attr_vals: Vec<AttributeValue<'a>>,
}

#[derive(Debug, PartialEq)]
pub struct Attribute<'a> {
    pub attr_type: LdapString<'a>,
    pub attr_vals: Vec<AttributeValue<'a>>,
}

#[derive(Debug, PartialEq)]
pub struct AttributeValueAssertion<'a> {
    pub attribute_desc: LdapString<'a>,
    pub assertion_value: &'a [u8],
}

#[derive(Debug, PartialEq)]
pub struct AttributeDescription<'a>(pub Cow<'a, str>);

#[derive(Debug, PartialEq)]
pub struct MatchingRuleAssertion<'a> {
    pub matching_rule: Option<LdapString<'a>>,
    pub rule_type: Option<AttributeDescription<'a>>,
    pub assertion_value: AssertionValue<'a>,
    pub dn_attributes: Option<bool>,
}

#[derive(Debug, PartialEq)]
pub struct MatchingRuleId<'a>(pub Cow<'a, str>);

#[derive(Debug, PartialEq)]
pub struct SubstringFilter<'a> {
    pub filter_type: LdapString<'a>,
    pub substrings: Vec<Substring<'a>>,
}

#[derive(Debug, PartialEq)]
pub enum Substring<'a> {
    Initial(AssertionValue<'a>),
    Any(AssertionValue<'a>),
    Final(AssertionValue<'a>),
}

#[derive(Debug, PartialEq)]
pub struct AssertionValue<'a>(pub Cow<'a, [u8]>);

#[derive(Debug, PartialEq)]
pub struct AttributeValue<'a>(pub Cow<'a, [u8]>);
