use crate::error::*;
use crate::filter::*;
use crate::ldap::*;
use crate::parser::*;
use asn1_rs::nom;
use asn1_rs::OptTaggedImplicit;
use asn1_rs::{
    Any, Class, FromBer, OptTaggedParser, ParseResult, Sequence, Set, Tag, TaggedParser,
};
use nom::combinator::{complete, map};
use nom::multi::{many0, many1};
use nom::Err;
// use nom::dbg_dmp;
use std::borrow::Cow;

// AttributeDescription ::= LDAPString
//                         -- Constrained to <attributedescription>
//                         -- [RFC4512]
#[inline]
fn parse_ldap_attribute_description(i: &[u8]) -> Result<'_, LdapString<'_>> {
    LdapString::from_ber(i)
}

// AttributeValue ::= OCTET STRING
// #[inline]
// fn parse_ldap_attribute_value(i: &[u8]) -> Result<&[u8]> {
//     parse_ldap_octet_string_as_slice(i)
// }

// AttributeValueAssertion ::= SEQUENCE {
//      attributeDesc   AttributeDescription,
//      assertionValue  AssertionValue }
fn parse_ldap_attribute_value_assertion_content(
    content: &[u8],
) -> Result<'_, AttributeValueAssertion<'_>> {
    let (content, attribute_desc) = parse_ldap_attribute_description(content)?;
    let (content, assertion_value) = parse_ldap_assertion_value(content)?;
    let assertion = AttributeValueAssertion {
        attribute_desc,
        assertion_value: assertion_value.into(),
    };
    Ok((content, assertion))
}

impl<'a> FromBer<'a, LdapError> for AttributeValueAssertion<'a> {
    fn from_ber(bytes: &'a [u8]) -> ParseResult<'a, Self, LdapError> {
        Sequence::from_ber_and_then(bytes, parse_ldap_attribute_value_assertion_content)
    }
}

// AssertionValue ::= OCTET STRING
#[inline]
fn parse_ldap_assertion_value(i: &[u8]) -> Result<'_, &[u8]> {
    parse_ldap_octet_string_as_slice(i)
}

// AttributeValue ::= OCTET STRING
#[inline]
fn parse_ldap_attribute_value(i: &[u8]) -> Result<'_, AttributeValue<'_>> {
    map(parse_ldap_octet_string_as_slice, |v| {
        AttributeValue(Cow::Borrowed(v))
    })(i)
}

// PartialAttribute ::= SEQUENCE {
//      type       AttributeDescription,
//      vals       SET OF value AttributeValue }
impl<'a> FromBer<'a, LdapError> for PartialAttribute<'a> {
    fn from_ber(bytes: &'a [u8]) -> ParseResult<'a, Self, LdapError> {
        Sequence::from_ber_and_then(bytes, |i| {
            let (i, attr_type) = LdapString::from_ber(i)?;
            let (i, attr_vals) = Set::from_ber_and_then(i, |inner| {
                many0(complete(
                    // dbg_dmp(|d| parse_ldap_attribute_value(d), "parse_partial_attribute")
                    parse_ldap_attribute_value,
                ))(inner)
            })?;
            let partial_attr = PartialAttribute {
                attr_type,
                attr_vals,
            };
            Ok((i, partial_attr))
        })
    }
}

// Attribute ::= PartialAttribute(WITH COMPONENTS {
//      ...,
//      vals (SIZE(1..MAX))})
impl<'a> FromBer<'a, LdapError> for Attribute<'a> {
    fn from_ber(bytes: &'a [u8]) -> ParseResult<'a, Self, LdapError> {
        Sequence::from_ber_and_then(bytes, |i| {
            let (i, attr_type) = LdapString::from_ber(i)?;
            let (i, attr_vals) = Set::from_ber_and_then(i, |inner| {
                many1(complete(
                    // dbg_dmp(|d| parse_ldap_attribute_value(d), "parse_partial_attribute")
                    parse_ldap_attribute_value,
                ))(inner)
            })?;
            let attr = Attribute {
                attr_type,
                attr_vals,
            };
            Ok((i, attr))
        })
    }
}

// MatchingRuleId ::= LDAPString

// Filter ::= CHOICE {
//     and             [0] SET SIZE (1..MAX) OF filter Filter,
//     or              [1] SET SIZE (1..MAX) OF filter Filter,
//     not             [2] Filter,
//     equalityMatch   [3] AttributeValueAssertion,
//     substrings      [4] SubstringFilter,
//     greaterOrEqual  [5] AttributeValueAssertion,
//     lessOrEqual     [6] AttributeValueAssertion,
//     present         [7] AttributeDescription,
//     approxMatch     [8] AttributeValueAssertion,
//     extensibleMatch [9] MatchingRuleAssertion,
//     ...  }
impl<'a> FromBer<'a, LdapError> for Filter<'a> {
    fn from_ber(bytes: &'a [u8]) -> ParseResult<'a, Self, LdapError> {
        // read next element as ANY and look tag value
        let (rem, any) = Any::from_ber(bytes).map_err(Err::convert)?;
        // eprintln!("parse_ldap_filter: [{}] {:?}", header.tag.0, header);
        // tag is context-specific IMPLICIT
        any.class()
            .assert_eq(Class::ContextSpecific)
            .map_err(|e| Err::Error(e.into()))?;
        let content = any.data;
        let (_, filter) = match any.tag().0 {
            0 => {
                let (rem, sub_filters) = many1(complete(Filter::from_ber))(content)?;
                Ok((rem, Filter::And(sub_filters)))
            }
            1 => {
                let (rem, sub_filters) = many1(complete(Filter::from_ber))(content)?;
                Ok((rem, Filter::Or(sub_filters)))
            }
            2 => map(Filter::from_ber, |f| Filter::Not(Box::new(f)))(content),
            3 => map(
                parse_ldap_attribute_value_assertion_content,
                Filter::EqualityMatch,
            )(content),
            4 => map(parse_ldap_substrings_filter_content, Filter::Substrings)(content),
            5 => map(
                parse_ldap_attribute_value_assertion_content,
                Filter::GreaterOrEqual,
            )(content),
            6 => map(
                parse_ldap_attribute_value_assertion_content,
                Filter::LessOrEqual,
            )(content),
            7 => {
                let s =
                    std::str::from_utf8(content).or(Err(Err::Error(LdapError::InvalidString)))?;
                let s = LdapString(Cow::Borrowed(s));
                Ok(([].as_ref(), Filter::Present(s)))
            }
            8 => map(
                parse_ldap_attribute_value_assertion_content,
                Filter::ApproxMatch,
            )(content),
            9 => map(
                parse_ldap_matching_rule_assertion_content,
                Filter::ExtensibleMatch,
            )(content),
            _ => {
                // print_hex_dump(i, 32);
                // panic!("Filter id {} not yet implemented", header.tag.0);
                Err(Err::Error(LdapError::InvalidFilterType))
            }
        }?;
        // use the remaining bytes from the outer object
        Ok((rem, filter))
    }
}

// SubstringFilter ::= SEQUENCE {
//      type           AttributeDescription,
//      substrings     SEQUENCE SIZE (1..MAX) OF substring CHOICE {
//           initial [0] AssertionValue,  -- can occur at most once
//           any     [1] AssertionValue,
//           final   [2] AssertionValue } -- can occur at most once
//      }
fn parse_ldap_substrings_filter_content(i: &[u8]) -> Result<'_, SubstringFilter<'_>> {
    let (i, filter_type) = parse_ldap_attribute_description(i)?;
    let (i, substrings) =
        Sequence::from_ber_and_then(i, |inner| many1(complete(parse_ldap_substring))(inner))?;
    let filter = SubstringFilter {
        filter_type,
        substrings,
    };
    Ok((i, filter))
}

fn parse_ldap_substring(bytes: &[u8]) -> Result<'_, Substring<'_>> {
    let (rem, any) = Any::from_ber(bytes).map_err(Err::convert)?;
    // in any case, this is an AssertionValue (== OCTET STRING)
    let b = AssertionValue(Cow::Borrowed(any.data));
    match any.tag().0 {
        0 => Ok((rem, Substring::Initial(b))),
        1 => Ok((rem, Substring::Any(b))),
        2 => Ok((rem, Substring::Final(b))),
        _ => Err(Err::Error(LdapError::InvalidSubstring)),
    }
}

// MatchingRuleAssertion ::= SEQUENCE {
//     matchingRule    [1] MatchingRuleId OPTIONAL,
//     type            [2] AttributeDescription OPTIONAL,
//     matchValue      [3] AssertionValue,
//     dnAttributes    [4] BOOLEAN DEFAULT FALSE }
fn parse_ldap_matching_rule_assertion_content(i: &[u8]) -> Result<'_, MatchingRuleAssertion<'_>> {
    // MatchingRuleId ::= LDAPString
    let (i, matching_rule) =
        OptTaggedParser::new(Class::ContextSpecific, Tag(1)).parse_ber(i, |_, content| {
            let s = std::str::from_utf8(content).or(Err(Err::Error(LdapError::InvalidString)))?;
            let s = LdapString(Cow::Borrowed(s));
            Ok((&b""[..], s))
        })?;
    let (i, rule_type) =
        OptTaggedParser::new(Class::ContextSpecific, Tag(2)).parse_ber(i, |_, content| {
            let s = std::str::from_utf8(content).or(Err(Err::Error(LdapError::InvalidString)))?;
            let s = AttributeDescription(Cow::Borrowed(s));
            Ok((&b""[..], s))
        })?;
    let (i, assertion_value) =
        TaggedParser::from_ber_and_then(Class::ContextSpecific, 3, i, |content| {
            let s = AssertionValue(Cow::Borrowed(content));
            Ok((&b""[..], s))
        })?;
    let (i, dn_attributes) =
        OptTaggedImplicit::<bool, asn1_rs::Error, 4>::from_ber(i).map_err(Err::convert)?;
    let dn_attributes = dn_attributes.map(|t| t.into_inner());
    let assertion = MatchingRuleAssertion {
        matching_rule,
        rule_type,
        assertion_value,
        dn_attributes,
    };
    Ok((i, assertion))
}
