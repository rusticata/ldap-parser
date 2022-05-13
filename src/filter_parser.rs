use crate::error::*;
use crate::filter::*;
use crate::ldap::*;
use crate::parser::*;
use der_parser::ber::*;
use nom::combinator::{complete, map, opt};
use nom::multi::{many0, many1};
use nom::Err;
// use nom::dbg_dmp;
use std::borrow::Cow;

// AttributeDescription ::= LDAPString
//                         -- Constrained to <attributedescription>
//                         -- [RFC4512]
#[inline]
fn parse_ldap_attribute_description(i: &[u8]) -> Result<LdapString> {
    parse_ldap_string(i)
}

// AttributeValue ::= OCTET STRING
// #[inline]
// fn parse_ldap_attribute_value(i: &[u8]) -> Result<&[u8]> {
//     parse_ldap_octet_string_as_slice(i)
// }

// AttributeValueAssertion ::= SEQUENCE {
//      attributeDesc   AttributeDescription,
//      assertionValue  AssertionValue }
fn parse_ldap_attribute_value_assertion_content(content: &[u8]) -> Result<AttributeValueAssertion> {
    let (content, attribute_desc) = parse_ldap_attribute_description(content)?;
    let (content, assertion_value) = parse_ldap_assertion_value(content)?;
    let assertion = AttributeValueAssertion {
        attribute_desc,
        assertion_value,
    };
    Ok((content, assertion))
}

pub(crate) fn parse_ldap_attribute_value_assertion(i: &[u8]) -> Result<AttributeValueAssertion> {
    parse_ber_sequence_defined_g(|i, _| parse_ldap_attribute_value_assertion_content(i))(i)
}

// AssertionValue ::= OCTET STRING
#[inline]
fn parse_ldap_assertion_value(i: &[u8]) -> Result<&[u8]> {
    parse_ldap_octet_string_as_slice(i)
}

// AttributeValue ::= OCTET STRING
#[inline]
fn parse_ldap_attribute_value(i: &[u8]) -> Result<AttributeValue> {
    map(parse_ldap_octet_string_as_slice, |v| {
        AttributeValue(Cow::Borrowed(v))
    })(i)
}

// PartialAttribute ::= SEQUENCE {
//      type       AttributeDescription,
//      vals       SET OF value AttributeValue }
pub(crate) fn parse_ldap_partial_attribute(i: &[u8]) -> Result<PartialAttribute> {
    parse_ber_sequence_defined_g(|i, _| {
        let (i, attr_type) = parse_ldap_string(i)?;
        let (i, attr_vals) = parse_ber_set_defined_g(|inner, _| {
            many0(complete(
                // dbg_dmp(|d| parse_ldap_attribute_value(d), "parse_partial_attribute")
                parse_ldap_attribute_value,
            ))(inner)
        })(i)?;
        let partial_attr = PartialAttribute {
            attr_type,
            attr_vals,
        };
        Ok((i, partial_attr))
    })(i)
}

// Attribute ::= PartialAttribute(WITH COMPONENTS {
//      ...,
//      vals (SIZE(1..MAX))})
pub(crate) fn parse_ldap_attribute(i: &[u8]) -> Result<Attribute> {
    parse_ber_sequence_defined_g(|i, _| {
        let (i, attr_type) = parse_ldap_string(i)?;
        let (i, attr_vals) = parse_ber_set_defined_g(|inner, _| {
            many1(complete(
                // dbg_dmp(|d| parse_ldap_attribute_value(d), "parse_partial_attribute")
                parse_ldap_attribute_value,
            ))(inner)
        })(i)?;
        let attr = Attribute {
            attr_type,
            attr_vals,
        };
        Ok((i, attr))
    })(i)
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
pub(crate) fn parse_ldap_filter(i: &[u8]) -> Result<Filter> {
    // read header of next element and look tag value
    let (_, header) = ber_read_element_header(i).map_err(Err::convert)?;
    // eprintln!("parse_ldap_filter: [{}] {:?}", header.tag.0, header);
    match header.tag().0 {
        0 => {
            let (i, sub_filters) = parse_ber_tagged_implicit_g(0, |content, _hdr, _depth| {
                many1(complete(parse_ldap_filter))(content)
            })(i)?;
            Ok((i, Filter::And(sub_filters)))
        }
        1 => {
            let (i, sub_filters) = parse_ber_tagged_implicit_g(1, |content, _hdr, _depth| {
                many1(complete(parse_ldap_filter))(content)
            })(i)?;
            Ok((i, Filter::Or(sub_filters)))
        }
        2 => {
            let (i, sub_filter) =
                parse_ber_tagged_implicit_g(2, |content, _hdr, _depth| parse_ldap_filter(content))(
                    i,
                )?;
            Ok((i, Filter::Not(Box::new(sub_filter))))
        }
        3 => parse_ber_tagged_implicit_g(3, |content, _hdr, _depth| {
            map(
                parse_ldap_attribute_value_assertion_content,
                Filter::EqualityMatch,
            )(content)
        })(i),
        4 => parse_ber_tagged_implicit_g(4, |content, _hdr, _depth| {
            map(parse_ldap_substrings_filter_content, Filter::Substrings)(content)
        })(i),
        5 => parse_ber_tagged_implicit_g(5, |content, _hdr, _depth| {
            map(
                parse_ldap_attribute_value_assertion_content,
                Filter::GreaterOrEqual,
            )(content)
        })(i),
        6 => parse_ber_tagged_implicit_g(6, |content, _hdr, _depth| {
            map(
                parse_ldap_attribute_value_assertion_content,
                Filter::LessOrEqual,
            )(content)
        })(i),
        7 => parse_ber_tagged_implicit_g(7, |content, _hdr, _depth| {
            let s = std::str::from_utf8(content).or(Err(Err::Error(LdapError::InvalidString)))?;
            let s = LdapString(Cow::Borrowed(s));
            Ok((i, Filter::Present(s)))
        })(i),
        8 => parse_ber_tagged_implicit_g(8, |content, _hdr, _depth| {
            map(
                parse_ldap_attribute_value_assertion_content,
                Filter::ApproxMatch,
            )(content)
        })(i),
        9 => parse_ber_tagged_implicit_g(9, |content, _hdr, _depth| {
            map(
                parse_ldap_matching_rule_assertion_content,
                Filter::ExtensibleMatch,
            )(content)
        })(i),
        _ => {
            // print_hex_dump(i, 32);
            // panic!("Filter id {} not yet implemented", header.tag.0);
            Err(Err::Error(LdapError::InvalidFilterType))
        }
    }
}

// SubstringFilter ::= SEQUENCE {
//      type           AttributeDescription,
//      substrings     SEQUENCE SIZE (1..MAX) OF substring CHOICE {
//           initial [0] AssertionValue,  -- can occur at most once
//           any     [1] AssertionValue,
//           final   [2] AssertionValue } -- can occur at most once
//      }
fn parse_ldap_substrings_filter_content(i: &[u8]) -> Result<SubstringFilter> {
    let (i, filter_type) = parse_ldap_attribute_description(i)?;
    let (i, substrings) =
        parse_ber_sequence_defined_g(|d, _| many1(complete(parse_ldap_substring))(d))(i)?;
    let filter = SubstringFilter {
        filter_type,
        substrings,
    };
    Ok((i, filter))
}

fn parse_ldap_substring(i: &[u8]) -> Result<Substring> {
    parse_ber_container(|i, hdr| {
        // in any case, this is an AssertionValue (== OCTET STRING)
        let empty: &[u8] = &[];
        let b = AssertionValue(Cow::Borrowed(i));
        match hdr.tag().0 {
            0 => Ok((empty, Substring::Initial(b))),
            1 => Ok((empty, Substring::Any(b))),
            2 => Ok((empty, Substring::Final(b))),
            _ => Err(Err::Error(LdapError::InvalidSubstring)),
        }
    })(i)
}

// MatchingRuleAssertion ::= SEQUENCE {
//     matchingRule    [1] MatchingRuleId OPTIONAL,
//     type            [2] AttributeDescription OPTIONAL,
//     matchValue      [3] AssertionValue,
//     dnAttributes    [4] BOOLEAN DEFAULT FALSE }
fn parse_ldap_matching_rule_assertion_content(i: &[u8]) -> Result<MatchingRuleAssertion> {
    // MatchingRuleId ::= LDAPString
    let (i, matching_rule) = opt(complete(parse_ber_tagged_implicit_g(
        1,
        |content, _hdr, _depth| {
            let s = std::str::from_utf8(content).or(Err(Err::Error(LdapError::InvalidString)))?;
            let s = LdapString(Cow::Borrowed(s));
            Ok((&b""[..], s))
        },
    )))(i)?;
    let (i, rule_type) = opt(complete(parse_ber_tagged_implicit_g(
        2,
        |content, _hdr, _depth| {
            let s = std::str::from_utf8(content).or(Err(Err::Error(LdapError::InvalidString)))?;
            let s = AttributeDescription(Cow::Borrowed(s));
            Ok((&b""[..], s))
        },
    )))(i)?;
    let (i, assertion_value) = parse_ber_tagged_implicit_g(3, |content, _hdr, _depth| {
        let s = AssertionValue(Cow::Borrowed(content));
        Ok((&b""[..], s))
    })(i)?;
    let (i, dn_attributes) = opt(complete(parse_ber_tagged_implicit_g(
        4,
        |content, hdr, depth| {
            let (rem, obj_content) = parse_ber_content(Tag::Boolean)(content, &hdr, depth)?;
            let b = obj_content.as_bool()?;
            Ok((rem, b))
        },
    )))(i)
    .map_err(Err::convert)?;
    let assertion = MatchingRuleAssertion {
        matching_rule,
        rule_type,
        assertion_value,
        dn_attributes,
    };
    Ok((i, assertion))
}
