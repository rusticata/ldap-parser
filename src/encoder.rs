// In the following, each `ToDer` impl acutally encodes into the LDAP BER format,
// since there is no ToBer to implement at the time of writing,
// noting each time we deviate using #LDAPBER

// Note: if you're looking (for some reason) for an implementation that
// encodes messages into actual DER (violating the LDAP standard), see
// commit ref c28674746e9cd28f6ad2f448e5e377ed478b2d97
use crate::filter::*;
use crate::ldap::*;
use asn1_rs::DynTagged;
use asn1_rs::Integer;
use asn1_rs::Length;
use asn1_rs::OctetString;
use asn1_rs::Tagged;
use asn1_rs::{Class, Header, Tag, ToDer};

// helper function to calculate the size of an explit tag plus the contained value
pub fn size_with_header(content_len: usize) -> asn1_rs::Result<usize> {
    if content_len <= 127 {
        Ok(2 + content_len)
    } else {
        let n = Length::Definite(content_len).to_der_len()?;
        Ok(1 + n + content_len)
    }
}

/// helper function for iter().try_fold() on a Vec/slice of impl ToDers
fn sum_der_lens<T: ToDer>(acc: usize, entry: &T) -> asn1_rs::Result<usize> {
    let entry_len = entry.to_der_len()?;
    Ok(acc + entry_len)
}

pub trait ToDerContentLen: ToDer {
    const CONTENT_IS_CONSTRUCTED: bool;
    fn der_content_len(&self) -> asn1_rs::Result<usize>;

    /// Calculates the size of this ToDer as it will be written by [`Self::write_tagged`]
    fn tagged_len(&self) -> asn1_rs::Result<usize> {
        // #LDAPBER
        self.to_der_len()
    }

    /// Helper function: Write this ToDer with a specific Tag
    ///
    /// the Tag will be written as an implicit (LDAP BER rules) tag
    fn write_tagged(
        &self,
        writer: &mut dyn std::io::Write,
        class: Class,
        tag: Tag,
    ) -> asn1_rs::SerializeResult<usize> {
        let mut written = 0;
        written += self.write_tagged_header(writer, class, tag)?;
        written += self.write_der_content(writer)?;
        Ok(written)
    }

    /// Helper function: Write the Header(s) for this ToDer with a specific Tag
    ///
    /// the Tag will be implicit (LDAP BER rules) tag+
    fn write_tagged_header(
        &self,
        writer: &mut dyn std::io::Write,
        class: Class,
        tag: Tag,
    ) -> asn1_rs::SerializeResult<usize> {
        // #LDAPBER
        let header = Header::new(
            class,
            Self::CONTENT_IS_CONSTRUCTED,
            tag,
            Length::Definite(self.der_content_len()?),
        );
        header.write_der_header(writer)
    }
}

impl ToDerContentLen for OctetString<'_> {
    const CONTENT_IS_CONSTRUCTED: bool = false;

    fn der_content_len(&self) -> asn1_rs::Result<usize> {
        Ok(self.as_cow().len())
    }
}

impl ToDerContentLen for bool {
    const CONTENT_IS_CONSTRUCTED: bool = false;

    fn der_content_len(&self) -> asn1_rs::Result<usize> {
        Ok(1)
    }
}

// MessageID ::= INTEGER (0 ..  maxInt)
impl ToDerContentLen for MessageID {
    const CONTENT_IS_CONSTRUCTED: bool = false;
    fn der_content_len(&self) -> asn1_rs::Result<usize> {
        Ok(match self.0 {
            0x0000_0000..=0x0000_007f => 1,
            0x0000_0080..=0x0000_7fff => 2,
            0x0000_8000..=0x007f_ffff => 3,
            0x0080_0000..=0x7fff_ffff => 4,
            0x8000_0000..=0xffff_ffff => 5,
        })
    }
}
impl ToDer for MessageID {
    fn to_der_len(&self) -> asn1_rs::Result<usize> {
        // int-len can range from 1-5 bytes, so is always less than 127,
        // -> header will always have 2 bytes
        Ok(2 + self.der_content_len()?)
    }

    fn write_der_header(&self, writer: &mut dyn std::io::Write) -> asn1_rs::SerializeResult<usize> {
        let header = Header::new(
            Class::Universal,
            false,
            Self::TAG,
            Length::Definite(self.der_content_len()?),
        );
        header.write_der_header(writer)
    }

    fn write_der_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> asn1_rs::SerializeResult<usize> {
        let int = Integer::from_u32(self.0);
        int.write_der_content(writer)
    }
}

impl Tagged for MessageID {
    const TAG: Tag = Tag::Integer;
}

macro_rules! str_newtype_to_der {
    ( $x:ident ) => {
        impl ToDer for $x<'_> {
            fn to_der_len(&self) -> asn1_rs::Result<usize> {
                OctetString::new(self.0.as_bytes()).to_der_len()
            }

            fn write_der_header(
                &self,
                writer: &mut dyn std::io::Write,
            ) -> asn1_rs::SerializeResult<usize> {
                OctetString::new(self.0.as_bytes()).write_der_header(writer)
            }

            fn write_der_content(
                &self,
                writer: &mut dyn std::io::Write,
            ) -> asn1_rs::SerializeResult<usize> {
                OctetString::new(self.0.as_bytes()).write_der_content(writer)
            }
        }

        impl Tagged for $x<'_> {
            const TAG: Tag = Tag::OctetString;
        }

        impl ToDerContentLen for $x<'_> {
            const CONTENT_IS_CONSTRUCTED: bool = false;
            fn der_content_len(&self) -> asn1_rs::Result<usize> {
                Ok(self.0.len())
            }
        }
    };
}

macro_rules! u8_newtype_to_der_octect {
    ( $x:ident ) => {
        impl ToDer for $x<'_> {
            fn to_der_len(&self) -> asn1_rs::Result<usize> {
                OctetString::new(&self.0).to_der_len()
            }

            fn write_der_header(
                &self,
                writer: &mut dyn std::io::Write,
            ) -> asn1_rs::SerializeResult<usize> {
                OctetString::new(&self.0).write_der_header(writer)
            }

            fn write_der_content(
                &self,
                writer: &mut dyn std::io::Write,
            ) -> asn1_rs::SerializeResult<usize> {
                OctetString::new(&self.0).write_der_content(writer)
            }
        }

        impl Tagged for $x<'_> {
            const TAG: Tag = Tag::OctetString;
        }

        impl ToDerContentLen for $x<'_> {
            const CONTENT_IS_CONSTRUCTED: bool = false;
            fn der_content_len(&self) -> asn1_rs::Result<usize> {
                Ok(self.0.len())
            }
        }
    };
}

macro_rules! u32_newtype_to_der_enumerated {
    ($x:ident) => {
        impl ToDerContentLen for $x {
            const CONTENT_IS_CONSTRUCTED: bool = false;
            fn der_content_len(&self) -> asn1_rs::Result<usize> {
                Ok(match self.0 {
                    0x0000_0000..=0x0000_007f => 1,
                    0x0000_0080..=0x0000_7fff => 2,
                    0x0000_8000..=0x007f_ffff => 3,
                    0x0080_0000..=0x7fff_ffff => 4,
                    0x8000_0000..=0xffff_ffff => 5,
                })
            }
        }

        impl ToDer for $x {
            fn to_der_len(&self) -> asn1_rs::Result<usize> {
                Ok(self.der_content_len()? + 2)
            }

            fn write_der_header(
                &self,
                writer: &mut dyn std::io::Write,
            ) -> asn1_rs::SerializeResult<usize> {
                let header = Header::new(
                    Class::Universal,
                    false,
                    Self::TAG,
                    Length::Definite(self.der_content_len()?),
                );
                header.write_der_header(writer)
            }

            fn write_der_content(
                &self,
                writer: &mut dyn std::io::Write,
            ) -> asn1_rs::SerializeResult<usize> {
                self.0.write_der_content(writer)
            }
        }
        impl Tagged for $x {
            const TAG: Tag = Tag::Enumerated;
        }
    };
}

// LDAPString ::= OCTET STRING -- UTF-8 encoded,
//                             -- [ISO10646] characters
str_newtype_to_der!(LdapString);

// LDAPDN ::= LDAPString -- Constrained to <distinguishedName>
//                       -- [RFC4514]
str_newtype_to_der!(LdapDN);

// RelativeLDAPDN ::= LDAPString -- Constrained to <name-component>
//                               -- [RFC4514]
str_newtype_to_der!(RelativeLdapDN);

// LDAPOID ::= OCTET STRING -- Constrained to <numericoid>
//                          -- [RFC4512]
str_newtype_to_der!(LdapOID);

// AttributeValue ::= OCTET STRING
u8_newtype_to_der_octect!(AttributeValue);

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

trait StructToDer {
    const CLASS: Class;
    const TAG: Tag;

    fn struct_content_len(&self) -> asn1_rs::Result<usize>;
    fn write_struct_der_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> asn1_rs::SerializeResult<usize>;
}

macro_rules! struct_to_der {
    ( $x:ident $(< $lt:lifetime >)? ) => {
        impl ToDer for $x$(< $lt >)? {
            fn to_der_len(&self) -> asn1_rs::Result<usize> {
                let content_len = self.struct_content_len()?;
                size_with_header(content_len)
            }

            fn write_der_header(
                &self,
                writer: &mut dyn std::io::Write,
            ) -> asn1_rs::SerializeResult<usize> {
                let header = Header::new(
                    Self::CLASS,
                    true,
                    <Self as StructToDer>::TAG,
                    Length::Definite(self.struct_content_len()?));
                header.write_der_header(writer)
            }

            fn write_der_content(
                &self,
                writer: &mut dyn std::io::Write,
            ) -> asn1_rs::SerializeResult<usize> {
                <Self as StructToDer>::write_struct_der_content(self, writer)
            }
        }

        impl Tagged for $x$(< $lt >)? {
            const TAG: Tag = <Self as StructToDer>::TAG;
        }

        impl ToDerContentLen for $x$(< $lt >)? {
            const CONTENT_IS_CONSTRUCTED: bool = true;
            fn der_content_len(&self) -> asn1_rs::Result<usize> {
                self.struct_content_len()
            }
        }
    };
}

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
u32_newtype_to_der_enumerated!(ResultCode);
impl StructToDer for LdapResult<'_> {
    const CLASS: Class = Class::Universal;
    const TAG: Tag = Tag::Sequence;

    fn struct_content_len(&self) -> asn1_rs::Result<usize> {
        let code_len = self.result_code.to_der_len()?;
        let dn_len = self.matched_dn.to_der_len()?;
        let msg_len = self.diagnostic_message.to_der_len()?;
        //TODO: referral
        Ok(code_len + dn_len + msg_len)
    }

    fn write_struct_der_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> asn1_rs::SerializeResult<usize> {
        let mut written = 0;
        written += self.result_code.write_der(writer)?;
        written += self.matched_dn.write_der(writer)?;
        written += self.diagnostic_message.write_der(writer)?;
        Ok(written)
    }
}
struct_to_der!(LdapResult<'_>);

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

impl StructToDer for LdapMessage<'_> {
    const CLASS: Class = Class::Universal;
    const TAG: Tag = Tag::Sequence;

    fn struct_content_len(&self) -> asn1_rs::Result<usize> {
        let message_id_len = self.message_id.to_der_len()?;
        let protocol_op_len = self.protocol_op.to_der_len()?;
        let controls_len = if let Some(controls) = &self.controls {
            // len of all Sequences
            let controls_content_len = controls.iter().try_fold(0, sum_der_lens)?;

            // len with the SequenceOf Tag:
            size_with_header(controls_content_len)?
        } else {
            0
        };
        Ok(message_id_len + protocol_op_len + controls_len)
    }

    fn write_struct_der_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> asn1_rs::SerializeResult<usize> {
        let mut written = 0;
        written += self.message_id.write_der(writer)?;
        written += self.protocol_op.write_der(writer)?;
        if let Some(controls) = &self.controls {
            let controls_content_len = controls.iter().try_fold(0, sum_der_lens)?;
            // 'Sequence of' Header:
            let controls_header = Header::new(
                Class::ContextSpecific,
                true,
                Tag(0),
                Length::Definite(controls_content_len),
            );
            written += controls_header.write_der(writer)?;

            for control in controls {
                written += control.write_der(writer)?;
            }
        }
        Ok(written)
    }
}
struct_to_der!(LdapMessage<'_>);

impl ToDer for ProtocolOp<'_> {
    fn to_der_len(&self) -> asn1_rs::Result<usize> {
        match self {
            Self::BindRequest(bind_request) => bind_request.to_der_len(),
            Self::BindResponse(bind_response) => bind_response.to_der_len(),
            Self::SearchRequest(search_request) => search_request.to_der_len(),
            Self::SearchResultEntry(search_result_entry) => search_result_entry.to_der_len(),
            Self::SearchResultReference(ldap_strings) => ldap_strings.to_der_len(),
            Self::ModifyRequest(modify_request) => modify_request.to_der_len(),
            Self::AddRequest(add_request) => add_request.to_der_len(),
            Self::ModDnRequest(mod_dn_request) => mod_dn_request.to_der_len(),
            Self::CompareRequest(compare_request) => compare_request.to_der_len(),
            Self::ExtendedRequest(extended_request) => extended_request.to_der_len(),
            Self::ExtendedResponse(extended_response) => extended_response.to_der_len(),
            Self::IntermediateResponse(intermediate_response) => intermediate_response.to_der_len(),

            Self::UnbindRequest => Ok(2), // Null message - header with len 0 only

            Self::SearchResultDone(ldap_result)
            | Self::AddResponse(ldap_result)
            | Self::DelResponse(ldap_result)
            | Self::ModDnResponse(ldap_result)
            | Self::CompareResponse(ldap_result)
            | Self::ModifyResponse(ModifyResponse {
                result: ldap_result,
            }) => ldap_result.tagged_len(),

            Self::DelRequest(ldap_dn) => ldap_dn.tagged_len(),
            Self::AbandonRequest(message_id) => message_id.tagged_len(),
        }
    }

    fn write_der_header(&self, writer: &mut dyn std::io::Write) -> asn1_rs::SerializeResult<usize> {
        match self {
            Self::BindRequest(bind_request) => bind_request.write_der_header(writer),
            Self::BindResponse(bind_response) => bind_response.write_der_header(writer),
            Self::SearchRequest(search_request) => search_request.write_der_header(writer),
            Self::SearchResultEntry(search_result_entry) => {
                search_result_entry.write_der_header(writer)
            }
            Self::ModifyRequest(modify_request) => modify_request.write_der_header(writer),
            Self::AddRequest(add_request) => add_request.write_der_header(writer),
            Self::UnbindRequest => {
                Header::new(Class::Application, false, Tag(2), Length::Definite(0))
                    .write_der_header(writer)
            }
            Self::ModDnRequest(mod_dn_request) => mod_dn_request.write_der_header(writer),
            Self::CompareRequest(compare_request) => compare_request.write_der_header(writer),
            Self::ExtendedRequest(extended_request) => extended_request.write_der_header(writer),
            Self::ExtendedResponse(extended_response) => extended_response.write_der_header(writer),
            Self::IntermediateResponse(intermediate_response) => {
                intermediate_response.write_der_header(writer)
            }

            Self::SearchResultReference(ldap_strings) => {
                let content_len = ldap_strings.iter().try_fold(0, sum_der_lens)?;
                // 'Sequence Of' Header
                let header = Header::new(
                    Class::Application,
                    true,
                    <Self as DynTagged>::tag(self),
                    Length::Definite(content_len),
                );
                header.write_der_header(writer)
            }

            Self::SearchResultDone(ldap_result)
            | Self::AddResponse(ldap_result)
            | Self::DelResponse(ldap_result)
            | Self::ModDnResponse(ldap_result)
            | Self::CompareResponse(ldap_result)
            | Self::ModifyResponse(ModifyResponse {
                result: ldap_result,
            }) => ldap_result.write_tagged_header(
                writer,
                Class::Application,
                <Self as DynTagged>::tag(self),
            ),

            Self::AbandonRequest(message_id) => message_id.write_tagged_header(
                writer,
                Class::Application,
                <Self as DynTagged>::tag(self),
            ),

            Self::DelRequest(ldap_dn) => ldap_dn.write_tagged_header(
                writer,
                Class::Application,
                <Self as DynTagged>::tag(self),
            ),
        }
    }

    fn write_der_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> asn1_rs::SerializeResult<usize> {
        match self {
            Self::BindRequest(bind_request) => bind_request.write_der_content(writer),
            Self::BindResponse(bind_response) => bind_response.write_der_content(writer),
            Self::UnbindRequest => Ok(0),
            Self::SearchRequest(search_request) => search_request.write_der_content(writer),
            Self::SearchResultDone(ldap_result) => ldap_result.write_der_content(writer),
            Self::SearchResultReference(ldap_strings) => ldap_strings.write_der_content(writer),
            Self::ModifyRequest(modify_request) => modify_request.write_der_content(writer),
            Self::ModifyResponse(modify_response) => {
                modify_response.result.write_der_content(writer)
            }
            Self::AddRequest(add_request) => add_request.write_der_content(writer),
            Self::AddResponse(ldap_result) => ldap_result.write_der_content(writer),
            Self::DelRequest(ldap_dn) => ldap_dn.write_der_content(writer),
            Self::DelResponse(ldap_result) => ldap_result.write_der_content(writer),
            Self::ModDnRequest(mod_dn_request) => mod_dn_request.write_der_content(writer),
            Self::ModDnResponse(ldap_result) => ldap_result.write_der_content(writer),
            Self::CompareRequest(compare_request) => compare_request.write_der_content(writer),
            Self::CompareResponse(ldap_result) => ldap_result.write_der_content(writer),
            Self::AbandonRequest(message_id) => message_id.write_der_content(writer),
            Self::ExtendedRequest(extended_request) => extended_request.write_der_content(writer),
            Self::ExtendedResponse(extended_response) => {
                extended_response.write_der_content(writer)
            }
            Self::IntermediateResponse(intermediate_response) => {
                intermediate_response.write_der_content(writer)
            }

            Self::SearchResultEntry(search_result_entry) => {
                search_result_entry.write_der_content(writer)
            }
        }
    }
}

impl DynTagged for ProtocolOp<'_> {
    fn tag(&self) -> Tag {
        // reuse tag from enum definition:
        Tag(self.tag().0)
    }
}

// BindRequest ::= [APPLICATION 0] SEQUENCE {
//      version                 INTEGER (1 ..  127),
//      name                    LDAPDN,
//      authentication          AuthenticationChoice }
impl StructToDer for BindRequest<'_> {
    const CLASS: Class = Class::Application;
    const TAG: Tag = Tag(0);

    fn struct_content_len(&self) -> asn1_rs::Result<usize> {
        let ver_len = self.version.to_der_len()?;
        let name_len = self.name.to_der_len()?;
        let auth_len = self.authentication.to_der_len()?;
        Ok(ver_len + name_len + auth_len)
    }

    fn write_struct_der_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> asn1_rs::SerializeResult<usize> {
        let mut written = 0;
        written += self.version.write_der(writer)?;
        written += self.name.write_der(writer)?;
        written += self.authentication.write_der(writer)?;
        Ok(written)
    }
}
struct_to_der!(BindRequest<'_>);

// BindResponse ::= [APPLICATION 1] SEQUENCE {
//      COMPONENTS OF LDAPResult,
//      serverSaslCreds    [7] OCTET STRING OPTIONAL }
impl StructToDer for BindResponse<'_> {
    const CLASS: Class = Class::Application;
    const TAG: Tag = Tag(1);

    fn struct_content_len(&self) -> asn1_rs::Result<usize> {
        let mut result = self.result.struct_content_len()?;
        if let Some(creds) = &self.server_sasl_creds {
            let creds = OctetString::new(creds);
            result += creds.tagged_len()?;
        }
        Ok(result)
    }

    fn write_struct_der_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> asn1_rs::SerializeResult<usize> {
        let mut written = 0;
        written += self.result.write_der_content(writer)?;
        if let Some(creds) = &self.server_sasl_creds {
            let creds = OctetString::new(creds);
            written += creds.write_tagged(writer, Class::ContextSpecific, Tag(7))?;
        }
        Ok(written)
    }
}
struct_to_der!(BindResponse<'_>);

// UnbindRequest ::= [APPLICATION 2] NULL
// handled in ToDer for ProtocolOp

//  SubstringFilter ::= SEQUENCE {
//      type           AttributeDescription,
//      substrings     SEQUENCE SIZE (1..MAX) OF substring CHOICE {
//           initial [0] AssertionValue,  -- can occur at most once
//           any     [1] AssertionValue,
//           final   [2] AssertionValue } -- can occur at most once
//  }
//  AssertionValue ::= OCTET STRING
u8_newtype_to_der_octect!(AssertionValue);
impl Substring<'_> {
    #[inline]
    fn get_assertion_val(&self) -> &AssertionValue<'_> {
        match self {
            Self::Initial(av) | Self::Any(av) | Self::Final(av) => av,
        }
    }
    #[inline]
    fn der_content_len(&self) -> asn1_rs::Result<usize> {
        self.get_assertion_val().to_der_len()
    }
}
impl ToDer for Substring<'_> {
    fn to_der_len(&self) -> asn1_rs::Result<usize> {
        size_with_header(self.der_content_len()?)
    }

    fn write_der_header(&self, writer: &mut dyn std::io::Write) -> asn1_rs::SerializeResult<usize> {
        let header = Header::new(
            Class::ContextSpecific,
            true,
            self.tag(),
            Length::Definite(self.der_content_len()?),
        );
        header.write_der_header(writer)
    }

    fn write_der_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> asn1_rs::SerializeResult<usize> {
        self.get_assertion_val().write_der(writer)
    }
}
impl DynTagged for Substring<'_> {
    fn tag(&self) -> Tag {
        match self {
            Self::Initial(_) => Tag(0),
            Self::Any(_) => Tag(1),
            Self::Final(_) => Tag(2),
        }
    }
}

impl StructToDer for SubstringFilter<'_> {
    const CLASS: Class = Class::Universal;
    const TAG: Tag = Tag::Sequence;

    fn struct_content_len(&self) -> asn1_rs::Result<usize> {
        let mut result = self.filter_type.to_der_len()?;
        result += self.substrings.iter().try_fold(0, sum_der_lens)?;
        Ok(result)
    }

    fn write_struct_der_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> asn1_rs::SerializeResult<usize> {
        let mut written = 0;
        written += self.filter_type.write_der(writer)?;
        for sub in &self.substrings {
            written += sub.write_der(writer)?;
        }
        Ok(written)
    }
}
struct_to_der!(SubstringFilter<'_>);

// MatchingRuleAssertion ::= SEQUENCE {
//    matchingRule    [1] MatchingRuleId OPTIONAL,
//    type            [2] AttributeDescription OPTIONAL,
//    matchValue      [3] AssertionValue,
//    dnAttributes    [4] BOOLEAN DEFAULT FALSE }

str_newtype_to_der!(AttributeDescription);
impl StructToDer for MatchingRuleAssertion<'_> {
    const CLASS: Class = Class::Universal;
    const TAG: Tag = Tag::Sequence;

    fn struct_content_len(&self) -> asn1_rs::Result<usize> {
        let mut result = 0;
        if let Some(rule) = &self.matching_rule {
            result += rule.tagged_len()?;
        }
        if let Some(ty) = &self.rule_type {
            result += ty.tagged_len()?;
        }
        result += self.assertion_value.tagged_len()?;
        if self.dn_attributes == Some(true) {
            result += true.tagged_len()?;
        }
        Ok(result)
    }

    fn write_struct_der_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> asn1_rs::SerializeResult<usize> {
        let mut written = 0;
        if let Some(rule) = &self.matching_rule {
            written += rule.write_tagged(writer, Class::ContextSpecific, Tag(1))?;
        }
        if let Some(ty) = &self.rule_type {
            written += ty.write_tagged(writer, Class::ContextSpecific, Tag(2))?;
        }
        written += self
            .assertion_value
            .write_tagged(writer, Class::ContextSpecific, Tag(3))?;
        if self.dn_attributes == Some(true) {
            written += true.write_tagged(writer, Class::ContextSpecific, Tag(4))?;
        }
        Ok(written)
    }
}
struct_to_der!(MatchingRuleAssertion<'_>);

//  Filter ::= CHOICE {
//              and             [0] SET SIZE (1..MAX) OF filter Filter,
//              or              [1] SET SIZE (1..MAX) OF filter Filter,
//              not             [2] Filter,
//              equalityMatch   [3] AttributeValueAssertion,
//              substrings      [4] SubstringFilter,
//              greaterOrEqual  [5] AttributeValueAssertion,
//              lessOrEqual     [6] AttributeValueAssertion,
//              present         [7] AttributeDescription,
//              approxMatch     [8] AttributeValueAssertion,
//              extensibleMatch [9] MatchingRuleAssertion,
//              ...  }
u32_newtype_to_der_enumerated!(SearchScope);
u32_newtype_to_der_enumerated!(DerefAliases);
impl ToDerContentLen for Filter<'_> {
    const CONTENT_IS_CONSTRUCTED: bool = true;

    fn der_content_len(&self) -> asn1_rs::Result<usize> {
        // #LDAPBER

        Ok(match self {
            Self::And(filters) | Self::Or(filters) => filters.iter().try_fold(0, sum_der_lens)?,
            Self::Not(filter) => filter.to_der_len()?,
            Self::Substrings(substring_filter) => substring_filter.struct_content_len()?, // #LDAPBER
            Self::EqualityMatch(ava)
            | Self::GreaterOrEqual(ava)
            | Self::LessOrEqual(ava)
            | Self::ApproxMatch(ava) => ava.struct_content_len()?, // #LDAPBER
            //Self::Present(ldap_string) => ldap_string.to_der_len()?, // #ACTUALDER
            Self::Present(ldap_string) => ldap_string.0.len(), // #LDAPBER -> implicit tagging
            Self::ExtensibleMatch(mra) => mra.struct_content_len()?, // #LDAPBER
        })
    }
}
impl ToDer for Filter<'_> {
    fn to_der_len(&self) -> asn1_rs::Result<usize> {
        size_with_header(self.der_content_len()?)
    }

    fn write_der_header(&self, writer: &mut dyn std::io::Write) -> asn1_rs::SerializeResult<usize> {
        let header = Header::new(
            Class::ContextSpecific,
            true,
            self.tag(),
            Length::Definite(self.der_content_len()?),
        );
        header.write_der_header(writer)
    }

    fn write_der_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> asn1_rs::SerializeResult<usize> {
        match self {
            Self::And(filters) | Self::Or(filters) => {
                //The SET has a Tag, plus each contained element
                let mut written = 0;
                for filter in filters {
                    written += filter.write_der(writer)?;
                }
                Ok(written)
            }
            Self::Not(filter) => filter.write_der(writer), //explicit Tag in both DER and LDAPDER
            Self::Substrings(substring_filter) => {
                let mut written = 0;
                // #LDAPBER
                written += substring_filter.write_der_content(writer)?;
                Ok(written)
            }
            Self::EqualityMatch(ava)
            | Self::GreaterOrEqual(ava)
            | Self::LessOrEqual(ava)
            | Self::ApproxMatch(ava) => {
                let mut written = 0;
                // #LDAPBER
                written += ava.write_der_content(writer)?;
                Ok(written)
            }
            Self::Present(ldap_string) => {
                let mut written = 0;
                // #LDAPBER
                written += ldap_string.write_der_content(writer)?;
                Ok(written)
            }
            Self::ExtensibleMatch(mra) => {
                let mut written = 0;
                // #LDAPBER
                written += mra.write_der_content(writer)?;
                Ok(written)
            }
        }
    }
}
impl DynTagged for Filter<'_> {
    fn tag(&self) -> Tag {
        Tag(match self {
            Self::And(_) => 0,
            Self::Or(_) => 1,
            Self::Not(_) => 2,
            Self::EqualityMatch(_) => 3,
            Self::Substrings(_) => 4,
            Self::GreaterOrEqual(_) => 5,
            Self::LessOrEqual(_) => 6,
            Self::Present(_) => 7,
            Self::ApproxMatch(_) => 8,
            Self::ExtensibleMatch(_) => 9,
        })
    }
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

impl StructToDer for SearchRequest<'_> {
    const CLASS: Class = Class::Application;
    const TAG: Tag = Tag(3);

    fn struct_content_len(&self) -> asn1_rs::Result<usize> {
        let mut result = self.base_object.to_der_len()?;
        result += self.scope.to_der_len()?;
        result += self.deref_aliases.to_der_len()?;
        result += self.size_limit.to_der_len()?;
        result += self.time_limit.to_der_len()?;
        result += self.types_only.to_der_len()?;
        result += self.filter.to_der_len()?;
        let attr_content_len = self.attributes.iter().try_fold(0, sum_der_lens)?;
        result += size_with_header(attr_content_len)?;
        Ok(result)
    }

    fn write_struct_der_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> asn1_rs::SerializeResult<usize> {
        let mut written = 0;
        written += self.base_object.write_der(writer)?;
        written += self.scope.write_der(writer)?;
        written += self.deref_aliases.write_der(writer)?;
        written += self.size_limit.write_der(writer)?;
        written += self.time_limit.write_der(writer)?;
        written += self.types_only.write_der(writer)?;
        written += self.filter.write_der(writer)?;

        let attr_content_len = self.attributes.iter().try_fold(0, sum_der_lens)?;
        let attr_seq_head = Header::new(
            Class::Universal,
            true,
            Tag::Sequence,
            Length::Definite(attr_content_len),
        );
        written += attr_seq_head.write_der_header(writer)?;
        for attr in &self.attributes {
            written += attr.write_der(writer)?;
        }
        Ok(written)
    }
}
struct_to_der!(SearchRequest<'_>);

// SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
//     objectName      LDAPDN,
//     attributes      PartialAttributeList }
impl StructToDer for SearchResultEntry<'_> {
    const CLASS: Class = Class::Application;
    const TAG: Tag = Tag(4);

    fn struct_content_len(&self) -> asn1_rs::Result<usize> {
        let name_len = self.object_name.to_der_len()?;
        let attr_content_len = self.attributes.iter().try_fold(0, sum_der_lens)?;
        let attr_len = size_with_header(attr_content_len)?;
        Ok(name_len + attr_len)
    }

    fn write_struct_der_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> asn1_rs::SerializeResult<usize> {
        let mut written = 0;
        written += self.object_name.write_der(writer)?;

        let attr_content_len = self.attributes.iter().try_fold(0, sum_der_lens)?;
        let attr_seq_head = Header::new(
            Class::Universal,
            true,
            Tag::Sequence,
            Length::Definite(attr_content_len),
        );
        written += attr_seq_head.write_der_header(writer)?;
        for attr in &self.attributes {
            written += attr.write_der(writer)?;
        }

        Ok(written)
    }
}
struct_to_der!(SearchResultEntry<'_>);

// SearchResultDone ::= [APPLICATION 5] LDAPResult
// handled in ProtocolOp + LdapResult

// ModifyRequest ::= [APPLICATION 6] SEQUENCE {
//     object          LDAPDN,
//     changes         SEQUENCE OF change SEQUENCE {
//          operation       ENUMERATED {
//               add     (0),
//               delete  (1),
//               replace (2),
//               ...  },
//          modification    PartialAttribute } }
impl StructToDer for ModifyRequest<'_> {
    const CLASS: Class = Class::Application;
    const TAG: Tag = Tag(6);

    fn struct_content_len(&self) -> asn1_rs::Result<usize> {
        let object_len = self.object.to_der_len()?;

        let changes_content_len = self.changes.iter().try_fold(0, sum_der_lens)?;
        let changes_len = size_with_header(changes_content_len)?;
        Ok(object_len + changes_len)
    }

    fn write_struct_der_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> asn1_rs::SerializeResult<usize> {
        let mut written = 0;
        written += self.object.write_der(writer)?;

        let changes_content_len = self.changes.iter().try_fold(0, sum_der_lens)?;
        let changes_header = Header::new(
            Class::Universal,
            true,
            Tag::Sequence,
            Length::Definite(changes_content_len),
        );
        written += changes_header.write_der_header(writer)?;
        for change in &self.changes {
            written += change.write_der(writer)?;
        }
        Ok(written)
    }
}
struct_to_der!(ModifyRequest<'_>);

// ModifyResponse ::= [APPLICATION 7] LDAPResult
// handled in ProtocolOp + LdapResult

// AddRequest ::= [APPLICATION 8] SEQUENCE {
//     entry           LDAPDN,
//     attributes      AttributeList }
impl StructToDer for AddRequest<'_> {
    const CLASS: Class = Class::Application;
    const TAG: Tag = Tag(8);

    fn struct_content_len(&self) -> asn1_rs::Result<usize> {
        let entry_len = self.entry.to_der_len()?;
        let attrs_content_len = self.attributes.iter().try_fold(0, sum_der_lens)?;
        let attrs_len = size_with_header(attrs_content_len)?;
        Ok(entry_len + attrs_len)
    }

    fn write_struct_der_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> asn1_rs::SerializeResult<usize> {
        let mut written = 0;
        written += self.entry.write_der(writer)?;

        let attrs_content_len = self.attributes.iter().try_fold(0, sum_der_lens)?;
        let attrs_header = Header::new(
            Class::Universal,
            true,
            Tag::Sequence,
            Length::Definite(attrs_content_len),
        );
        written += attrs_header.write_der_header(writer)?;
        for attr in &self.attributes {
            written += attr.write_der(writer)?;
        }
        Ok(written)
    }
}
struct_to_der!(AddRequest<'_>);

// AddResponse ::= [APPLICATION 9] LDAPResult
// handled in ProtocolOp + LdapResult

// DelRequest ::= [APPLICATION 10] LDAPDN
// handled in ProtocolOp + LdapDn

// DelResponse ::= [APPLICATION 11] LDAPResult
// handled in ProtocolOp + LdapResult

// ModifyDNRequest ::= [APPLICATION 12] SEQUENCE {
//     entry           LDAPDN,
//     newrdn          RelativeLDAPDN,
//     deleteoldrdn    BOOLEAN,
//     newSuperior     [0] LDAPDN OPTIONAL }
impl StructToDer for ModDnRequest<'_> {
    const CLASS: Class = Class::Application;
    const TAG: Tag = Tag(12);

    fn struct_content_len(&self) -> asn1_rs::Result<usize> {
        let mut result = self.entry.to_der_len()?;
        result += self.newrdn.to_der_len()?;
        result += self.deleteoldrdn.to_der_len()?;
        if let Some(newsup) = &self.newsuperior {
            result += newsup.tagged_len()?;
        }
        Ok(result)
    }

    fn write_struct_der_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> asn1_rs::SerializeResult<usize> {
        let mut written = 0;
        written += self.entry.write_der(writer)?;
        written += self.newrdn.write_der(writer)?;
        written += self.deleteoldrdn.write_der(writer)?;
        if let Some(newsup) = &self.newsuperior {
            written += newsup.write_tagged(writer, Class::ContextSpecific, Tag(0))?;
        }
        Ok(written)
    }
}
struct_to_der!(ModDnRequest<'_>);

// ModifyDNResponse ::= [APPLICATION 13] LDAPResult
// handled in ProtocolOp + LdapResult

// CompareRequest ::= [APPLICATION 14] SEQUENCE {
//     entry           LDAPDN,
//     ava             AttributeValueAssertion }

// AttributeValueAssertion ::= SEQUENCE {
//      attributeDesc   AttributeDescription,
//      assertionValue  AssertionValue }

// AssertionValue ::= OCTET STRING
impl StructToDer for AttributeValueAssertion<'_> {
    const CLASS: Class = Class::Universal;
    const TAG: Tag = Tag::Sequence;

    fn struct_content_len(&self) -> asn1_rs::Result<usize> {
        let mut result = self.attribute_desc.to_der_len()?;
        result += OctetString::new(&self.assertion_value).to_der_len()?;
        Ok(result)
    }

    fn write_struct_der_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> asn1_rs::SerializeResult<usize> {
        let mut written = 0;
        written += self.attribute_desc.write_der(writer)?;
        written += OctetString::new(&self.assertion_value).write_der(writer)?;
        Ok(written)
    }
}
struct_to_der!(AttributeValueAssertion<'_>);

impl StructToDer for CompareRequest<'_> {
    const CLASS: Class = Class::Application;
    const TAG: Tag = Tag(14);

    fn struct_content_len(&self) -> asn1_rs::Result<usize> {
        let mut result = self.entry.to_der_len()?;
        result += self.ava.to_der_len()?;
        Ok(result)
    }

    fn write_struct_der_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> asn1_rs::SerializeResult<usize> {
        let mut written = 0;
        written += self.entry.write_der(writer)?;
        written += self.ava.write_der(writer)?;
        Ok(written)
    }
}
struct_to_der!(CompareRequest<'_>);

// CompareResponse ::= [APPLICATION 15] LDAPResult
// handled in ProtocolOp + LdapResult

// AbandonRequest ::= [APPLICATION 16] MessageID
// handled in ProtocolOp + MessageID

// SearchResultReference ::= [APPLICATION 19] SEQUENCE
//                                   SIZE (1..MAX) OF uri URI
// handled in ProtocolOp

// ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
//     requestName      [0] LDAPOID,
//     requestValue     [1] OCTET STRING OPTIONAL }
impl StructToDer for ExtendedRequest<'_> {
    const CLASS: Class = Class::Application;
    const TAG: Tag = Tag(23);

    fn struct_content_len(&self) -> asn1_rs::Result<usize> {
        let mut result = self.request_name.tagged_len()?;
        if let Some(val) = &self.request_value {
            result += OctetString::new(val).tagged_len()?;
        }
        Ok(result)
    }

    fn write_struct_der_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> asn1_rs::SerializeResult<usize> {
        let mut written = 0;

        written += self
            .request_name
            .write_tagged(writer, Class::ContextSpecific, Tag(0))?;

        if let Some(val) = &self.request_value {
            written +=
                OctetString::new(val).write_tagged(writer, Class::ContextSpecific, Tag(1))?;
        }
        Ok(written)
    }
}
struct_to_der!(ExtendedRequest<'_>);

// ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
//     COMPONENTS OF LDAPResult,
//     responseName     [10] LDAPOID OPTIONAL,
//     responseValue    [11] OCTET STRING OPTIONAL }
impl StructToDer for ExtendedResponse<'_> {
    const CLASS: Class = Class::Application;
    const TAG: Tag = Tag(24);

    fn struct_content_len(&self) -> asn1_rs::Result<usize> {
        let mut result = self.result.struct_content_len()?;
        if let Some(name) = &self.response_name {
            result += name.tagged_len()?;
        }
        if let Some(val) = &self.response_value {
            result += OctetString::new(val).tagged_len()?;
        }
        Ok(result)
    }

    fn write_struct_der_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> asn1_rs::SerializeResult<usize> {
        let mut written = 0;

        written += self.result.write_der_content(writer)?;

        if let Some(name) = &self.response_name {
            written += name.write_tagged(writer, Class::ContextSpecific, Tag(10))?;
        }

        if let Some(val) = &self.response_value {
            let val = OctetString::new(val);
            written += val.write_tagged(writer, Class::ContextSpecific, Tag(11))?;
        }
        Ok(written)
    }
}
struct_to_der!(ExtendedResponse<'_>);

// IntermediateResponse ::= [APPLICATION 25] SEQUENCE {
//      responseName     [0] LDAPOID OPTIONAL,
//      responseValue    [1] OCTET STRING OPTIONAL }
impl StructToDer for IntermediateResponse<'_> {
    const CLASS: Class = Class::Application;
    const TAG: Tag = Tag(25);

    fn struct_content_len(&self) -> asn1_rs::Result<usize> {
        let mut result = 0;
        if let Some(name) = &self.response_name {
            result += name.tagged_len()?;
        }
        if let Some(val) = &self.response_value {
            result += OctetString::new(val).tagged_len()?;
        }
        Ok(result)
    }

    fn write_struct_der_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> asn1_rs::SerializeResult<usize> {
        let mut written = 0;

        if let Some(name) = &self.response_name {
            written += name.write_tagged(writer, Class::ContextSpecific, Tag(10))?;
        }

        if let Some(val) = &self.response_value {
            let val = OctetString::new(val);
            written += val.write_tagged(writer, Class::ContextSpecific, Tag(11))?;
        }
        Ok(written)
    }
}
struct_to_der!(IntermediateResponse<'_>);

// AuthenticationChoice ::= CHOICE {
//      simple                  [0] OCTET STRING,
//                              -- 1 and 2 reserved
//      sasl                    [3] SaslCredentials,
//      ...  }
impl ToDer for AuthenticationChoice<'_> {
    fn to_der_len(&self) -> asn1_rs::Result<usize> {
        match self {
            Self::Simple(cow) => OctetString::new(cow).tagged_len(),
            Self::Sasl(cred) => cred.tagged_len(),
        }
    }

    fn write_der_header(&self, writer: &mut dyn std::io::Write) -> asn1_rs::SerializeResult<usize> {
        match self {
            Self::Simple(cow) => {
                OctetString::new(cow).write_tagged_header(writer, Class::ContextSpecific, Tag(0))
            }
            Self::Sasl(cred) => cred.write_tagged_header(writer, Class::ContextSpecific, Tag(3)),
        }
    }

    fn write_der_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> asn1_rs::SerializeResult<usize> {
        Ok(match self {
            Self::Simple(cow) => {
                writer.write_all(cow)?;
                cow.len()
            }
            Self::Sasl(sasl) => sasl.write_der_content(writer)?,
        })
    }
}

impl DynTagged for AuthenticationChoice<'_> {
    fn tag(&self) -> Tag {
        match self {
            Self::Simple(_) => Tag(0),
            Self::Sasl(_) => Tag(3),
        }
    }
}

// SaslCredentials ::= SEQUENCE {
//      mechanism               LDAPString,
//      credentials             OCTET STRING OPTIONAL }
impl StructToDer for SaslCredentials<'_> {
    const CLASS: Class = Class::Universal;
    const TAG: Tag = Tag::Sequence;

    fn struct_content_len(&self) -> asn1_rs::Result<usize> {
        let mut result = self.mechanism.to_der_len()?;
        if let Some(cred) = &self.credentials {
            let cred_content_length = cred.len();
            result += if cred_content_length < 127 {
                2 + cred_content_length
            } else {
                let n = Length::Definite(cred_content_length).to_der_len()?;
                1 + n + cred_content_length
            };
        }
        Ok(result)
    }

    fn write_struct_der_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> asn1_rs::SerializeResult<usize> {
        let mut written = 0;
        written += self.mechanism.write_der(writer)?;
        if let Some(cred) = &self.credentials {
            written += OctetString::new(cred).write_der(writer)?;
        }
        Ok(written)
    }
}
struct_to_der!(SaslCredentials<'_>);

// AttributeSelection ::= SEQUENCE OF selector LDAPString
//      -- The LDAPString is constrained to
//      -- <attributeSelector> in Section 4.5.1.8

// PartialAttributeList ::= SEQUENCE OF partialAttribute PartialAttribute

// AttributeList ::= SEQUENCE OF attribute Attribute

// PartialAttribute ::= SEQUENCE {
//      type       AttributeDescription,
//      vals       SET OF value AttributeValue }

// Attribute ::= PartialAttribute(WITH COMPONENTS {
//      ...,
//      vals (SIZE(1..MAX))})

impl StructToDer for Attribute<'_> {
    const CLASS: Class = Class::Universal;
    const TAG: Tag = Tag::Sequence;

    fn struct_content_len(&self) -> asn1_rs::Result<usize> {
        let mut result = self.attr_type.to_der_len()?;
        let vals_len = self.attr_vals.iter().try_fold(0, sum_der_lens)?;
        result += if vals_len < 127 {
            2 + vals_len
        } else {
            let n = Length::Definite(vals_len).to_der_len()?;
            1 + n + vals_len
        };
        Ok(result)
    }

    fn write_struct_der_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> asn1_rs::SerializeResult<usize> {
        let mut written = 0;
        written += self.attr_type.write_der(writer)?;

        let vals_len = self.attr_vals.iter().try_fold(0, sum_der_lens)?;
        let vals_header = Header::new(Class::Universal, true, Tag::Set, Length::Definite(vals_len));
        written += vals_header.write_der_header(writer)?;
        for val in &self.attr_vals {
            written += val.write_der(writer)?;
        }
        Ok(written)
    }
}
struct_to_der!(Attribute<'_>);

impl StructToDer for PartialAttribute<'_> {
    const CLASS: Class = Class::Universal;
    const TAG: Tag = Tag::Sequence;

    fn struct_content_len(&self) -> asn1_rs::Result<usize> {
        let mut result = self.attr_type.to_der_len()?;
        let vals_len = self.attr_vals.iter().try_fold(0, sum_der_lens)?;
        result += if vals_len < 127 {
            2 + vals_len
        } else {
            let n = Length::Definite(vals_len).to_der_len()?;
            1 + n + vals_len
        };
        Ok(result)
    }

    fn write_struct_der_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> asn1_rs::SerializeResult<usize> {
        let mut written = 0;
        written += self.attr_type.write_der(writer)?;

        let vals_len = self.attr_vals.iter().try_fold(0, sum_der_lens)?;
        let vals_header = Header::new(Class::Universal, true, Tag::Set, Length::Definite(vals_len));
        written += vals_header.write_der_header(writer)?;
        for val in &self.attr_vals {
            written += val.write_der(writer)?;
        }
        Ok(written)
    }
}
struct_to_der!(PartialAttribute<'_>);

// change SEQUENCE {
//          operation       ENUMERATED {
//               add     (0),
//               delete  (1),
//               replace (2),
//               ...  },
//          modification    PartialAttribute }
u32_newtype_to_der_enumerated!(Operation);
impl StructToDer for Change<'_> {
    const CLASS: Class = Class::Universal;
    const TAG: Tag = Tag::Sequence;

    fn struct_content_len(&self) -> asn1_rs::Result<usize> {
        let mut result = self.operation.to_der_len()?;
        result += self.modification.to_der_len()?;
        Ok(result)
    }

    fn write_struct_der_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> asn1_rs::SerializeResult<usize> {
        let mut written = 0;
        written += self.operation.write_der(writer)?;
        written += self.modification.write_der(writer)?;
        Ok(written)
    }
}
struct_to_der!(Change<'_>);

// Control ::= SEQUENCE {
//     controlType             LDAPOID,
//     criticality             BOOLEAN DEFAULT FALSE,
//     controlValue            OCTET STRING OPTIONAL }
impl StructToDer for Control<'_> {
    const CLASS: Class = Class::Universal;
    const TAG: Tag = Tag::Sequence;

    fn struct_content_len(&self) -> asn1_rs::Result<usize> {
        let mut result = self.control_type.to_der_len()?;
        if self.criticality {
            // only include crit if it is the non-default (true) value
            result += self.criticality.to_der_len()?;
        }
        if let Some(val) = &self.control_value {
            result += OctetString::new(val).to_der_len()?;
        }
        Ok(result)
    }

    fn write_struct_der_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> asn1_rs::SerializeResult<usize> {
        let mut written = 0;
        written += self.control_type.write_der(writer)?;
        if self.criticality {
            // only include crit if it is the non-default (true) value
            written += self.criticality.write_der(writer)?;
        }
        if let Some(val) = &self.control_value {
            written += OctetString::new(val).write_der(writer)?;
        }
        Ok(written)
    }
}

struct_to_der!(Control<'_>);

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
    use std::borrow::Cow;

    use super::*;
    use asn1_rs::FromBer;

    #[test]
    fn test_encode_bind_request() {
        let data = BindRequest {
            version: 3,
            name: LdapDN(Cow::Borrowed("xxxxxxxxxxx@xx.xxx.xxxxx.net")),
            authentication: AuthenticationChoice::Simple(Cow::Borrowed(b"passwor8d1")),
        };

        let encoded = data.to_der_vec().expect("encoding failed");
        //
        eprintln!("{:x?}", &encoded);
        //
        let (rem, decoded) = BindRequest::from_ber(&encoded).expect("parsing failed");
        //
        // dbg!(&decoded);
        //
        assert!(rem.is_empty());
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encode_bind_request_sasl() {
        let data = BindRequest {
            version: 3,
            name: LdapDN(Cow::Borrowed("")),
            authentication: AuthenticationChoice::Sasl(SaslCredentials {
                mechanism: LdapString(Cow::Borrowed("GSS_SPNEGO")),
                credentials: None,
            }),
        };

        let encoded = data.to_der_vec().expect("encoding failed");
        //
        eprintln!("{:x?}", &encoded);
        //
        let (rem, decoded) = BindRequest::from_ber(&encoded).expect("parsing failed");
        //
        // dbg!(&decoded);
        //
        assert!(rem.is_empty());
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encode_bind_response_minimal() {
        let data = BindResponse {
            result: LdapResult {
                result_code: ResultCode::Success,
                matched_dn: LdapDN(Cow::Borrowed(&"")),
                diagnostic_message: LdapString(Cow::Borrowed(&"")),
            },
            server_sasl_creds: None,
        };

        let encoded = data.to_der_vec().expect("encoding failed");
        //
        // eprintln!("{:x?}", &encoded);
        //
        let (rem, decoded) = BindResponse::from_ber(&encoded).expect("parsing failed");
        //
        // dbg!(&decoded);
        //
        assert!(rem.is_empty());
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encode_bind_response_sasl() {
        let data = BindResponse {
            result: LdapResult {
                result_code: ResultCode::Success,
                matched_dn: LdapDN(Cow::Borrowed(&"")),
                diagnostic_message: LdapString(Cow::Borrowed(&"")),
            },
            server_sasl_creds: Some(Cow::Borrowed(b"creds")),
        };

        let encoded = data.to_der_vec().expect("encoding failed");
        //
        // eprintln!("{:x?}", &encoded);
        //
        let (rem, decoded) = BindResponse::from_ber(&encoded).expect("parsing failed");
        //
        // dbg!(&decoded);
        //
        assert!(rem.is_empty());
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encode_unbind_request() {
        let data = ProtocolOp::UnbindRequest;

        let encoded = data.to_der_vec().expect("encoding failed");
        //
        // eprintln!("{:x?}", &encoded);
        //

        assert_eq!(&encoded, &[0x42, 0x00]);
    }

    #[test]
    fn test_encode_search_request() {
        let data = SearchRequest {
            base_object: LdapDN(Cow::Borrowed("DC=xx,DC=xxx,DC=xxxxx,DC=net")),
            scope: SearchScope::WholeSubtree,
            deref_aliases: DerefAliases::DerefAlways,
            size_limit: 0x0,
            time_limit: 0x0,
            types_only: false,
            filter: Filter::And(vec![
                Filter::Present(LdapString(Cow::Borrowed("objectclass"))),
                Filter::EqualityMatch(AttributeValueAssertion {
                    attribute_desc: LdapString(Cow::Borrowed("sAMAccountName")),
                    assertion_value: Cow::Borrowed(b"xxxxxxxx"),
                }),
            ]),
            attributes: vec![LdapString(Cow::Borrowed("sAMAccountName"))],
        };

        let encoded = data.to_der_vec().expect("encoding failed");
        //
        // eprintln!("{:x?}", &encoded);
        //
        let (rem, decoded) = SearchRequest::from_ber(&encoded).expect("parsing failed");
        //
        // dbg!(&decoded);
        //
        assert!(rem.is_empty());
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encode_search_result_entry() {
        let data = SearchResultEntry {
            object_name: LdapDN(Cow::Borrowed(
                "CN=xxxxxxxx,OU=Users,OU=Accounts,DC=xx,DC=xxx,DC=xxxxx,DC=net",
            )),
            attributes: vec![PartialAttribute {
                attr_type: LdapString(Cow::Borrowed("sAMAccountName")),
                attr_vals: vec![AttributeValue(Cow::Borrowed(b"xxxxxxxx"))],
            }],
        };

        let encoded = data.to_der_vec().expect("encoding failed");
        //
        eprintln!("{:x?}", &encoded);
        //
        let (rem, decoded) = SearchResultEntry::from_ber(&encoded).expect("parsing failed");
        //
        // dbg!(&decoded);
        //
        assert!(rem.is_empty());
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encode_search_result_done() {
        let data = LdapMessage {
            message_id: MessageID(0),
            protocol_op: ProtocolOp::SearchResultDone(LdapResult {
                result_code: ResultCode::Success,
                matched_dn: LdapDN(Cow::Borrowed("")),
                diagnostic_message: LdapString(Cow::Borrowed("")),
            }),
            controls: None,
        };
        let encoded = data.to_der_vec().expect("encoding failed");
        //
        // eprintln!("{:x?}", &encoded);
        //
        let (rem, decoded) = LdapMessage::from_ber(&encoded).expect("parsing failed");
        //
        // dbg!(&decoded);
        //
        assert!(rem.is_empty());
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encode_search_result_ref() {
        let data = LdapMessage {
            message_id: MessageID(0),
            protocol_op: ProtocolOp::SearchResultReference(vec![LdapString(Cow::Borrowed(
                "ldap://DomainDnsZones.rccad.net/DC=DomainDnsZones,DC=rccad,DC=net",
            ))]),
            controls: None,
        };
        let encoded = data.to_der_vec().expect("encoding failed");
        //
        // eprintln!("{:x?}", &encoded);
        //
        let (rem, decoded) = LdapMessage::from_ber(&encoded).expect("parsing failed");
        //
        // dbg!(&decoded);
        //
        assert!(rem.is_empty());
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encode_extended_req() {
        let data = ExtendedRequest {
            request_name: LdapOID(Cow::Borrowed("1.3.6.1.4.1.1466.20037")),
            request_value: None,
        };
        let encoded = data.to_der_vec().expect("encoding failed");
        //
        // eprintln!("{:x?}", &encoded);
        //
        let (rem, decoded) = ExtendedRequest::from_ber(&encoded).expect("parsing failed");
        //
        // dbg!(&decoded);
        //
        assert!(rem.is_empty());
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_parse_extended_response() {
        let data = ExtendedResponse {
            result: LdapResult {
                result_code: ResultCode::Success,
                matched_dn: LdapDN(Cow::Borrowed("")),
                diagnostic_message: LdapString(Cow::Borrowed("")),
            },
            response_name: None,
            response_value: None,
        };
        let encoded = data.to_der_vec().expect("encoding failed");
        //
        eprintln!("{:x?}", &encoded);
        //
        let (rem, decoded) = ExtendedResponse::from_ber(&encoded).expect("parsing failed");
        //
        dbg!(&decoded);
        //
        assert!(rem.is_empty());
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encode_modify_request() {
        let data = ModifyRequest {
            object: LdapDN(Cow::Borrowed("cn=username1,ou=users,dc=xxx,dc=internet")),
            changes: vec![Change {
                operation: Operation::Replace,
                modification: PartialAttribute {
                    attr_type: LdapString(Cow::Borrowed("description")),
                    attr_vals: vec![AttributeValue(Cow::Borrowed(b"test user 1"))],
                },
            }],
        };
        let encoded = data.to_der_vec().expect("encoding failed");
        //
        // eprintln!("{:x?}", &encoded);
        //
        let (rem, decoded) = ModifyRequest::from_ber(&encoded).expect("parsing failed");
        //
        // dbg!(&decoded);
        //
        assert!(rem.is_empty());
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encode_modify_response() {
        let data = LdapMessage {
            message_id: MessageID(0),
            protocol_op: ProtocolOp::ModifyResponse(ModifyResponse {
                result: LdapResult {
                    result_code: ResultCode::Success,
                    matched_dn: LdapDN(Cow::Borrowed("")),
                    diagnostic_message: LdapString(Cow::Borrowed("")),
                },
            }),
            controls: None,
        };
        let encoded = data.to_der_vec().expect("encoding failed");
        //
        // eprintln!("{:x?}", &encoded);
        //
        let (rem, decoded) = LdapMessage::from_ber(&encoded).expect("parsing failed");
        //
        // dbg!(&decoded);
        //
        assert!(rem.is_empty());
        assert_eq!(decoded, data);
    }

    // #[test]
    // fn test_parse_add_request() {
    //     const DATA: &[u8] = include_bytes!("../assets/add-request.bin");
    //     let (rem, req) = AddRequest::from_ber(DATA).expect("parsing failed");
    //     //
    //     // dbg!(&req);
    //     //
    //     assert!(rem.is_empty());
    //     assert_eq!(&req.entry.0, "cn=username1,ou=users,dc=xxx,dc=internet");
    //     assert_eq!(req.attributes.len(), 4);
    // }

    // #[test]
    // fn test_parse_add_response() {
    //     const DATA: &[u8] = include_bytes!("../assets/add-response.bin");
    //     let (rem, resp) = parse_ldap_add_response(DATA).expect("parsing failed");
    //     //
    //     // dbg!(&resp);
    //     //
    //     assert!(rem.is_empty());
    //     assert_eq!(resp.result_code, ResultCode::Success);
    // }

    // #[test]
    // fn test_parse_del_request() {
    //     const DATA: &[u8] = include_bytes!("../assets/del-request.bin");
    //     let (rem, req) = parse_ldap_del_request(DATA).expect("parsing failed");
    //     //
    //     // dbg!(&req);
    //     //
    //     assert!(rem.is_empty());
    //     assert_eq!(&req.0, "cn=username2,ou=users2,dc=xxx,dc=internet");
    // }

    // #[test]
    // fn test_parse_del_response() {
    //     const DATA: &[u8] = include_bytes!("../assets/del-response.bin");
    //     let (rem, resp) = parse_ldap_del_response(DATA).expect("parsing failed");
    //     //
    //     // dbg!(&resp);
    //     //
    //     assert!(rem.is_empty());
    //     assert_eq!(resp.result_code, ResultCode::Success);
    // }

    // #[test]
    // fn test_parse_moddn_request() {
    //     const DATA: &[u8] = include_bytes!("../assets/moddn-request.bin");
    //     let (rem, req) = ModDnRequest::from_ber(DATA).expect("parsing failed");
    //     //
    //     // dbg!(&req);
    //     //
    //     assert!(rem.is_empty());
    //     assert_eq!(&req.entry.0, "cn=username1,ou=users,dc=xxx,dc=internet");
    //     assert_eq!(&req.newrdn.0, "cn=username2");
    //     assert!(req.deleteoldrdn);
    //     assert_eq!(&req.newsuperior.unwrap().0, "ou=users,dc=xxx,dc=internet");
    // }

    // #[test]
    // fn test_parse_moddn_response() {
    //     const DATA: &[u8] = include_bytes!("../assets/moddn-response.bin");
    //     let (rem, resp) = parse_ldap_moddn_response(DATA).expect("parsing failed");
    //     //
    //     // dbg!(&resp);
    //     //
    //     assert!(rem.is_empty());
    //     assert_eq!(resp.result_code, ResultCode::Success);
    // }

    // #[test]
    // fn test_parse_compare_request() {
    //     const DATA: &[u8] = include_bytes!("../assets/compare-request.bin");
    //     let (rem, req) = CompareRequest::from_ber(DATA).expect("parsing failed");
    //     //
    //     // dbg!(&req);
    //     //
    //     assert!(rem.is_empty());
    //     assert_eq!(&req.entry.0, "cn=username2,ou=users2,dc=xxx,dc=internet");
    //     assert_eq!(&req.ava.attribute_desc.0, "cn");
    // }

    // #[test]
    // fn test_parse_compare_response() {
    //     const DATA: &[u8] = include_bytes!("../assets/compare-response.bin");
    //     let (rem, resp) = parse_ldap_compare_response(DATA).expect("parsing failed");
    //     //
    //     // dbg!(&resp);
    //     //
    //     assert!(rem.is_empty());
    //     assert_eq!(resp.result_code, ResultCode::CompareTrue);
    // }

    // #[test]
    // fn test_parse_abandon_request() {
    //     const DATA: &[u8] = &[0x30, 0x06, 0x02, 0x01, 0x06, 0x50, 0x01, 0x05];

    //     let (rem, msg) = LdapMessage::from_ber(DATA).expect("parsing failed");
    //     assert!(rem.is_empty());
    //     assert_eq!(msg.message_id, MessageID(6));
    //     assert!(matches!(
    //         msg.protocol_op,
    //         ProtocolOp::AbandonRequest(MessageID(5))
    //     ))
    // }
}
