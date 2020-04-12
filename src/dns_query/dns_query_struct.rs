use crate::dns_query::dns_query_0_header::DnsQueryHeader;
use crate::dns_query::dns_query_1_question::DnsQueryQuestion;
use crate::dns_query::dns_query_2_resource_record::DnsQueryResourceRecord;
use std::convert::{TryFrom, TryInto};
use std::option::NoneError;
use std::slice::Iter;

/// [RFC 1035](https://tools.ietf.org/html/rfc1035)
#[derive(Debug)]
pub struct DnsQuery {
  pub(crate) header: DnsQueryHeader,
  pub(crate) question: DnsQueryQuestion,
  pub(crate) answer: DnsQueryResourceRecord,
  pub(crate) authority: DnsQueryResourceRecord,
  pub(crate) additional: DnsQueryResourceRecord,
}

// example send: ?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB
// example recv: 0x00008180000100010000000003777777076578616d706c6503636f6d0000010001c00c0001000100002f1900045db8d822

impl TryFrom<&mut Iter<'_, u8>> for DnsQuery {
  type Error = NoneError;

  fn try_from(iter: &mut Iter<'_, u8>) -> Result<Self, Self::Error> {
    let header = iter.try_into()?;

    let question = iter.try_into()?;

    let answer = iter.try_into()?;

    let authority = iter.try_into()?;

    let additional = iter.try_into()?;

    Ok(Self { header, question, answer, authority, additional })
  }
}