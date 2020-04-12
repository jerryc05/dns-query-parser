use crate::dns_query::dns_query_0_header::DnsQueryHeader;
use crate::dns_query::dns_query_1_question::DnsQueryQuestion;
use crate::dns_query::dns_query_2_resource_record::DnsQueryResourceRecord;
use std::convert::{TryFrom, TryInto};
use std::option::NoneError;
use std::slice::Iter;
use std::num::TryFromIntError;

/*
 *  Reference:
 *  - [RFC 1035](https://tools.ietf.org/html/rfc1035)
 *  - [RFC 2535](https://tools.ietf.org/html/rfc2535)
 */

#[derive(Debug)]
pub struct DnsRequestQuery<'a> {
  pub header: DnsQueryHeader,
  pub question: DnsQueryQuestion<'a>,
}

impl<'a> TryFrom<&DnsRequestQuery<'a>> for Vec<u8> {
  type Error = TryFromIntError;

  fn try_from(query: &DnsRequestQuery<'a>) -> Result<Self, Self::Error> {
    let mut result = Self::with_capacity(16);

    /* header */ {
      let header: [u8; 12] = (&query.header).into();
      result.extend(header.iter());
    }

    /* question */ {
      let question: Self = (&query.question).try_into()?;
      result.extend(question.iter());
    }

    result.shrink_to_fit();
    Ok(result)
  }
}

#[derive(Debug)]
pub struct DnsRespondQuery<'a> {
  pub header: DnsQueryHeader,
  pub question: DnsQueryQuestion<'a>,
  pub answer: DnsQueryResourceRecord,
  pub authority: DnsQueryResourceRecord,
  pub additional: DnsQueryResourceRecord,
}

impl<'a> TryFrom<&mut Iter<'_, u8>> for DnsRespondQuery<'a> {
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