use crate::dns_query::dns_query_0_header::{DnsQueryHeader,
                                           DnsQueryHeaderFlags,
                                           DnsQueryHeaderFlagsQr,
                                           DnsQueryHeaderFlagsOpcode,
                                           DnsQueryHeaderFlagsAa,
                                           DnsQueryHeaderFlagsTc,
                                           DnsQueryHeaderFlagsRd,
                                           DnsQueryHeaderFlagsRa,
                                           DnsQueryHeaderFlagsAd,
                                           DnsQueryHeaderFlagsCd,
                                           DnsQueryHeaderFlagsRcode};
use crate::dns_query::dns_query_1_question::DnsQueryQuestion;
use crate::dns_query::dns_query_2_resource_record::DnsQueryResourceRecord;
use crate::dns_query::utils::{DnsQueryType, DnsQueryClass};
use std::convert::{TryFrom, TryInto};
use std::option::NoneError;
use std::slice::Iter;
use std::num::TryFromIntError;
use std::borrow::Cow;

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

impl<'a> DnsRequestQuery<'a> {
  pub const fn from_url(cow_str: Cow<'a, str>) -> Self {
    Self {
      header: DnsQueryHeader {
        id: 0,
        flags: DnsQueryHeaderFlags {
          qr: DnsQueryHeaderFlagsQr::Query,
          op_code: DnsQueryHeaderFlagsOpcode::StdQuery,
          aa: DnsQueryHeaderFlagsAa::NonAuthAns,
          tc: DnsQueryHeaderFlagsTc::NonTrunc,
          rd: DnsQueryHeaderFlagsRd::Recur,
          ra: DnsQueryHeaderFlagsRa::NotAvailable,
          z: 0,
          ad: DnsQueryHeaderFlagsAd::NotAuthed,
          cd: DnsQueryHeaderFlagsCd::Checked,
          r_code: DnsQueryHeaderFlagsRcode::NoErr,
        },
        qd_count: 1,
        an_count: 0,
        ns_count: 0,
        ar_count: 0,
      },
      question: DnsQueryQuestion {
        q_name: cow_str,
        q_type: DnsQueryType::A,
        q_class: DnsQueryClass::In,
      },
    }
  }
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