#![feature(try_trait)]

use dns_query_parser::dns_query::dns_query_struct::DnsRequestQuery;
use std::convert::TryFrom;
use dns_query_parser::dns_query::dns_query_0_header::{DnsQueryHeader, DnsQueryHeaderFlags,
                                                      DnsQueryHeaderFlagsRcode,
                                                      DnsQueryHeaderFlagsQr,
                                                      DnsQueryHeaderFlagsOpcode,
                                                      DnsQueryHeaderFlagsAa,
                                                      DnsQueryHeaderFlagsTc,
                                                      DnsQueryHeaderFlagsRd,
                                                      DnsQueryHeaderFlagsRa,
                                                      DnsQueryHeaderFlagsAd,
                                                      DnsQueryHeaderFlagsCd};
use dns_query_parser::dns_query::dns_query_1_question::DnsQueryQuestion;
use std::borrow::Cow;
use dns_query_parser::dns_query::utils::{DnsQueryType, DnsQueryClass};
use std::num::TryFromIntError;

fn main() -> Result<(), TryFromIntError> {
  // let respond = &[b'0', b'0', b'0', b'0', b'8', b'1', b'8', b'0', b'0', b'0',
  //   b'0', b'1', b'0', b'0', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'0',
  //   b'0', b'0', b'3', b'7', b'7', b'7', b'7', b'7', b'7', b'0', b'7', b'6', b'5',
  //   b'7', b'8', b'6', b'1', b'6', b'd', b'7', b'0', b'6', b'c', b'6', b'5', b'0',
  //   b'3', b'6', b'3', b'6', b'f', b'6', b'd', b'0', b'0', b'0', b'0', b'0', b'1',
  //   b'0', b'0', b'0', b'1', b'c', b'0', b'0', b'c', b'0', b'0', b'0', b'1', b'0',
  //   b'0', b'0', b'1', b'0', b'0', b'0', b'0', b'2', b'f', b'1', b'9', b'0', b'0',
  //   b'0', b'4', b'5', b'd', b'b', b'8', b'd', b'8', b'2', b'2'];

  let query = DnsRequestQuery {
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
      q_name: Cow::from("www.example.com"),
      q_type: DnsQueryType::A,
      q_class: DnsQueryClass::In,
    },
  };

  for b in Vec::try_from(&query)?.into_iter(){
    print!("{:02x} ", b);
  }
  // AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQABAAE=
  // AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB

  Ok(())
}