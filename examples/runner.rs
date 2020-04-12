#![feature(try_trait)]

use dns_query_parser::dns_query::dns_query_struct::DnsQuery;
use std::convert::TryFrom;
use std::option::NoneError;

fn main() -> Result<(), NoneError> {
  let respond = &[b'0', b'0', b'0', b'0', b'8', b'1', b'8', b'0', b'0', b'0',
    b'0', b'1', b'0', b'0', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'0',
    b'0', b'0', b'3', b'7', b'7', b'7', b'7', b'7', b'7', b'0', b'7', b'6', b'5',
    b'7', b'8', b'6', b'1', b'6', b'd', b'7', b'0', b'6', b'c', b'6', b'5', b'0',
    b'3', b'6', b'3', b'6', b'f', b'6', b'd', b'0', b'0', b'0', b'0', b'0', b'1',
    b'0', b'0', b'0', b'1', b'c', b'0', b'0', b'c', b'0', b'0', b'0', b'1', b'0',
    b'0', b'0', b'1', b'0', b'0', b'0', b'0', b'2', b'f', b'1', b'9', b'0', b'0',
    b'0', b'4', b'5', b'd', b'b', b'8', b'd', b'8', b'2', b'2'];

  println!("{:?}", DnsQuery::try_from(&mut respond.iter())?);

  Ok(())
}