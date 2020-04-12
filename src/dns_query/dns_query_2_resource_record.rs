#![allow(dead_code)]

use crate::dns_query::utils::{iter_to_str, iter_to_u16_be, iter_to_u32_be,
                              DnsQueryClass, DnsQueryType};
use crate::dns_query::utils::DnsQueryType::{A, CName};
use crate::dns_query::utils::DnsQueryClass::In;
use std::net::Ipv4Addr;
use std::convert::TryFrom;
use std::option::NoneError;
use std::slice::Iter;

/*
Answer/Authority/Additional format
  
 15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
  0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     name                      |
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     type                      |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     class                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
|                      ttl                      |
|                                               |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   rd_length                   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                    r_data                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
#[derive(Debug)]
pub struct DnsQueryResourceRecord {
  name: String,
  type_: DnsQueryType,
  class: DnsQueryClass,
  ttl: u32,
  rd_length: u16,
  r_data: DnsQueryResourceRecordRDataType,
}

#[derive(Debug)]
pub enum DnsQueryResourceRecordRDataType {
  Ipv4Addr(Ipv4Addr),
  String(String),
  _Other(Vec<u8>),
}

impl TryFrom<&mut Iter<'_, u8>> for DnsQueryResourceRecord {
  type Error = NoneError;

  fn try_from(iter: &mut Iter<'_, u8>) -> Result<Self, Self::Error> {
    /* Parse name */
    let name = {
      let mut name = String::new();
      iter_to_str(iter, &mut name);
      name
    };

    /* Parse type_ */
    let type_ = iter_to_u16_be(iter)?.into();

    /* Parse class */
    let class = iter_to_u16_be(iter)?.into();

    /* Parse ttl */
    let ttl = iter_to_u32_be(iter)?;

    /* Parse rd_length */
    let rd_length = iter_to_u16_be(iter)?;

    /* Parse r_data */
    let r_data;
    {
      if let In = class {
        match type_ {
          A => {
            r_data = DnsQueryResourceRecordRDataType::Ipv4Addr(Ipv4Addr::new(
              *iter.next()?, *iter.next()?,
              *iter.next()?, *iter.next()?,
            ));
          }
          CName => {
            let mut s = String::new();
            iter_to_str(iter, &mut s);
            r_data = DnsQueryResourceRecordRDataType::String(s);
          }
          _ => {
            r_data = DnsQueryResourceRecordRDataType::_Other(iter.as_slice().to_vec());
          }
        }
      } else {
        r_data = DnsQueryResourceRecordRDataType::_Other(iter.as_slice().to_vec());
      }
    }

    Ok(Self { name, type_, class, ttl, rd_length, r_data })
  }
}