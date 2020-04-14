#![allow(dead_code)]

use crate::dns_query::utils::{iter_to_str, str_to_vec, iter_to_u16_be,
                              DnsQueryType, DnsQueryClass};
use std::convert::TryFrom;
use std::num::TryFromIntError;
use std::option::NoneError;
use std::slice::Iter;
use std::borrow::Cow;

/*
Question format

 15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
  0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                    q_name                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    q_type                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    q_class                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
#[derive(Debug)]
pub struct DnsQueryQuestion<'a> {
  pub q_name: Cow<'a, str>,
  pub q_type: DnsQueryType,
  pub q_class: DnsQueryClass,
}

impl<'a> TryFrom<&mut Iter<'_, u8>> for DnsQueryQuestion<'a> {
  type Error = NoneError;

  fn try_from(iter: &mut Iter<'_, u8>) -> Result<Self, Self::Error> {
    /* Parse q_name */
    let q_name = {
      let mut val = String::new();
      iter_to_str(iter, &mut val);
      Cow::from(val)
    };

    /* Parse q_type  */
    let q_type = iter_to_u16_be(iter)?.into();

    /* Parse q_class */
    let q_class = iter_to_u16_be(iter)?.into();

    Ok(Self { q_name, q_type, q_class })
  }
}

impl<'a> TryFrom<&DnsQueryQuestion<'a>> for Vec<u8> {
  type Error = TryFromIntError;

  fn try_from(question: &DnsQueryQuestion) -> Result<Self, Self::Error> {
    let mut result = vec![];

    /* Parse q_name */ {
      str_to_vec(&question.q_name, &mut result)?;
    }

    /* Parse q_type */ {
      let q_type: u16 = (&question.q_type).into();
      result.extend_from_slice(&q_type.to_be_bytes());
    }

    /* Parse q_class */ {
      let q_class: u16 = (&question.q_class).into();
      result.extend_from_slice(&q_class.to_be_bytes());
    }

    result.shrink_to_fit();
    Ok(result)
  }
}