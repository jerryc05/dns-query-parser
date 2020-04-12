#![allow(dead_code)]

use DnsQueryHeaderFlagsQr::{Query, Response};
use std::mem::transmute;
use std::convert::{TryFrom, TryInto};
use std::option::NoneError;
use std::slice::Iter;
use crate::dns_query::utils::iter_to_u16_be;

/*
Header format

 15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
  0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      id                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|qr|  op_code  |aa|tc|rd|ra| z|ad|cd|  r_code   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   qd_count                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   an_count                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   ns_count                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   ar_count                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
#[derive(Debug)]
pub struct DnsQueryHeader {
  pub id: u16,
  pub flags: DnsQueryHeaderFlags,
  pub qd_count: u16,
  pub an_count: u16,
  pub ns_count: u16,
  pub ar_count: u16,
}

impl TryFrom<&mut Iter<'_, u8>> for DnsQueryHeader {
  type Error = NoneError;

  fn try_from(iter: &mut Iter<'_, u8>) -> Result<Self, Self::Error> {
    let id = iter_to_u16_be(iter)?;

    let flags = iter.try_into()?;

    let qd_count = iter_to_u16_be(iter)?;

    let an_count = iter_to_u16_be(iter)?;

    let ns_count = iter_to_u16_be(iter)?;

    let ar_count = iter_to_u16_be(iter)?;

    Ok(Self { id, flags, qd_count, an_count, ns_count, ar_count })
  }
}

impl From<&DnsQueryHeader> for [u8; 12] {
  fn from(header: &DnsQueryHeader) -> Self {
    let b1b2 = header.id.to_be_bytes();

    let b3b4: [u8; 2] = (&header.flags).into();

    let b5b6 = header.qd_count.to_be_bytes();

    let b7b8 = header.an_count.to_be_bytes();

    let b9b10 = header.ns_count.to_be_bytes();

    let b11b12 = header.ar_count.to_be_bytes();

    [b1b2[0], b1b2[1], b3b4[0], b3b4[1], b5b6[0], b5b6[1],
      b7b8[0], b7b8[1], b9b10[0], b9b10[1], b11b12[0], b11b12[1]]
  }
}

/*
  7  6  5  4  3  2  1  0  7  6  5  4  3  2  1  0
 15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
  0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|qr|  op_code  |aa|tc|rd|ra| z|ad|cd|  r_code   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
#[derive(Debug)]
pub struct DnsQueryHeaderFlags {
  pub qr: DnsQueryHeaderFlagsQr,
  pub op_code: DnsQueryHeaderFlagsOpcode,
  pub aa: DnsQueryHeaderFlagsAa,
  pub tc: DnsQueryHeaderFlagsTc,
  pub rd: DnsQueryHeaderFlagsRd,
  pub ra: DnsQueryHeaderFlagsRa,
  pub z: u8,
  pub ad: DnsQueryHeaderFlagsAd,
  pub cd: DnsQueryHeaderFlagsCd,
  pub r_code: DnsQueryHeaderFlagsRcode,
}

impl TryFrom<&mut Iter<'_, u8>> for DnsQueryHeaderFlags {
  type Error = NoneError;

  fn try_from(iter: &mut Iter<'_, u8>) -> Result<Self, Self::Error> {
    let byte_1 = iter.next()?;
    let byte_2 = iter.next()?;

    /* qr */
    let qr = {
      let val = (byte_1 >> 7) as u8;
      debug_assert!(val <= 0b1);
      if val == 0 { Query } else { Response }
    };

    /* op_code */
    let op_code = {
      let val = ((byte_1 >> 3) & 0b1111) as u8;
      debug_assert!(val <= 0b1111);
      unsafe { transmute::<u8, DnsQueryHeaderFlagsOpcode>(val) }
    };

    /* aa */
    let aa = {
      let val = ((byte_1 >> 2) & 0b1) as u8;
      debug_assert!(val <= 0b1);
      unsafe { transmute::<u8, DnsQueryHeaderFlagsAa>(val) }
    };

    /* tc */
    let tc = {
      let val = ((byte_1 >> 1) & 0b1) as u8;
      debug_assert!(val <= 0b1);
      unsafe { transmute::<u8, DnsQueryHeaderFlagsTc>(val) }
    };

    /* rd */
    let rd = {
      let val = (byte_1 & 0b1) as u8;
      debug_assert!(val <= 0b1);
      unsafe { transmute::<u8, DnsQueryHeaderFlagsRd>(val) }
    };

    /* ra */
    let ra = {
      let val = ((byte_2 >> 7) & 0b1) as u8;
      debug_assert!(val <= 0b1);
      unsafe { transmute::<u8, DnsQueryHeaderFlagsRa>(val) }
    };

    /* z */
    let z = {
      let val = ((byte_2 >> 6) & 0b1) as u8;
      debug_assert!(val <= 0b1);
      val
    };

    /* ad */
    let ad = {
      let val = ((byte_2 >> 5) & 0b1) as u8;
      debug_assert!(val <= 0b1);
      unsafe { transmute::<u8, DnsQueryHeaderFlagsAd>(val) }
    };

    /* cd */
    let cd = {
      let val = ((byte_2 >> 4) & 0b1) as u8;
      debug_assert!(val <= 0b1);
      unsafe { transmute::<u8, DnsQueryHeaderFlagsCd>(val) }
    };

    /* r_code */
    let r_code = {
      let val = (byte_2 & 0b1111) as u8;
      debug_assert!(val <= 0b1111);
      unsafe { transmute::<u8, DnsQueryHeaderFlagsRcode>(val) }
    };

    Ok(Self {
      qr,
      op_code,
      aa,
      tc,
      rd,
      ra,
      z,
      ad,
      cd,
      r_code,
    })
  }
}

#[allow(clippy::fallible_impl_from)]
impl From<&DnsQueryHeaderFlags> for [u8; 2] {
  fn from(flags: &DnsQueryHeaderFlags) -> Self {
    let mut byte_1 = 0;
    let mut byte_2 = 0;

    /* qr */ {
      let val = flags.qr as u8;
      debug_assert!(val <= 0b1);
      byte_1 |= val << 7;
    }

    /* op_code */ {
      let val = flags.op_code as u8;
      debug_assert!(val <= 0b1111);
      byte_1 |= val << 3;
    }

    /* aa */ {
      let val = flags.aa as u8;
      debug_assert!(val <= 0b1);
      byte_1 |= val << 2;
    }

    /* tc */ {
      let val = flags.tc as u8;
      debug_assert!(val <= 0b1);
      byte_1 |= val << 1;
    }

    /* rd */ {
      let val = flags.rd as u8;
      debug_assert!(val <= 0b1);
      byte_1 |= val;
    }

    /* ra */ {
      let val = flags.ra as u8;
      debug_assert!(val <= 0b1);
      byte_2 |= val << 7;
    }

    /* z */ {
      let val = flags.z as u8;
      debug_assert!(val <= 0b1);
      byte_2 |= val << 6;
    }

    /* ad */ {
      let val = flags.ad as u8;
      debug_assert!(val <= 0b1);
      byte_2 |= val << 5;
    }

    /* cd */ {
      let val = flags.cd as u8;
      debug_assert!(val <= 0b1);
      byte_2 |= val << 4;
    }

    /* r_code */ {
      let val = flags.r_code as u8;
      debug_assert!(val <= 0b1111);
      byte_2 |= val;
    }

    [byte_1, byte_2]
  }
}

#[derive(Debug, Copy, Clone)]
pub enum DnsQueryHeaderFlagsQr {
  /// 0: a query (0)
  Query = 0,
  /// 1: a response (1)
  Response = 1,
}

#[derive(Debug, Copy, Clone)]
pub enum DnsQueryHeaderFlagsOpcode {
  /// 0: a standard query (QUERY)
  StdQuery = 0,
  /// 1: an inverse query (IQUERY)
  InvQuery = 1,
  /// 2: a server status request (STATUS)
  StatReq = 2,
  /// 3: unassigned
  _UnAssign3 = 3,
  /// 4: notify
  Notify = 4,
  /// 5: update
  Upd = 5,
  /// 6: DNS Stateful Operations (DSO)
  Dso = 6,
  /// 7-15: reserved for future use
  _Resv7To15 = 15,  // use largest possible for correct `std::mem::transmute()` parsing
}

#[derive(Debug, Copy, Clone)]
pub enum DnsQueryHeaderFlagsAa {
  /// 0
  NonAuthAns = 0,
  /// 1
  AuthAns = 1,
}

#[derive(Debug, Copy, Clone)]
pub enum DnsQueryHeaderFlagsTc {
  /// 0
  NonTrunc = 0,
  /// 1
  Trunc = 1,
}

#[derive(Debug, Copy, Clone)]
pub enum DnsQueryHeaderFlagsRd {
  /// 0
  NotRecur = 0,
  /// 1
  Recur = 1,
}

#[derive(Debug, Copy, Clone)]
pub enum DnsQueryHeaderFlagsRa {
  /// 0
  NotAvailable = 0,
  /// 1
  Available = 1,
}

#[derive(Debug, Copy, Clone)]
pub enum DnsQueryHeaderFlagsAd {
  /// 0
  NotAuthed = 0,
  /// 1
  Authed = 1,
}

#[derive(Debug, Copy, Clone)]
pub enum DnsQueryHeaderFlagsCd {
  /// 0
  Checked = 0,
  /// 1
  NotChecked = 1,
}

#[derive(Debug, Copy, Clone)]
pub enum DnsQueryHeaderFlagsRcode {
  /// 0: No error condition
  NoErr = 0,
  /// 1: Format error - The name server was unable to interpret the query.
  FormatErr = 1,
  /// 2: Server failure - The name server was unable to process this query
  ///                     due to a problem with the name server.
  SvrFail = 2,
  /// 3: Name Error - Meaningful only for responses from an authoritative
  ///                 name server, this code signifies that the domain name
  ///                 referenced in the query does not exist.
  NameErr = 3,
  /// 4: Not Implemented - The name server does not support the requested
  ///                      kind of query.
  NotImpl = 4,
  /// 5: Refused - The name server refuses to perform the specified operation
  ///              for policy reasons.  For example, a name server may not
  ///              wish to provide the information to the particular requester,
  ///              or a name server may not wish to perform a particular
  ///              operation (e.g., z//one transfer) for particular data.
  Refused = 5,
  /// 6: A name that should not exist does exist.
  NameExist = 6,
  /// 7: A resource record set that should not exist does exist.
  ResRecordExist = 7,
  /// 8: A resource record set that should exist does not exist.
  ResRecordNotExist = 8,
  /// 9: DNS server is not authoritative for the z//one named in the Zone section.
  ZoneNotAuth = 9,
  /// 10: A name used in the Prerequisite or Update sections is not within the
  ///     z//one specified by the Zone section.
  NameNotInZone = 10,
  /// 11-15: Reserved for future use.
  _Resv11To15 = 15,  // use largest possible for correct `std::mem::transmute()` parsing
}