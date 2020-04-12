#![allow(dead_code)]

use DnsQueryHeaderFlagsQr::{Query, Response};
use std::mem::transmute;
use std::convert::TryFrom;
use std::option::NoneError;

/*
Header format

 15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
  0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      id                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|qr|  op_code  |aa|tc|rd|ra|   z    |  r_code   |
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
pub(crate) struct DnsQueryHeader {
  pub(crate) id: u16,
  pub(crate) flags: DnsQueryHeaderFlags,
  pub(crate) qd_count: u16,
  pub(crate) an_count: u16,
  pub(crate) ns_count: u16,
  pub(crate) ar_count: u16,
}

/*
  7  6  5  4  3  2  1  0  7  6  5  4  3  2  1  0
 15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
  0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|qr|  op_code  |aa|tc|rd|ra|   z    |  r_code   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
#[derive(Debug)]
pub(crate) struct DnsQueryHeaderFlags {
  qr: DnsQueryHeaderFlagsQr,
  op_code: DnsQueryHeaderFlagsOpcode,
  aa: DnsQueryHeaderFlagsAa,
  tc: DnsQueryHeaderFlagsTc,
  rd: DnsQueryHeaderFlagsRd,
  ra: DnsQueryHeaderFlagsRa,
  z: u8,
  r_code: DnsQueryHeaderFlagsRcode,
}

impl TryFrom<&[u8]> for DnsQueryHeaderFlags {
  type Error = NoneError;

  fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
    let mut iter = bytes.into_iter();
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
      let val = ((byte_2 >> 3) & 0b111) as u8;
      debug_assert!(val <= 0b111);
      val
    };

    /* r_code */
    let r_code = {
      let val = (byte_2 & 0b1111) as u8;
      debug_assert!(val <= 0b1111);
      unsafe { transmute::<u8, DnsQueryHeaderFlagsRcode>(val) }
    };

    Ok(Self { qr, op_code, aa, tc, rd, ra, z, r_code })
  }
}

impl From<&DnsQueryHeaderFlags> for Vec<u8> {
  fn from(_: &DnsQueryHeaderFlags) -> Self {
    unimplemented!()
  }
}

// qr
impl DnsQueryHeaderFlags {
  fn qr_mut(&mut self, new: &DnsQueryHeaderFlagsQr) {
    self.0 &= ((*new) as u16) << 15;
  }
}

// op_code
impl DnsQueryHeaderFlags {
  fn op_code_mut(&mut self, new: &DnsQueryHeaderFlagsOpcode) {
    self.0 &= ((*new) as u16) << 11;
  }
}

// tc
impl DnsQueryHeaderFlags {
  fn tc_mut(&mut self, new: &DnsQueryHeaderFlagsTc) {
    self.0 &= ((*new) as u16) << 9;
  }
}

// rd
impl DnsQueryHeaderFlags {
  fn rd_mut(&mut self, new: &DnsQueryHeaderFlagsRd) {
    self.0 &= ((*new) as u16) << 8;
  }
}

// ra
impl DnsQueryHeaderFlags {
  fn ra_mut(&mut self, new: &DnsQueryHeaderFlagsRa) {
    self.0 &= ((*new) as u16) << 7;
  }
}


#[derive(Debug, Copy, Clone)]
pub(crate) enum DnsQueryHeaderFlagsQr {
  /// 0: a query (0)
  Query = 0,
  /// 1: a response (1)
  Response = 1,
}

#[derive(Debug, Copy, Clone)]
pub(crate) enum DnsQueryHeaderFlagsOpcode {
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

#[derive(Debug)]
pub(crate) enum DnsQueryHeaderFlagsAa {
  /// 0
  NonAuthAns = 0,
  /// 1
  AuthAns = 1,
}

#[derive(Debug, Copy, Clone)]
pub(crate) enum DnsQueryHeaderFlagsTc {
  /// 0
  NonTrunc = 0,
  /// 1
  Trunc = 1,
}

#[derive(Debug, Copy, Clone)]
pub(crate) enum DnsQueryHeaderFlagsRd {
  /// 0
  NotRecur = 0,
  /// 1
  Recur = 1,
}

#[derive(Debug, Copy, Clone)]
pub(crate) enum DnsQueryHeaderFlagsRa {
  /// 0
  NotAvailable = 0,
  /// 1
  Available = 1,
}

#[derive(Debug)]
pub(crate) enum DnsQueryHeaderFlagsRcode {
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
  ///              operation (e.g., zone transfer) for particular data.
  Refused = 5,
  /// 6: A name that should not exist does exist.
  NameExist = 6,
  /// 7: A resource record set that should not exist does exist.
  ResRecordExist = 7,
  /// 8: A resource record set that should exist does not exist.
  ResRecordNotExist = 8,
  /// 9: DNS server is not authoritative for the zone named in the Zone section.
  ZoneNotAuth = 9,
  /// 10: A name used in the Prerequisite or Update sections is not within the
  ///     zone specified by the Zone section.
  NameNotInZone = 10,
  /// 11-15: Reserved for future use.
  _Resv11To15 = 15,  // use largest possible for correct `std::mem::transmute()` parsing
}