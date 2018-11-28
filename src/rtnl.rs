use std::mem;

use buffering::copy::{StreamReadBuffer,StreamWriteBuffer};
use libc;

use Nl;
use consts::{Arphrd,AddrFamily,Iff};
use err::{SerError,DeError};

/// Struct representing interface information messages
pub struct Ifinfomsg {
    /// Interface address family
    pub ifi_family: AddrFamily,
    /// Interface type
    pub ifi_type: Arphrd,
    /// Interface index
    pub ifi_index: libc::c_int,
    /// Interface flags
    pub ifi_flags: Vec<Iff>,
    ifi_change: libc::c_uint,
}

impl Ifinfomsg {
    /// Create a fully initialized interface info struct
    pub fn new(ifi_family: AddrFamily, ifi_type: Arphrd, ifi_index: libc::c_int, ifi_flags: Vec<Iff>) -> Self {
        Ifinfomsg { ifi_family, ifi_type, ifi_index, ifi_flags, ifi_change: 0xffffffff }
    }
}

impl Nl for Ifinfomsg {
    type SerIn = ();
    type DeIn = ();

    fn serialize(&self, buf: &mut StreamWriteBuffer) -> Result<(), SerError> {
        self.ifi_family.serialize(buf)?;
        self.ifi_type.serialize(buf)?;
        self.ifi_index.serialize(buf)?;
        self.ifi_flags.iter().fold(0, |acc: libc::c_uint, next| {
            let next_uint: libc::c_uint = next.into();
            acc | next_uint
        }).serialize(buf)?;
        self.ifi_change.serialize(buf)?;
        Ok(())
    }

    fn deserialize<B>(buf: &mut StreamReadBuffer<B>) -> Result<Self, DeError> where B: AsRef<[u8]> {
        Ok(Ifinfomsg {
            ifi_family: AddrFamily::deserialize(buf)?,
            ifi_type: Arphrd::deserialize(buf)?,
            ifi_index: libc::c_int::deserialize(buf)?,
            ifi_flags: {
                let flags = libc::c_uint::deserialize(buf)?;
                let mut nl_flags = Vec::new();
                for i in 0..mem::size_of::<libc::c_int>() * 8 {
                    let bit = 1 << i;
                    if bit & flags == bit {
                        nl_flags.push(bit.into());
                    }
                }
                nl_flags
            },
            ifi_change: 0xffffffff,
        })
    }

    fn size(&self) -> usize {
        self.ifi_family.size() + self.ifi_type.size() + self.ifi_index.size() + mem::size_of::<libc::c_uint>()
    }
}

/// Struct representing route netlink attributes
pub struct RtAttr {
    /// Length of the attribute
    pub rta_len: libc::c_ushort,
    /// Type of the attribute
    pub rta_type: libc::c_ushort,
}

impl Nl for RtAttr {
    type SerIn = ();
    type DeIn = ();

    fn serialize(&self, buf: &mut StreamWriteBuffer) -> Result<(), SerError> {
        self.rta_len.serialize(buf)?;
        self.rta_type.serialize(buf)?;
        Ok(())
    }

    fn deserialize<B>(buf: &mut StreamReadBuffer<B>) -> Result<Self, DeError> where B: AsRef<[u8]> {
        Ok(RtAttr {
            rta_len: libc::c_ushort::deserialize(buf)?,
            rta_type: libc::c_ushort::deserialize(buf)?,
        })
    }

    fn size(&self) -> usize {
        self.rta_len.size() + self.rta_type.size()
    }
}
