use buffering::copy::{StreamReadBuffer,StreamWriteBuffer};
use libc;

use Nl;
use consts::{Arphrd,AddrFamily};
use err::{SerError,DeError};

/// Struct representing interface information messages
pub struct Ifinfomsg {
    /// Interface address family
    pub ifi_family: AddrFamily,
    /// Interface type
    pub ifi_type: Arphrd
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
