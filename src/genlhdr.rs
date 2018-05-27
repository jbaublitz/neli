use {Nl,MemRead,MemWrite,SerError,DeError};
use nlattr::{NlAttrHdr,AttrHandle};

/// Struct representing generic netlink header and payload
#[derive(Debug,PartialEq)]
pub struct GenlHdr<C> {
    /// Generic netlink message command
    pub cmd: C,
    /// Version of generic netlink family protocol
    pub version: u8,
    reserved: u16,
    /// Attributes included in generic netlink message
    attrs: Vec<u8>,
}

impl<C> GenlHdr<C> where C: From<u8> + Into<u8> {
    /// Create new generic netlink packet
    pub fn new<T>(cmd: C, version: u8, mut attrs: Vec<NlAttrHdr<T>>)
            -> Result<Self, SerError> where T: Nl + Into<u16> + From<u16> {
        let mut mem = MemWrite::new_vec(Some(attrs.iter().fold(0, |acc, item| {
            acc + item.asize()
        })));
        for item in attrs.iter_mut() {
            item.serialize(&mut mem)?;
        }
        Ok(GenlHdr {
            cmd,
            version,
            reserved: 0,
            attrs: mem.as_slice().to_vec(),
        })
    }

    /// Get handle for attribute parsing and traversal
    pub fn get_attr_handle<T>(&self) -> AttrHandle<T> where T: Nl + Into<u16> + From<u16> {
        AttrHandle::Bin(self.attrs.as_slice())
    }
}

impl<C> Nl for GenlHdr<C> where C: Nl + From<u8> + Into<u8> {
    type SerIn = ();
    type DeIn = ();

    fn serialize(&self, cur: &mut MemWrite) -> Result<(), SerError> {
        self.cmd.serialize(cur)?;
        self.version.serialize(cur)?;
        self.reserved.serialize(cur)?;
        self.attrs.serialize(cur)?;
        Ok(())
    }

    fn deserialize(mem: &mut MemRead) -> Result<Self, DeError> {
        Ok(GenlHdr {
            cmd: C::deserialize(mem)?,
            version: u8::deserialize(mem)?,
            reserved: u16::deserialize(mem)?,
            attrs: Vec::<u8>::deserialize(mem)?,
        })
    }

    fn size(&self) -> usize {
        self.cmd.size() + self.version.size() + self.reserved.size()
            + self.attrs.size()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use byteorder::{NativeEndian,WriteBytesExt};
    use std::io::{Cursor,Write};
    use ffi::{CtrlAttr,CtrlCmd};

    #[test]
    pub fn test_serialize() {
        let attr = vec![NlAttrHdr::new_binary_payload(None, CtrlAttr::FamilyId,
                                                        vec![0, 1, 2, 3, 4, 5, 0, 0]
                                                      )];
        let genl = GenlHdr::new(CtrlCmd::Getops, 2,
                                    attr).unwrap();
        let mut mem = MemWrite::new_vec(None);
        genl.serialize(&mut mem).unwrap();
        let v = Vec::with_capacity(genl.asize());
        let v_final = {
            let mut c = Cursor::new(v);
            c.write_u8(CtrlCmd::Getops.into()).unwrap();
            c.write_u8(2).unwrap();
            c.write_u16::<NativeEndian>(0).unwrap();
            c.write_u16::<NativeEndian>(12).unwrap();
            c.write_u16::<NativeEndian>(CtrlAttr::FamilyId.into()).unwrap();
            c.write_all(&vec![0, 1, 2, 3, 4, 5, 0, 0]).unwrap();
            c.into_inner()
        };
        assert_eq!(mem.as_slice(), v_final.as_slice())
    }

    #[test]
    pub fn test_deserialize() {
        let genl_mock = GenlHdr::new(CtrlCmd::Getops, 2,
                                     vec![NlAttrHdr::new_str_payload(None,
                                            CtrlAttr::FamilyId, "AAAAAAA"
                                        ).unwrap()]
                                     ).unwrap();
        let v = Vec::new();
        let v_final = {
            let mut c = Cursor::new(v);
            c.write_u8(CtrlCmd::Getops.into()).unwrap();
            c.write_u8(2).unwrap();
            c.write_u16::<NativeEndian>(0).unwrap();
            c.write_u16::<NativeEndian>(12).unwrap();
            c.write_u16::<NativeEndian>(CtrlAttr::FamilyId.into()).unwrap();
            c.write(&vec![65, 65, 65, 65, 65, 65, 65, 0]).unwrap();
            c.into_inner()
        };
        let mut mem = MemRead::new_slice(&v_final);
        let genl = GenlHdr::deserialize(&mut mem).unwrap();
        assert_eq!(genl, genl_mock)
    }
}
