use buffering::copy::{StreamReadBuffer,StreamWriteBuffer};

use {Nl,SerError,DeError};
use consts::{Cmd,NlAttrType};
use nlattr::{Nlattr,AttrHandle};

/// Struct representing generic netlink header and payload
#[derive(Debug,PartialEq)]
pub struct Genlmsghdr<C> {
    /// Generic netlink message command
    pub cmd: C,
    /// Version of generic netlink family protocol
    pub version: u8,
    reserved: u16,
    /// Attributes included in generic netlink message
    attrs: Vec<u8>,
}

impl<C> Genlmsghdr<C> where C: Cmd {
    /// Create new generic netlink packet
    pub fn new<T>(cmd: C, version: u8, mut attrs: Vec<Nlattr<T>>)
            -> Result<Self, SerError> where T: NlAttrType {
        let mut mem = StreamWriteBuffer::new_growable(Some(attrs.iter().fold(0, |acc, item| {
            acc + item.asize()
        })));
        for item in attrs.iter_mut() {
            item.serialize(&mut mem)?;
        }
        Ok(Genlmsghdr {
            cmd,
            version,
            reserved: 0,
            attrs: mem.as_ref().to_vec(),
        })
    }

    /// Get handle for attribute parsing and traversal
    pub fn get_attr_handle<T>(&self) -> AttrHandle<T> where T: NlAttrType {
        AttrHandle::Bin(self.attrs.as_slice())
    }
}

impl<C> Nl for Genlmsghdr<C> where C: Cmd {
    fn serialize(&self, cur: &mut StreamWriteBuffer) -> Result<(), SerError> {
        self.cmd.serialize(cur)?;
        self.version.serialize(cur)?;
        self.reserved.serialize(cur)?;
        self.attrs.serialize(cur)?;
        Ok(())
    }

    fn deserialize<T>(mem: &mut StreamReadBuffer<T>) -> Result<Self, DeError> where T: AsRef<[u8]> {
        let cmd = C::deserialize(mem)?;
        let version = u8::deserialize(mem)?;
        let reserved = u16::deserialize(mem)?;
        let size_hint = mem.take_size_hint().map(|sh| sh - (cmd.size() + version.size() +
                                                            reserved.size()));
        if let Some(sh) = size_hint {
            mem.set_size_hint(sh);
        }
        let attrs = Vec::<u8>::deserialize(mem)?;
        Ok(Genlmsghdr {
            cmd,
            version,
            reserved,
            attrs,
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
    use consts::{CtrlAttr,CtrlCmd};
    use socket::NlSocket;

    #[test]
    pub fn test_serialize() {
        let attr = vec![Nlattr::new_binary_payload(None, CtrlAttr::FamilyId,
                                                        vec![0, 1, 2, 3, 4, 5, 0, 0]
                                                      )];
        let genl = Genlmsghdr::new(CtrlCmd::Getops, 2,
                                    attr).unwrap();
        let mut mem = StreamWriteBuffer::new_growable(None);
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
        assert_eq!(mem.as_ref(), v_final.as_slice())
    }

    #[test]
    pub fn test_deserialize() {
        let genl_mock = Genlmsghdr::new(CtrlCmd::Getops, 2,
                                     vec![Nlattr::new_str_payload(None,
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
        let mut mem = StreamReadBuffer::new(&v_final);
        let genl = Genlmsghdr::deserialize(&mut mem).unwrap();
        assert_eq!(genl, genl_mock)
    }

    #[test]
    #[ignore]
    pub fn test_resolve_genl_family() {
        let mut s = NlSocket::new_genl().unwrap();
        let id = s.resolve_genl_family("acpi_event").unwrap();
        assert_eq!(23, id)
    }

    #[test]
    #[ignore]
    pub fn test_resolve_mcast_group() {
        let mut s = NlSocket::new_genl().unwrap();
        let id = s.resolve_nl_mcast_group("acpi_event", "acpi_mc_group").unwrap();
        assert_eq!(2, id)
    }

    //#[test]
    //pub fn test_deserialize_multiple_messages() {
    //    let genl_mock = Genlmsghdr::new(CtrlCmd::Getops, 2,
    //                                 vec![Nlattr::new_str_payload(None,
    //                                        CtrlAttr::FamilyId, "AAAAAAA"
    //                                    ).unwrap()]
    //                                 ).unwrap();
    //    let genl_second_mock = Genlmsghdr::new(CtrlCmd::Newops, 2,
    //                                 vec![Nlattr::new_str_payload(None,
    //                                        CtrlAttr::FamilyId, "BBBB"
    //                                    ).unwrap()]
    //                                 ).unwrap();
    //    let v = Vec::new();
    //    let v_final = {
    //        let mut c = Cursor::new(v);
    //        c.write_u8(CtrlCmd::Getops.into()).unwrap();
    //        c.write_u8(2).unwrap();
    //        c.write_u16::<NativeEndian>(0).unwrap();
    //        c.write_u16::<NativeEndian>(12).unwrap();
    //        c.write_u16::<NativeEndian>(CtrlAttr::FamilyId.into()).unwrap();
    //        c.write(&vec![65, 65, 65, 65, 65, 65, 65, 0]).unwrap();
    //        c.write_u8(CtrlCmd::Setops.into()).unwrap();
    //        c.write_u8(2).unwrap();
    //        c.write_u16::<NativeEndian>(0).unwrap();
    //        c.write_u16::<NativeEndian>(12).unwrap();
    //        c.write_u16::<NativeEndian>(CtrlAttr::FamilyId.into()).unwrap();
    //        c.write(&vec![66, 66, 66, 66, 0]).unwrap();
    //        c.into_inner()
    //    };
    //    let mut mem = StreamReadBuffer::new(&v_final);
    //    let genl = Genlmsghdr::deserialize_with(&mut mem).unwrap();
    //    let genl_second = Genlmsghdr::deserialize_with(&mut mem).unwrap();
    //    assert_eq!(genl, genl_mock);
    //    assert_eq!(genl_second, genl_second_mock)
    //}
}
