use buffering::copy::{StreamReadBuffer,StreamWriteBuffer};

use {Nl,SerError,DeError};
use consts::{Cmd,NlAttrType};
use nlattr::{Nlattr,AttrHandle};

/// Struct representing generic netlink header and payload
#[derive(Debug,PartialEq)]
pub struct Genlmsghdr<C, T, P> {
    /// Generic netlink message command
    pub cmd: C,
    /// Version of generic netlink family protocol
    pub version: u8,
    reserved: u16,
    /// Attributes included in generic netlink message
    attrs: Vec<Nlattr<T, P>>,
}

impl<C, T, P> Genlmsghdr<C, T, P> where C: Cmd, T: NlAttrType, P: Nl {
    /// Create new generic netlink packet
    pub fn new(cmd: C, version: u8, attrs: Vec<Nlattr<T, P>>) -> Result<Self, SerError> {
        Ok(Genlmsghdr {
            cmd,
            version,
            reserved: 0,
            attrs,
        })
    }
}

impl<C, T> Genlmsghdr<C, T, Vec<u8>> where C: Cmd, T: NlAttrType {
    /// Get handle for attribute parsing and traversal
    pub fn get_attr_handle(&self) -> AttrHandle<T> {
        AttrHandle::new_borrowed(&self.attrs)
    }
}

impl<C, T, P> Nl for Genlmsghdr<C, T, P> where C: Cmd, T: NlAttrType, P: Nl {
    fn serialize(&self, cur: &mut StreamWriteBuffer) -> Result<(), SerError> {
        self.cmd.serialize(cur)?;
        self.version.serialize(cur)?;
        self.reserved.serialize(cur)?;
        self.attrs.serialize(cur)?;
        Ok(())
    }

    fn deserialize<B>(mem: &mut StreamReadBuffer<B>) -> Result<Self, DeError> where B: AsRef<[u8]> {
        let cmd = C::deserialize(mem)?;
        let version = u8::deserialize(mem)?;
        let reserved = u16::deserialize(mem)?;
        let mut size_hint = match mem.take_size_hint().map(|sh| {
            sh - (cmd.size() + version.size() + reserved.size())
        }) {
            Some(sh) => sh,
            None => return Err(DeError::new("Must provide size hint to deserialize Genlmsghdr")),
        };
        let mut attrs = Vec::new();
        while size_hint > 0 {
            let attr = Nlattr::<T, P>::deserialize(mem)?;
            size_hint -= attr.size();
            attrs.push(attr);
        }
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
    use consts::{CtrlAttr,CtrlCmd,NlFamily};
    use socket::NlSocket;

    #[test]
    pub fn test_serialize() {
        let attr = vec![Nlattr::new(None, CtrlAttr::FamilyId,
                                    vec![0, 1, 2, 3, 4, 5, 0, 0])];
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
                                        vec![Nlattr::new(None, CtrlAttr::FamilyId,
                                                         "AAAAAAA".to_string())]).unwrap();
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
        mem.set_size_hint(genl_mock.size());
        let genl = Genlmsghdr::deserialize(&mut mem).unwrap();
        assert_eq!(genl, genl_mock)
    }

    #[test]
    #[ignore]
    pub fn test_resolve_genl_family() {
        let mut s = NlSocket::connect(NlFamily::Generic, None, None, true).unwrap();
        let id = s.resolve_genl_family("acpi_event").unwrap();
        assert_eq!(23, id)
    }

    #[test]
    #[ignore]
    pub fn test_resolve_mcast_group() {
        let mut s = NlSocket::connect(NlFamily::Generic, None, None, true).unwrap();
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
