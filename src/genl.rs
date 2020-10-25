//! This module contains generic netlink parsing data structures. This is all handled by
//! the `Genlmsghdr` header struct which contains all of the information needed for the generic
//! netlink layer.
//!
//! # Design decisions
//!
//! The attributes that generic netlink uses are located in `nlattr.rs`. These attributes require
//! special attention when parsing so they are separated into their own module.
//!
//! The generic netlink `attrs` field has been changed to a `Vec` of `Nlattr`s instead of the
//! original `Vec<u8>` to allow simpler
//! parsing at the top level when one `Nlattr` structure is not nested within another, a use case
//! that is instead handled in `nlattr.rs`.

use crate::{
    consts::{Cmd, NlAttrType},
    nlattr::AttrHandle,
    types::{Buffer, DeBuffer, DeBufferOps, GenlBuffer, SerBuffer},
    DeError, Nl, SerError,
};

/// Struct representing generic netlink header and payload
#[derive(Debug, PartialEq)]
pub struct Genlmsghdr<C, T> {
    /// Generic netlink message command
    pub cmd: C,
    /// Version of generic netlink family protocol
    pub version: u8,
    reserved: u16,
    /// Attributes included in generic netlink message
    attrs: GenlBuffer<T, Buffer>,
}

impl<C, T> Genlmsghdr<C, T>
where
    C: Cmd,
    T: NlAttrType,
{
    /// Create new generic netlink packet
    pub fn new(cmd: C, version: u8, attrs: GenlBuffer<T, Buffer>) -> Self {
        Genlmsghdr {
            cmd,
            version,
            reserved: 0,
            attrs,
        }
    }
}

impl<C, T> Genlmsghdr<C, T>
where
    C: Cmd,
    T: NlAttrType,
{
    /// Get handle for attribute parsing and traversal
    pub fn get_attr_handle(&self) -> AttrHandle<T> {
        AttrHandle::new_borrowed(self.attrs.as_ref())
    }
}

impl<C, T> Nl for Genlmsghdr<C, T>
where
    C: Cmd,
    T: NlAttrType,
{
    fn serialize<'a>(&self, mem: SerBuffer<'a>) -> Result<SerBuffer<'a>, SerError<'a>> {
        Ok(serialize! {
            PAD self;
            mem;
            self.cmd;
            self.version;
            self.reserved;
            self.attrs
        })
    }

    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
        Ok(deserialize! {
            mem;
            Genlmsghdr {
                cmd: C,
                version: u8,
                reserved: u16,
                attrs: GenlBuffer<T, Buffer> => mem.len().checked_sub(
                    C::type_size().expect("Must be static size") +
                    u8::type_size().expect("Must be static size") +
                    u16::type_size().expect("Must be static size")
                )
                .ok_or(DeError::UnexpectedEOB)?
            }
        })
    }

    fn type_size() -> Option<usize> {
        None
    }

    fn size(&self) -> usize {
        self.cmd.size() + self.version.size() + self.reserved.size() + self.attrs.asize()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::io::{Cursor, Write};

    use byteorder::{NativeEndian, WriteBytesExt};

    use crate::{
        consts::{CtrlAttr, CtrlCmd, NlFamily},
        nlattr::Nlattr,
        socket::NlSocketHandle,
        types::{GenlBufferOps, SerBufferOps},
        utils::U32Bitmask,
    };

    #[test]
    pub fn test_serialize() {
        let mut attr = GenlBuffer::new();
        attr.push(
            Nlattr::new(
                None,
                false,
                false,
                CtrlAttr::FamilyId,
                vec![0, 1, 2, 3, 4, 5, 0, 0],
            )
            .unwrap(),
        );
        let genl = Genlmsghdr::new(CtrlCmd::Getops, 2, attr);
        let mut mem = SerBuffer::new(Some(genl.size()));
        mem = genl.serialize(mem).unwrap();

        let v = vec![0; genl.asize()];
        let v_final = {
            let mut c = Cursor::new(v);
            c.write_u8(CtrlCmd::Getops.into()).unwrap();
            c.write_u8(2).unwrap();
            c.write_u16::<NativeEndian>(0).unwrap();
            c.write_u16::<NativeEndian>(12).unwrap();
            c.write_u16::<NativeEndian>(CtrlAttr::FamilyId.into())
                .unwrap();
            c.write_all(&[0, 1, 2, 3, 4, 5, 0, 0]).unwrap();
            c.into_inner()
        };
        assert_eq!(mem.as_ref(), v_final.as_slice())
    }

    #[test]
    pub fn test_deserialize() {
        let mut attr = GenlBuffer::new();
        attr.push(
            Nlattr::new(
                None,
                false,
                false,
                CtrlAttr::FamilyId,
                "AAAAAAA".to_string(),
            )
            .unwrap(),
        );
        let genl_mock = Genlmsghdr::new(CtrlCmd::Getops, 2, attr);
        let v = Vec::new();
        let v_final = {
            let mut c = Cursor::new(v);
            c.write_u8(CtrlCmd::Getops.into()).unwrap();
            c.write_u8(2).unwrap();
            c.write_u16::<NativeEndian>(0).unwrap();
            c.write_u16::<NativeEndian>(12).unwrap();
            c.write_u16::<NativeEndian>(CtrlAttr::FamilyId.into())
                .unwrap();
            c.write_all(&[65, 65, 65, 65, 65, 65, 65, 0]).unwrap();
            c.into_inner()
        };
        let mem = DeBuffer::from(v_final.as_slice());
        let genl = Genlmsghdr::deserialize(mem).unwrap();
        assert_eq!(genl, genl_mock)
    }

    #[test]
    #[ignore]
    pub fn test_resolve_genl_family() {
        let mut s = NlSocketHandle::connect(NlFamily::Generic, None, U32Bitmask::empty()).unwrap();
        let id = s.resolve_genl_family("acpi_event").unwrap();
        assert_eq!(23, id)
    }

    #[test]
    #[ignore]
    pub fn test_resolve_mcast_group() {
        let mut s = NlSocketHandle::connect(NlFamily::Generic, None, U32Bitmask::empty()).unwrap();
        let id = s
            .resolve_nl_mcast_group("acpi_event", "acpi_mc_group")
            .unwrap();
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
