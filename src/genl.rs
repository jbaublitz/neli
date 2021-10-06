//! This module contains generic netlink parsing data structures.
//! This is all handled by the [`Genlmsghdr`][crate::genl::Genlmsghdr]
//! header struct which contains all of the information needed for
//! the generic netlink layer.
//!
//! # Design decisions
//!
//! The generic netlink `attrs` field has been changed to a
//! [`GenlBuffer`][crate::types::GenlBuffer] of
//! [`Nlattr`][crate::genl::Nlattr]s instead of the
//! original [`Vec<u8>`][Vec] to allow simpler parsing at the top
//! level when one [`Nlattr`][crate::genl::Nlattr] structure is not
//! nested within another, a use case that is instead handled using
//! [`AttrHandle`][crate::attr::AttrHandle].

use crate::{
    alignto,
    attr::{AttrHandle, AttrHandleMut, Attribute},
    consts::genl::{Cmd, NlAttrType},
    err::NlError,
    parse::packet_length_u16,
    types::{Buffer, DeBuffer, GenlBuffer, SerBuffer},
    utils::serialize,
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
    pub fn get_attr_handle(&self) -> AttrHandle<GenlBuffer<T, Buffer>, Nlattr<T, Buffer>> {
        self.attrs.get_attr_handle()
    }

    /// Get handle for attribute mutable and traversal
    pub fn get_attr_handle_mut(
        &mut self,
    ) -> AttrHandleMut<GenlBuffer<T, Buffer>, Nlattr<T, Buffer>> {
        self.attrs.get_attr_handle_mut()
    }
}

impl<C, T> Nl for Genlmsghdr<C, T>
where
    C: Cmd,
    T: NlAttrType,
{
    fn serialize(&self, mem: SerBuffer) -> Result<(), SerError> {
        serialize! {
            PAD self;
            mem;
            self.cmd;
            self.version;
            self.reserved;
            self.attrs
        };
        Ok(())
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

impl<'a, T, P> Nl for &'a [Nlattr<T, P>]
where
    T: NlAttrType,
    P: Nl,
{
    fn serialize(&self, mem: SerBuffer) -> Result<(), SerError> {
        let mut pos = 0;
        for item in self.iter() {
            pos = drive_serialize!(item, mem, pos, asize);
        }
        drive_serialize!(END mem, pos);
        Ok(())
    }

    fn deserialize(_: DeBuffer) -> Result<Self, DeError> {
        Err(DeError::new(
            "Deserialize a GenlBuffer and call .as_slice()",
        ))
    }

    fn type_size() -> Option<usize> {
        None
    }

    fn size(&self) -> usize {
        let mut size = 0;
        for attr in self.iter() {
            size += attr.asize()
        }
        size
    }
}

impl<T, P> Nl for GenlBuffer<T, P>
where
    T: NlAttrType,
    P: Nl + std::fmt::Debug,
{
    fn serialize(&self, mem: SerBuffer) -> Result<(), SerError> {
        self.as_ref().serialize(mem)
    }

    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
        let mut vec = GenlBuffer::new();
        let mut pos = 0;
        while pos < mem.len() {
            let (attr, pos_tmp) = drive_deserialize!(
                Nlattr<T, P>,
                mem,
                pos,
                alignto(packet_length_u16(mem, pos))
            );
            vec.push(attr);
            pos = pos_tmp;
        }
        Ok(vec)
    }

    fn type_size() -> Option<usize> {
        None
    }

    fn size(&self) -> usize {
        self.as_ref().size()
    }
}

/// Struct representing netlink attributes and payloads
#[derive(Debug, PartialEq)]
pub struct Nlattr<T, P> {
    /// Length of the attribute header and payload together
    pub nla_len: u16,
    /// If true, the payload contains nested attributes.
    pub nla_nested: bool,
    /// If true, the payload is in net work byte order.
    pub nla_network_order: bool,
    /// Enum representing the type of the attribute payload
    pub nla_type: T,
    /// Payload of the attribute - either parsed or a binary buffer
    pub nla_payload: P,
}

impl<T> Nlattr<T, Buffer>
where
    T: NlAttrType,
{
    /// Create a new `Nlattr` with parameters for setting bitflags
    /// in the header.
    pub fn new<P>(
        nla_len: Option<u16>,
        nla_nested: bool,
        nla_network_order: bool,
        nla_type: T,
        nla_payload: P,
    ) -> Result<Self, NlError>
    where
        P: Nl,
    {
        let mut attr = Nlattr {
            nla_len: nla_len.unwrap_or(0),
            nla_nested,
            nla_network_order,
            nla_type,
            nla_payload: Buffer::new(),
        };
        attr.set_payload(&nla_payload).map_err(|e| {
            NlError::new(format!("Failed to convert payload to a byte buffer: {}", e))
        })?;
        Ok(attr)
    }

    /// Add a nested attribute to the end of the payload.
    pub fn add_nested_attribute<TT, P>(&mut self, attr: &Nlattr<TT, P>) -> Result<(), NlError>
    where
        TT: NlAttrType,
        P: Nl,
    {
        let ser_buffer = serialize(attr, true)?;

        self.nla_payload.extend_from_slice(ser_buffer.as_ref());
        self.nla_len += attr.asize() as u16;
        Ok(())
    }

    /// Return an `AttrHandle` for attributes nested in the given attribute payload
    pub fn get_attr_handle<R>(&self) -> Result<GenlAttrHandle<R>, NlError>
    where
        R: NlAttrType,
    {
        Ok(AttrHandle::new(
            GenlBuffer::deserialize(self.nla_payload.as_ref()).map_err(NlError::new)?,
        ))
    }

    /// Return a mutable `AttrHandle` for attributes nested in the given attribute payload
    pub fn get_attr_handle_mut<R>(&mut self) -> Result<GenlAttrHandleMut<R>, NlError>
    where
        R: NlAttrType,
    {
        Ok(AttrHandleMut::new(
            GenlBuffer::deserialize(self.nla_payload.as_ref()).map_err(NlError::new)?,
        ))
    }
}

impl<T> Attribute<T> for Nlattr<T, Buffer>
where
    T: NlAttrType,
{
    fn payload(&self) -> &Buffer {
        &self.nla_payload
    }

    fn set_payload<P>(&mut self, payload: &P) -> Result<(), NlError>
    where
        P: Nl,
    {
        let ser_buffer = serialize(payload, false)?;
        self.nla_payload = Buffer::from(ser_buffer);

        // Update Nlattr with new length
        self.nla_len = (self.nla_len.size() + self.nla_type.size() + payload.size()) as u16;

        Ok(())
    }
}

// Generate the bitflag mask for field nla_type in Nlattr.
fn to_nla_type_bit_flags<T>(nla_nested: bool, nla_network_order: bool, nla_type: T) -> u16
where
    T: NlAttrType,
{
    let nla_type_u16: u16 = nla_type.into();
    (if nla_nested { 1 << 15 } else { 0u16 })
        | (if nla_network_order { 1 << 14 } else { 0u16 })
        | nla_type_u16
}

// Get the bitflags from nla_type in Nlattr.
fn from_nla_type_bit_flags<T>(nla_type: u16) -> (bool, bool, T)
where
    T: NlAttrType,
{
    (
        nla_type & (1 << 15) != 0,
        nla_type & (1 << 14) != 0,
        T::from(nla_type & !(3 << 14)),
    )
}

impl<T, P> Nl for Nlattr<T, P>
where
    T: NlAttrType,
    P: Nl,
{
    fn serialize(&self, mem: SerBuffer) -> Result<(), SerError> {
        let nla_type =
            to_nla_type_bit_flags(self.nla_nested, self.nla_network_order, self.nla_type);
        serialize! {
            PAD self;
            mem;
            self.nla_len, size;
            nla_type, size;
            self.nla_payload, size
        };
        Ok(())
    }

    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
        let pos = 0;
        let (nla_len, pos) = drive_deserialize!(u16, mem, pos);
        let (nla_type, pos) = drive_deserialize!(u16, mem, pos);
        let (nla_payload, pos) = drive_deserialize!(
            P,
            mem,
            pos,
            (nla_len as usize)
                .checked_sub(
                    u16::type_size().expect("Must be a static size")
                        + T::type_size().expect("Must be a static size")
                )
                .ok_or(DeError::UnexpectedEOB)?
        );
        let pos = drive_deserialize!(
            STRIP mem, pos, alignto(nla_len as usize) - nla_len as usize
        );
        drive_deserialize!(END mem, pos);

        let (nla_nested, nla_network_order, nla_type) = from_nla_type_bit_flags(nla_type);
        Ok(Nlattr::<T, P> {
            nla_len,
            nla_nested,
            nla_network_order,
            nla_type,
            nla_payload,
        })
    }

    fn type_size() -> Option<usize> {
        None
    }

    fn size(&self) -> usize {
        self.nla_len.size() + self.nla_type.size() + self.nla_payload.size()
    }
}
type GenlAttrHandle<'a, T> = AttrHandle<'a, GenlBuffer<T, Buffer>, Nlattr<T, Buffer>>;
type GenlAttrHandleMut<'a, T> = AttrHandleMut<'a, GenlBuffer<T, Buffer>, Nlattr<T, Buffer>>;

impl<'a, T> AttrHandle<'a, GenlBuffer<T, Buffer>, Nlattr<T, Buffer>>
where
    T: NlAttrType,
{
    /// Get the payload of an attribute as a handle for parsing nested attributes
    pub fn get_nested_attributes<S>(&mut self, subattr: T) -> Result<GenlAttrHandle<S>, NlError>
    where
        S: NlAttrType,
    {
        Ok(AttrHandle::new(
            GenlBuffer::deserialize(
                self.get_attribute(subattr)
                    .ok_or_else(|| NlError::new("Couldn't find specified attribute"))?
                    .nla_payload
                    .as_ref(),
            )
            .map_err(NlError::new)?,
        ))
    }

    /// Get nested attributes from a parsed handle
    pub fn get_attribute(&self, t: T) -> Option<&Nlattr<T, Buffer>> {
        for item in self.get_attrs().iter() {
            if item.nla_type == t {
                return Some(item);
            }
        }
        None
    }

    /// Parse binary payload as a type that implements [`Nl`] using
    /// [`deserialize`][crate::Nl::deserialize].
    pub fn get_attr_payload_as<R>(&self, attr: T) -> Result<R, NlError>
    where
        R: Nl,
    {
        match self.get_attribute(attr) {
            Some(a) => a.get_payload_as::<R>(),
            _ => Err(NlError::new("Failed to find specified attribute")),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::io::{Cursor, Write};

    use byteorder::{NativeEndian, WriteBytesExt};

    use crate::{
        consts::{
            genl::{CtrlAttr, CtrlCmd},
            socket::NlFamily,
        },
        socket::NlSocketHandle,
        utils::serialize,
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
        let mem = serialize(&genl, false).unwrap();

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
        assert_eq!(mem.as_slice(), v_final.as_slice())
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
        let mem = v_final.as_slice();
        let genl = Genlmsghdr::deserialize(mem).unwrap();
        assert_eq!(genl, genl_mock)
    }

    #[test]
    #[ignore]
    pub fn test_resolve_genl_family() {
        let mut s = NlSocketHandle::connect(NlFamily::Generic, None, &[]).unwrap();
        let id = s.resolve_genl_family("acpi_event").unwrap();
        assert_eq!(23, id)
    }

    #[test]
    #[ignore]
    pub fn test_resolve_mcast_group() {
        let mut s = NlSocketHandle::connect(NlFamily::Generic, None, &[]).unwrap();
        let id = s
            .resolve_nl_mcast_group("acpi_event", "acpi_mc_group")
            .unwrap();
        assert_eq!(2, id)
    }

    #[test]
    fn test_padding_size_calculation() {
        let nlattr = Nlattr::new(None, false, false, CtrlAttr::Unspec, 4u16).unwrap();
        assert_eq!(nlattr.size(), 6);
        assert_eq!(nlattr.asize(), 8);
    }

    #[test]
    fn test_nlattr_bitflags() {
        let type_ = 3 << 14;
        assert_eq!((true, true, 0), from_nla_type_bit_flags(type_))
    }

    #[test]
    fn test_nl_nlattr() {
        let nlattr = Nlattr::new(None, false, false, CtrlAttr::Unspec, 4u16).unwrap();
        let nlattr_serialized = serialize(&nlattr, true).unwrap();

        let mut nlattr_desired_serialized = Cursor::new(vec![0; nlattr.size()]);
        nlattr_desired_serialized
            .write_u16::<NativeEndian>(6)
            .unwrap();
        nlattr_desired_serialized
            .write_u16::<NativeEndian>(CtrlAttr::Unspec.into())
            .unwrap();
        nlattr_desired_serialized
            .write_u16::<NativeEndian>(4)
            .unwrap();
        nlattr_desired_serialized.write_all(&[0, 0]).unwrap();

        assert_eq!(
            nlattr_serialized.as_slice(),
            nlattr_desired_serialized.into_inner().as_slice()
        );

        let nlattr_desired_deserialized = Nlattr {
            nla_len: 6,
            nla_nested: false,
            nla_network_order: false,
            nla_type: CtrlAttr::Unspec,
            nla_payload: 4u16,
        };

        let mut nlattr_deserialize_buffer =
            Cursor::new(vec![0; nlattr_desired_deserialized.asize()]);
        nlattr_deserialize_buffer
            .write_u16::<NativeEndian>(6)
            .unwrap();
        nlattr_deserialize_buffer
            .write_u16::<NativeEndian>(CtrlAttr::Unspec.into())
            .unwrap();
        nlattr_deserialize_buffer
            .write_u16::<NativeEndian>(4)
            .unwrap();
        nlattr_deserialize_buffer.write_all(&[0, 0]).unwrap();
        let bytes = nlattr_deserialize_buffer.get_ref().as_slice();
        let nlattr_deserialized = Nlattr::<CtrlAttr, u16>::deserialize(bytes).unwrap();
        assert_eq!(nlattr_deserialized, nlattr_desired_deserialized);
    }

    #[test]
    fn test_nl_len_after_adding_nested_attributes() {
        let mut nlattr =
            Nlattr::new::<Vec<u8>>(None, true, false, CtrlAttr::Unspec, vec![]).unwrap();
        assert_eq!(nlattr.size(), 4);

        let aligned = Nlattr::new(None, false, false, CtrlAttr::Unspec, vec![1, 2, 3, 4]).unwrap();
        assert_eq!(aligned.size(), 8);
        let unaligned = Nlattr::new(None, false, false, CtrlAttr::FamilyId, vec![1]).unwrap();
        assert_eq!(unaligned.size(), 5);

        nlattr.add_nested_attribute(&aligned).unwrap();
        assert_eq!(nlattr.size(), 12);

        nlattr.add_nested_attribute(&unaligned).unwrap();
        assert_eq!(nlattr.size(), 20);
        assert_eq!(
            nlattr
                .get_attr_handle()
                .unwrap()
                .get_attribute(CtrlAttr::FamilyId)
                .unwrap()
                .size(),
            5
        );

        nlattr.add_nested_attribute(&aligned).unwrap();
        assert_eq!(nlattr.size(), 28);
    }

    #[test]
    fn test_vec_nlattr_nl() {
        let mut vec_nlattr_desired = Cursor::new(vec![]);

        vec_nlattr_desired.write_u16::<NativeEndian>(40).unwrap();
        vec_nlattr_desired
            .write_u16::<NativeEndian>(1 << 15 | 1)
            .unwrap();

        vec_nlattr_desired.write_u16::<NativeEndian>(12).unwrap();
        vec_nlattr_desired.write_u16::<NativeEndian>(1).unwrap();
        vec_nlattr_desired
            .write_all(&[0, 1, 2, 3, 4, 5, 6, 7])
            .unwrap();

        vec_nlattr_desired.write_u16::<NativeEndian>(8).unwrap();
        vec_nlattr_desired.write_u16::<NativeEndian>(2).unwrap();
        vec_nlattr_desired.write_all(&[0, 1, 2, 3]).unwrap();

        vec_nlattr_desired.write_u16::<NativeEndian>(5).unwrap();
        vec_nlattr_desired.write_u16::<NativeEndian>(3).unwrap();
        vec_nlattr_desired.write_all(&[0, 0, 0, 0]).unwrap();

        vec_nlattr_desired.write_u16::<NativeEndian>(6).unwrap();
        vec_nlattr_desired.write_u16::<NativeEndian>(4).unwrap();
        vec_nlattr_desired.write_u16::<NativeEndian>(15).unwrap();
        vec_nlattr_desired.write_all(&[0, 0]).unwrap();

        vec_nlattr_desired.write_u16::<NativeEndian>(6).unwrap();
        vec_nlattr_desired.write_u16::<NativeEndian>(2).unwrap();
        vec_nlattr_desired.write_all(&[0, 1, 0, 0]).unwrap();

        vec_nlattr_desired.write_u16::<NativeEndian>(5).unwrap();
        vec_nlattr_desired.write_u16::<NativeEndian>(3).unwrap();
        vec_nlattr_desired.write_all(&[5, 0, 0, 0]).unwrap();

        let mut nlattr = Nlattr::new(None, true, false, 1u16, Vec::<u8>::new()).unwrap();
        nlattr
            .add_nested_attribute(
                &Nlattr::new(
                    None,
                    false,
                    false,
                    1u16,
                    &[0u8, 1, 2, 3, 4, 5, 6, 7] as &[u8],
                )
                .unwrap(),
            )
            .unwrap();
        nlattr
            .add_nested_attribute(
                &Nlattr::new(None, false, false, 2u16, &[0u8, 1, 2, 3] as &[u8]).unwrap(),
            )
            .unwrap();
        nlattr
            .add_nested_attribute(&Nlattr::new(None, false, false, 3u16, 0u8).unwrap())
            .unwrap();
        nlattr
            .add_nested_attribute(&Nlattr::new(None, false, false, 4u16, 15u16).unwrap())
            .unwrap();
        let mut vec = GenlBuffer::new();
        vec.push(nlattr);
        vec.push(Nlattr::new(None, false, false, 2u16, vec![0, 1]).unwrap());
        vec.push(Nlattr::new(None, false, false, 3u16, 5u8).unwrap());

        let bytes = serialize(&vec, true).unwrap();

        assert_eq!(vec_nlattr_desired.get_ref().as_slice(), bytes.as_slice());

        let bytes = vec_nlattr_desired.get_ref().as_slice();
        let deserialized = GenlBuffer::deserialize(bytes).unwrap();

        assert_eq!(vec, deserialized);
    }
}
