use {Nl,NlSerState,NlDeState,SerError,DeError};
use ffi::GenlCmds;

use std::fmt::Debug;

/// Handle returned by `GenlHdr` for traversing nested attribute structures
#[derive(Debug)]
pub enum AttrHandle<P> {
    /// Binary internal representation of attributes
    Bin(Vec<u8>),
    /// Rust representation of attributes
    Parsed(Vec<NlAttrHdr<P>>),
}

impl<'a, P> AttrHandle<P> where P: PartialEq + Nl + Debug {
    /// Parse a binary payload into nested attributes
    pub fn parse_nested_attributes(&mut self) -> Result<&mut AttrHandle<P>, DeError> {
        let opt_v = match *self {
            AttrHandle::Bin(ref v) => {
                let mut len = v.len();
                let mut attrs = Vec::new();
                let mut state = NlDeState::new(&v);
                while len > 0 {
                    let hdr = NlAttrHdr::<P>::deserialize(&mut state)?;
                    len -= hdr.asize();
                    attrs.push(hdr);
                }
                Some(attrs)
            },
            _ => None,
        };
        match opt_v {
            Some(v) => { *self = AttrHandle::Parsed(v); },
            None => (),
        };
        Ok(self)
    }

    /// Get the payload of an attribute as a handle for parsing nested attributes
    pub fn get_nested_attributes<S>(&mut self, payload: P) -> Result<AttrHandle<S>, DeError> {
        let nested = self.parse_nested_attributes()?.get_attribute(payload);
        match nested {
            Some(a) => Ok(AttrHandle::Bin(a.payload.clone())),
            None => Err(DeError::new("Failed to find requested attribute")),
        }
    }

    /// Get nested attributes from a parsed handle
    pub fn get_attribute(&'a self, p: P) -> Option<&'a NlAttrHdr<P>> {
        match *self {
            AttrHandle::Parsed(ref parsed) => {
                for item in parsed {
                    if item.nla_type == p {
                        return Some(&item);
                    }
                }
                None
            },
            _ => None,
        }
    }

    /// Mutably get nested attributes from a parsed handle
    pub fn get_attribute_mut(&'a mut self, p: P) -> Option<&'a mut NlAttrHdr<P>> {
        match *self {
            AttrHandle::Parsed(ref mut parsed) => {
                for item in parsed {
                    if item.nla_type == p {
                        return Some(item);
                    }
                }
                None
            },
            _ => None,
        }
    }

    /// Parse binary payload as a type that implements `Nl`
    pub fn get_payload_as<T>(&mut self, attr: P) -> Result<T, DeError> where T: Nl {
        match self.parse_nested_attributes()?.get_attribute(attr) {
            Some(ref a) => {
                let mut state = NlDeState::new(&a.payload);
                T::deserialize(&mut state)
            },
            _ => Err(DeError::new("Failed to find specified attribute")),
        }
    }
}

/// Struct representing generic netlink header and payload
#[derive(Debug,PartialEq)]
pub struct GenlHdr {
    /// Generic netlink message command
    pub cmd: GenlCmds,
    /// Version of generic netlink family protocol
    pub version: u8,
    reserved: u16,
    /// Attributes included in generic netlink message
    attrs: Vec<u8>,
}

impl GenlHdr {
    /// Create new generic netlink packet
    pub fn new<T>(cmd: GenlCmds, version: u8, mut attrs: Vec<NlAttrHdr<T>>) -> Result<Self, SerError>
                  where T: Nl {
        let mut state = NlSerState::new();
        for item in attrs.iter_mut() {
            item.serialize(&mut state)?
        }
        Ok(GenlHdr {
            cmd,
            version,
            reserved: 0,
            attrs: state.into_inner(),
        })
    }

    /// Get handle for attribute parsing and traversal
    pub fn get_attr_handle<T>(&self) -> AttrHandle<T> {
        AttrHandle::Bin(self.attrs.clone())
    }
}

impl Default for GenlHdr {
    fn default() -> Self {
        GenlHdr {
            cmd: GenlCmds::CmdUnspec,
            version: 0,
            reserved: 0,
            attrs: Vec::new(),
        }
    }
}

impl Nl for GenlHdr {
    fn serialize(&mut self, state: &mut NlSerState) -> Result<(), SerError> {
        self.cmd.serialize(state)?;
        self.version.serialize(state)?;
        self.reserved.serialize(state)?;
        self.attrs.serialize(state)?;
        Ok(())
    }

    fn deserialize(state: &mut NlDeState) -> Result<Self, DeError> {
        let mut genl = GenlHdr::default();
        genl.cmd = GenlCmds::deserialize(state)?;
        genl.version = u8::deserialize(state)?;
        genl.reserved = u16::deserialize(state)?;
        genl.attrs = Vec::<u8>::deserialize(state)?;
        Ok(genl)
    }

    fn size(&self) -> usize {
        self.cmd.size() + self.version.size() + self.reserved.size()
            + self.attrs.size()
    }
}

/// Struct representing netlink attributes and payloads
#[derive(Debug,PartialEq)]
pub struct NlAttrHdr<T> {
    /// Length of the attribute header and payload together
    pub nla_len: u16,
    /// Enum representing the type of the attribute payload
    pub nla_type: T,
    /// Payload of the attribute - either parsed or a binary buffer
    pub payload: Vec<u8>,
}

impl<T> NlAttrHdr<T> where T: Nl {
    /// Create new netlink attribute with a payload
    pub fn new_binary_payload(nla_len: Option<u16>, nla_type: T, payload: Vec<u8>)
            -> Result<Self, SerError> {
        let mut nla = NlAttrHdr::default();
        nla.nla_type = nla_type;
        nla.payload = payload;
        nla.nla_len = nla_len.unwrap_or(nla.size() as u16);
        Ok(nla)
    }

    /// Create new netlink attribute with a nested payload
    pub fn new_nested<P>(nla_len: Option<u16>, nla_type: T, mut payload: Vec<NlAttrHdr<P>>)
            -> Result<Self, SerError> where P: Nl {
        let mut nla = NlAttrHdr::default();
        nla.nla_type = nla_type;
        let mut state = NlSerState::new();
        for item in payload.iter_mut() {
            item.serialize(&mut state)?
        }
        nla.payload = state.into_inner();
        nla.nla_len = nla_len.unwrap_or(nla.size() as u16);
        Ok(nla)
    }
}

impl<T> Default for NlAttrHdr<T> where T: Default {
    fn default() -> Self {
        NlAttrHdr {
            nla_len: 0,
            nla_type: T::default(),
            payload: Vec::new(),
        }
    }
}

impl<T> Nl for NlAttrHdr<T> where T: Default + Nl {
    fn serialize(&mut self, state: &mut NlSerState) -> Result<(), SerError> {
        self.nla_len.serialize(state)?;
        self.nla_type.serialize(state)?;
        self.payload.serialize(state)?;
        Ok(())
    }

    fn deserialize(state: &mut NlDeState) -> Result<Self, DeError> {
        let mut nla = NlAttrHdr::default();
        nla.nla_len = u16::deserialize(state)?;
        nla.nla_type = T::deserialize(state)?;
        state.set_usize(nla.nla_len as usize);
        nla.payload = Vec::<u8>::deserialize(state)?;
        Ok(nla)
    }

    fn size(&self) -> usize {
        self.nla_len.size() + self.nla_type.size() + self.payload.size()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use byteorder::{NativeEndian,WriteBytesExt};
    use std::io::{Cursor,Write};
    use ffi::NlaType;

    #[test]
    pub fn test_serialize() {
        let attr = vec![NlAttrHdr::new_binary_payload(None, NlaType::AttrFamilyId,
                                                        vec![0, 1, 2, 3, 4, 5, 0, 0]
                                                      ).unwrap()];
        let mut genl = GenlHdr::new(GenlCmds::CmdGetops, 2,
                                    attr).unwrap();
        let mut state = NlSerState::new();
        genl.serialize(&mut state).unwrap();
        let v = Vec::with_capacity(genl.asize());
        let v_final = {
            let mut c = Cursor::new(v);
            c.write_u8(GenlCmds::CmdGetops.into()).unwrap();
            c.write_u8(2).unwrap();
            c.write_u16::<NativeEndian>(0).unwrap();
            c.write_u16::<NativeEndian>(12).unwrap();
            c.write_u16::<NativeEndian>(NlaType::AttrFamilyId.into()).unwrap();
            c.write_all(&vec![0, 1, 2, 3, 4, 5, 0, 0]).unwrap();
            c.into_inner()
        };
        assert_eq!(&state.into_inner(), &v_final)
    }

    #[test]
    pub fn test_deserialize() {
        let genl_mock = GenlHdr::new(GenlCmds::CmdGetops, 2,
                                     vec![NlAttrHdr::new_binary_payload(None,
                                            NlaType::AttrFamilyId, vec![0, 1, 2, 3, 4, 5, 0, 0]
                                        ).unwrap()]
                                     ).unwrap();
        let v = Vec::new();
        let v_final = {
            let mut c = Cursor::new(v);
            c.write_u8(GenlCmds::CmdGetops.into()).unwrap();
            c.write_u8(2).unwrap();
            c.write_u16::<NativeEndian>(0).unwrap();
            c.write_u16::<NativeEndian>(12).unwrap();
            c.write_u16::<NativeEndian>(NlaType::AttrFamilyId.into()).unwrap();
            c.write(&vec![0, 1, 2, 3, 4, 5, 0, 0]).unwrap();
            c.into_inner()
        };
        let mut state = NlDeState::new(&v_final);
        let genl = GenlHdr::deserialize(&mut state).unwrap();
        assert_eq!(genl, genl_mock)
    }
}
