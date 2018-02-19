use {Nl,NlSerState,NlDeState,SerError,DeError};
use ffi::CtrlCmd;
use nlhdr::{NlAttrHdr,AttrHandle};

/// Struct representing generic netlink header and payload
#[derive(Debug,PartialEq)]
pub struct GenlHdr {
    /// Generic netlink message command
    pub cmd: CtrlCmd,
    /// Version of generic netlink family protocol
    pub version: u8,
    reserved: u16,
    /// Attributes included in generic netlink message
    attrs: Vec<u8>,
}

impl GenlHdr {
    /// Create new generic netlink packet
    pub fn new<T>(cmd: CtrlCmd, version: u8, mut attrs: Vec<NlAttrHdr<T>>) -> Result<Self, SerError>
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
            cmd: CtrlCmd::Unspec,
            version: 0,
            reserved: 0,
            attrs: Vec::new(),
        }
    }
}

impl Nl for GenlHdr {
    fn serialize(&self, state: &mut NlSerState) -> Result<(), SerError> {
        self.cmd.serialize(state)?;
        self.version.serialize(state)?;
        self.reserved.serialize(state)?;
        self.attrs.serialize(state)?;
        Ok(())
    }

    fn deserialize(state: &mut NlDeState) -> Result<Self, DeError> {
        let mut genl = GenlHdr::default();
        genl.cmd = CtrlCmd::deserialize(state)?;
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

#[cfg(test)]
mod test {
    use super::*;
    use byteorder::{NativeEndian,WriteBytesExt};
    use std::io::{Cursor,Write};
    use ffi::CtrlAttr;

    #[test]
    pub fn test_serialize() {
        let attr = vec![NlAttrHdr::new_binary_payload(None, CtrlAttr::FamilyId,
                                                        vec![0, 1, 2, 3, 4, 5, 0, 0]
                                                      )];
        let genl = GenlHdr::new(CtrlCmd::Getops, 2,
                                    attr).unwrap();
        let mut state = NlSerState::new();
        genl.serialize(&mut state).unwrap();
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
        assert_eq!(&state.into_inner(), &v_final)
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
        let mut state = NlDeState::new(&v_final);
        let genl = GenlHdr::deserialize(&mut state).unwrap();
        assert_eq!(genl, genl_mock)
    }
}
