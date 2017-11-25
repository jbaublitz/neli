use {Nl,NlSerState,NlDeState,SerError,DeError};
use ffi::{GenlCmds,NlaTypes};

#[derive(Debug,PartialEq)]
pub struct GenlHdr {
    cmd: GenlCmds,
    version: u8,
    reserved: u16,
    attrs: Vec<NlAttrHdr>,
}

impl GenlHdr {
    pub fn new(cmd: GenlCmds, version: u8, attrs: Vec<NlAttrHdr>) -> Self {
        GenlHdr {
            cmd,
            version,
            reserved: 0,
            attrs,
        }
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
    type Input = ();

    fn serialize(&mut self, state: &mut NlSerState) -> Result<(), SerError> {
        try!(self.cmd.serialize(state));
        try!(self.version.serialize(state));
        try!(self.reserved.serialize(state));
        for mut attr in self.attrs.iter_mut() {
            try!(attr.serialize(state));
        }
        Ok(())
    }

    fn deserialize_with(state: &mut NlDeState, _input: Self::Input) -> Result<Self, DeError> {
        let mut genl = GenlHdr::default();
        genl.cmd = try!(GenlCmds::deserialize(state));
        genl.version = try!(u8::deserialize(state));
        genl.reserved = try!(u16::deserialize(state));
        while state.0.position() < state.0.get_ref().len() as u64 {
            genl.attrs.push(try!(NlAttrHdr::deserialize(state)));
        }
        Ok(genl)
    }

    fn size(&self) -> usize {
        self.cmd.size() + self.version.size() + self.reserved.size()
            + self.attrs.iter().fold(0, |acc, x| {
                acc + x.size()
            })
    }
}

#[derive(Debug,PartialEq)]
pub struct NlAttrHdr {
    nla_len: u16,
    nla_type: NlaTypes,
    payload: NlAttrPayload,
}

impl NlAttrHdr {
    pub fn new(nla_len: Option<u16>, nla_type: NlaTypes, payload: NlAttrPayload) -> Self {
        let mut nla = NlAttrHdr::default();
        nla.nla_type = nla_type;
        nla.payload = payload;
        nla.nla_len = nla_len.unwrap_or(nla.asize() as u16);
        nla
    }
}

impl Default for NlAttrHdr {
    fn default() -> Self {
        NlAttrHdr {
            nla_len: 0,
            nla_type: NlaTypes::AttrUnspec,
            payload: NlAttrPayload::Bin(Vec::new()),
        }
    }
}

impl Nl for NlAttrHdr {
    type Input = ();

    fn serialize(&mut self, state: &mut NlSerState) -> Result<(), SerError> {
        try!(self.nla_len.serialize(state));
        try!(self.nla_type.serialize(state));
        try!(self.payload.serialize(state));
        Ok(())
    }

    fn deserialize_with(state: &mut NlDeState, _input: Self::Input) -> Result<Self, DeError> {
        let mut nla = NlAttrHdr::default();
        nla.nla_len = try!(u16::deserialize(state));
        nla.nla_type = try!(NlaTypes::deserialize(state));
        nla.payload = try!(NlAttrPayload::deserialize_with(state, nla.nla_len as usize));
        Ok(nla)
    }

    fn size(&self) -> usize {
        self.nla_len.size() + self.nla_type.size() + self.payload.size()
    }
}

#[derive(Debug,PartialEq)]
pub enum NlAttrPayload {
    Bin(Vec<u8>),
    Parsed(Box<NlAttrHdr>),
}

impl Default for NlAttrPayload {
    fn default() -> Self {
        NlAttrPayload::Bin(Vec::new())
    }
}

impl Nl for NlAttrPayload {
    type Input = usize;

    fn serialize(&mut self, state: &mut NlSerState) -> Result<(), SerError> {
        match *self {
            NlAttrPayload::Bin(ref mut v) => try!(v.serialize(state)),
            NlAttrPayload::Parsed(ref mut p) => try!(p.serialize(state)),
        };
        Ok(())
    }

    fn deserialize_with(state: &mut NlDeState, size: Self::Input) -> Result<Self, DeError> {
        Ok(NlAttrPayload::Bin(try!(Vec::<u8>::deserialize_with(state, size))))
    }

    fn size(&self) -> usize {
        match *self {
            NlAttrPayload::Bin(ref v) => v.len(),
            NlAttrPayload::Parsed(ref p) => p.size(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use byteorder::{NativeEndian,WriteBytesExt};
    use std::io::{Cursor,Write};

    #[test]
    pub fn test_serialize() {
        let mut genl = GenlHdr::new(GenlCmds::CmdGetops, 2,
                                    vec![NlAttrHdr::new(None, NlaTypes::AttrFamilyId,
                                                        NlAttrPayload::Bin(
                                                            vec![0, 1, 2, 3, 4, 5]
                                                        ))]);
        let mut state = NlSerState::new();
        genl.serialize(&mut state).unwrap();
        let v = Vec::with_capacity(genl.asize());
        let v_final = {
            let mut c = Cursor::new(v);
            c.write_u8(GenlCmds::CmdGetops.into()).unwrap();
            c.write_u8(2).unwrap();
            c.write_u16::<NativeEndian>(0).unwrap();
            c.write_u16::<NativeEndian>(12).unwrap();
            c.write_u16::<NativeEndian>(NlaTypes::AttrFamilyId.into()).unwrap();
            c.write_all(&vec![0, 1, 2, 3, 4, 5]).unwrap();
            c.into_inner()
        };
        assert_eq!(&state.into_inner(), &v_final)
    }

    #[test]
    pub fn test_deserialize() {
        let genl_mock = GenlHdr::new(GenlCmds::CmdGetops, 2,
                                    vec![NlAttrHdr::new(None, NlaTypes::AttrFamilyId,
                                                        NlAttrPayload::Bin(
                                                            vec![0, 1, 2, 3, 4, 5]
                                                        ))]);
        let v = Vec::with_capacity(genl_mock.asize());
        let v_final = {
            let mut c = Cursor::new(v);
            c.write_u8(GenlCmds::CmdGetops.into()).unwrap();
            c.write_u8(2).unwrap();
            c.write_u16::<NativeEndian>(0).unwrap();
            c.write_u16::<NativeEndian>(12).unwrap();
            c.write_u16::<NativeEndian>(NlaTypes::AttrFamilyId.into()).unwrap();
            c.write_all(&vec![0, 1, 2, 3, 4, 5]).unwrap();
            c.into_inner()
        };
        let mut state = NlDeState::new(&v_final);
        let genl = GenlHdr::deserialize(&mut state).unwrap();
        assert_eq!(genl, genl_mock)
    }
}
