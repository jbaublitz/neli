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
        try!(<GenlCmds as Nl>::serialize(&mut self.cmd, state));
        try!(<u8 as Nl>::serialize(&mut self.version, state));
        try!(<u16 as Nl>::serialize(&mut self.reserved, state));
        for mut attr in self.attrs.iter_mut() {
            try!(<NlAttrHdr as Nl>::serialize(&mut attr, state));
        }
        Ok(())
    }

    fn deserialize_with(state: &mut NlDeState, _input: Self::Input) -> Result<Self, DeError> {
        let mut genl = GenlHdr::default();
        genl.cmd = try!(<GenlCmds as Nl>::deserialize(state));
        genl.version = try!(<u8 as Nl>::deserialize(state));
        genl.reserved = try!(<u16 as Nl>::deserialize(state));
        while state.0.position() < state.0.get_ref().len() as u64 {
            genl.attrs.push(try!(<NlAttrHdr as Nl>::deserialize(state)));
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
        nla.nla_len = nla_len.unwrap_or(nla.size() as u16);
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
        try!(<u16 as Nl>::serialize(&mut self.nla_len, state));
        try!(<NlaTypes as Nl>::serialize(&mut self.nla_type, state));
        try!(<NlAttrPayload as Nl>::serialize(&mut self.payload, state));
        Ok(())
    }

    fn deserialize_with(state: &mut NlDeState, _input: Self::Input) -> Result<Self, DeError> {
        let mut nla = NlAttrHdr::default();
        nla.nla_len = try!(<u16 as Nl>::deserialize(state));
        nla.nla_type = try!(<NlaTypes as Nl>::deserialize(state));
        nla.payload = try!(<NlAttrPayload as Nl>::deserialize_with(state, nla.nla_len as usize));
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
        Ok(NlAttrPayload::Bin(try!(<Vec<u8> as Nl>::deserialize_with(state, size))))
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
    #[test]
    pub fn test_serialize() {
    }

    #[test]
    pub fn test_deserialize() {
    }
}
