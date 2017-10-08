use std::mem;

use Nl;
use ffi::{GenlCmds,NlaTypes};

#[derive(Serialize,Deserialize)]
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

impl Nl for GenlHdr {
    fn size(&self) -> usize {
        self.cmd.size() + mem::size_of::<u8>() + mem::size_of::<u16>() + self.attrs.iter()
            .fold(0, |acc, val| { acc + val.size() })
    }
}

#[derive(Serialize,Deserialize)]
pub struct NlAttrHdr {
    nla_len: u16,
    nla_type: NlaTypes,
    payload: NlAttrPayload,
}

impl NlAttrHdr {
    pub fn new(nla_len: Option<u16>, nla_type: NlaTypes, payload: NlAttrPayload) -> Self {
        let mut attr = NlAttrHdr { nla_len: nla_len.unwrap_or(0), nla_type, payload };
        if let None = nla_len {
            attr.nla_len = attr.asize() as u16;
        }
        attr
    }
}

impl Nl for NlAttrHdr {
    fn size(&self) -> usize {
        mem::size_of::<u16>() + self.nla_type.size() + self.payload.size()
    }
}

#[derive(Serialize,Deserialize)]
pub enum NlAttrPayload {
    Parsed(Box<NlAttrHdr>),
    Bin(Vec<u8>),
}

impl Nl for NlAttrPayload {
    fn size(&self) -> usize {
        match *self {
            NlAttrPayload::Parsed(ref nl) => nl.size(),
            NlAttrPayload::Bin(ref v) => v.len(),
        }
    }
}

#[cfg(test)]
mod test {
    use serde::Serialize;

    use super::*;
    use ser::NlSerializer;

    #[test]
    pub fn test_serialize() {
        let mut ser = NlSerializer::new();
        let mut v = Vec::new();
        v.push(NlAttrHdr::new(None, NlaTypes::AttrUnspec, NlAttrPayload::Bin(Vec::new())));
        let gh = GenlHdr::new(GenlCmds::CmdGetfamily, 2, v);
        match gh.serialize(&mut ser) {
            Ok(_) => (),
            Err(_) => panic!(),
        };
        assert_eq!(ser.into_inner(), &[3, 2, 0, 0, 4, 0, 0, 0])
    }
}
