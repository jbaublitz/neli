use std::mem;

use Nl;
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

#[derive(Debug,PartialEq)]
pub struct NlAttrHdr {
    nla_len: u16,
    nla_type: NlaTypes,
    payload: NlAttrPayload,
}

#[derive(Debug,PartialEq)]
pub enum NlAttrPayload {
    Bin(Vec<u8>),
    Parsed(Box<NlAttrHdr>),
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn test_serialize() {
    }

    #[test]
    pub fn test_deserialize() {
    }
}
