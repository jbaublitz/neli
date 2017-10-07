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

#[derive(Serialize,Deserialize)]
pub struct NlAttrHdr {
    nla_len: u16,
    nla_type: NlaTypes,
}

impl NlAttrHdr {
    pub fn new(nla_len: u16, nla_type: NlaTypes) -> Self {
        NlAttrHdr { nla_len, nla_type }
    }
}
