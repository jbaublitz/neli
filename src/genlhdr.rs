use ffi::GenlCmds;

#[derive(Serialize,Deserialize)]
pub struct GenlHdr {
    cmd: GenlCmds,
    version: u8,
    reserved: u16,
    
}

impl GenlHdr {
    pub fn new(cmd: GenlCmds, version: u8) -> Self {
        GenlHdr {
            cmd,
            version,
            reserved: 0,
        }
    }
}
