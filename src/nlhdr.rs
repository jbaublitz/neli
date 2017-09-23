use ffi::NlType;

#[derive(Serialize,Deserialize)]
pub struct NlHdr {
    nl_len: u32,
    nl_type: NlType,
    nl_flags: u16,
    nl_seq: u32,
    nl_pid: u32,
}
