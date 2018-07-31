use libc;

/// Struct representing route netlink top level headers
pub struct RtAttr {
    /// Length of the attribute
    pub rta_len: libc::c_ushort,
    /// Type of the attribute
    pub rta_type: libc::c_ushort,
}
