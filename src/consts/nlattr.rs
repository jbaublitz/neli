impl_trait!(
    /// Marker trait for types usable in `Nlattr.nla_type`
    NlAttrType,
    u16
);

impl_var_trait!(
    /// Values for `nla_type` in `Nlattr`
    CtrlAttr, u16, NlAttrType,
    Unspec => libc::CTRL_ATTR_UNSPEC as u16,
    FamilyId => libc::CTRL_ATTR_FAMILY_ID as u16,
    FamilyName => libc::CTRL_ATTR_FAMILY_NAME as u16,
    Version => libc::CTRL_ATTR_VERSION as u16,
    Hdrsize => libc::CTRL_ATTR_HDRSIZE as u16,
    Maxattr => libc::CTRL_ATTR_MAXATTR as u16,
    Ops => libc::CTRL_ATTR_OPS as u16,
    McastGroups => libc::CTRL_ATTR_MCAST_GROUPS as u16
);

impl_var_trait!(
    /// Values for `nla_type` in `Nlattr`
    CtrlAttrMcastGrp, u16, NlAttrType,
    Unspec => libc::CTRL_ATTR_MCAST_GRP_UNSPEC as u16,
    Name => libc::CTRL_ATTR_MCAST_GRP_NAME as u16,
    Id => libc::CTRL_ATTR_MCAST_GRP_ID as u16
);

/// Type representing attribute list types as indices
#[derive(PartialEq)]
pub struct Index(u16);

impl Into<u16> for Index {
    fn into(self) -> u16 {
        self.0
    }
}

impl From<u16> for Index {
    fn from(v: u16) -> Self {
        Index(v)
    }
}

impl crate::Nl for Index {
    fn serialize(&self, buf: &mut crate::StreamWriteBuffer) -> Result<(), crate::SerError> {
        self.0.serialize(buf)?;
        Ok(())
    }

    fn deserialize<B>(buf: &mut crate::StreamReadBuffer<B>) -> Result<Self, crate::DeError>
    where
        B: AsRef<[u8]>,
    {
        Ok(Index(u16::deserialize(buf)?))
    }

    fn size(&self) -> usize {
        std::mem::size_of::<u16>()
    }
}

impl NlAttrType for Index {}
