impl_trait!(
    /// Marker trait for types usable in `Nlattr.nla_type`
    NlAttrType, u16
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
