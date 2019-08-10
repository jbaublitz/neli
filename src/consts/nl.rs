impl_trait!(
    /// Trait marking constants valid for use in `Nlmsghdr.nl_type`
    NlType,
    u16
);

impl_var_trait!(
    /// Values for `nl_type` in `Nlmsghdr`
    Nlmsg, u16, NlType,
    Noop => libc::NLMSG_NOOP as u16,
    Error => libc::NLMSG_ERROR as u16,
    Done => libc::NLMSG_DONE as u16,
    Overrun => libc::NLMSG_OVERRUN as u16
);

impl_var_trait!(
    /// Values for `nl_type` in `Nlmsghdr`
    GenlId, u16, NlType,
    Ctrl => libc::GENL_ID_CTRL as u16,
    #[cfg(target_env="gnu")]
    VfsDquot => libc::GENL_ID_VFS_DQUOT as u16,
    #[cfg(target_env="gnu")]
    Pmcraid => libc::GENL_ID_PMCRAID as u16
);

impl_var_trait!(
    /// rtnetlink-related values for `nl_type` in `Nlmsghdr`
    Rtm, u16, NlType,
    Newlink => libc::RTM_NEWLINK,
    Dellink => libc::RTM_DELLINK,
    Getlink => libc::RTM_GETLINK,
    Setlink => libc::RTM_SETLINK,
    Newaddr => libc::RTM_NEWADDR,
    Deladdr => libc::RTM_DELADDR,
    Getaddr => libc::RTM_GETADDR,
    Newroute => libc::RTM_NEWROUTE,
    Delroute => libc::RTM_DELROUTE,
    Getroute => libc::RTM_GETROUTE,
    Newneigh => libc::RTM_NEWNEIGH,
    Delneigh => libc::RTM_DELNEIGH,
    Getneigh => libc::RTM_GETNEIGH,
    Newrule => libc::RTM_NEWRULE,
    Delrule => libc::RTM_DELRULE,
    Getrule => libc::RTM_GETRULE,
    Newqdisc=> libc::RTM_NEWQDISC,
    Delqdisc=> libc::RTM_DELQDISC,
    Getqdisc=> libc::RTM_GETQDISC,
    Newtclass => libc::RTM_NEWTCLASS,
    Deltclass => libc::RTM_DELTCLASS,
    Gettclass => libc::RTM_GETTCLASS,
    Newtfilter => libc::RTM_NEWTFILTER,
    Deltfilter => libc::RTM_DELTFILTER,
    Gettfilter => libc::RTM_GETTFILTER,
    Newaction => libc::RTM_NEWACTION,
    Delaction => libc::RTM_DELACTION,
    Getaction => libc::RTM_GETACTION,
    Newprefix => libc::RTM_NEWPREFIX,
    Getmulticast => libc::RTM_GETMULTICAST,
    Getanycast => libc::RTM_GETANYCAST,
    Newneightbl => libc::RTM_NEWNEIGHTBL,
    Getneightbl => libc::RTM_GETNEIGHTBL,
    Setneightbl => libc::RTM_SETNEIGHTBL,
    Newnduseropt => libc::RTM_NEWNDUSEROPT,
    Newaddrlabel => libc::RTM_NEWADDRLABEL,
    Deladdrlabel => libc::RTM_DELADDRLABEL,
    Getaddrlabel => libc::RTM_GETADDRLABEL,
    Getdcb => libc::RTM_GETDCB,
    Setdcb => libc::RTM_SETDCB,
    Newnetconf => libc::RTM_NEWNETCONF,
    Getnetconf => libc::RTM_GETNETCONF,
    Newmdb => libc::RTM_NEWMDB,
    Delmdb => libc::RTM_DELMDB,
    Getmdb => libc::RTM_GETMDB,
    Newnsid => libc::RTM_NEWNSID,
    Delnsid => libc::RTM_DELNSID,
    Getnsid => libc::RTM_GETNSID
);

impl_var!(
    /// Values for `nl_flags` in `Nlmsghdr`
    NlmF, u16,
    Request => libc::NLM_F_REQUEST as u16,
    Multi => libc::NLM_F_MULTI as u16,
    Ack => libc::NLM_F_ACK as u16,
    Echo => libc::NLM_F_ECHO as u16,
    DumpIntr => libc::NLM_F_DUMP_INTR as u16,
    DumpFiltered => libc::NLM_F_DUMP_FILTERED as u16,
    Root => libc::NLM_F_ROOT as u16,
    Match => libc::NLM_F_MATCH as u16,
    Atomic => libc::NLM_F_ATOMIC as u16,
    Dump => libc::NLM_F_DUMP as u16,
    Replace => libc::NLM_F_REPLACE as u16,
    Excl => libc::NLM_F_EXCL as u16,
    Create => libc::NLM_F_CREATE as u16,
    Append => libc::NLM_F_APPEND as u16
);
