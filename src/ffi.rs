use std::mem;

use {Nl,NlSerState,NlDeState};
use err::{SerError,DeError};

macro_rules! impl_var {
    ( $name:ident, $ty:ty, $var_def:ident => $val_def:ident,
      $( $var:ident => $val:ident ),* ) => (
        /// Enum representing C constants for netlink packets
        #[derive(Clone,Debug,Eq,PartialEq)]
        pub enum $name {
            #[allow(missing_docs)]
            $var_def,
            $(
                #[allow(missing_docs)]
                $var,
            )*
            /// Variant that signifies an invalid value while deserializing
            UnrecognizedVariant,
        }

        impl Default for $name {
            fn default() -> Self {
                $name::$var_def
            }
        }

        impl From<$ty> for $name {
            fn from(v: $ty) -> Self {
                match v {
                    i if i == unsafe { $val_def } => $name::$var_def,
                    $( i if i == unsafe { $val } => $name::$var,)*
                    _ => $name::UnrecognizedVariant
                }
            }
        }

        impl From<$name> for $ty {
            fn from(v: $name) -> Self {
                match v {
                    $name::$var_def => unsafe { $val_def },
                    $( $name::$var => unsafe { $val }, )*
                    $name::UnrecognizedVariant =>
                        unimplemented!("InvalidData is not a valid netlink \
                                        constant and should never be \
                                        serialized"),
                }
            }
        }

        impl Nl for $name {
            fn serialize(&mut self, state: &mut NlSerState) -> Result<(), SerError> {
                let mut v: $ty = self.clone().into();
                try!(Nl::serialize(&mut v, state));
                Ok(())
            }

            fn deserialize(state: &mut NlDeState) -> Result<Self, DeError> {
                let v: $ty = try!(<$ty as Nl>::deserialize(state));
                Ok(v.into())
            }

            fn size(&self) -> usize {
                mem::size_of::<$ty>()
            }
        }
    );
}

#[link(name = "netlink")]
extern {
    pub static nla_alignto: usize;

    pub static netlink_route: u32;
    pub static netlink_unused: u32;
    pub static netlink_usersock: u32;
    pub static netlink_firewall: u32;
    pub static netlink_sock_diag: u32;
    pub static netlink_nflog: u32;
    pub static netlink_xfrm: u32;
    pub static netlink_selinux: u32;
    pub static netlink_iscsi: u32;
    pub static netlink_audit: u32;
    pub static netlink_fib_lookup: u32;
    pub static netlink_connector: u32;
    pub static netlink_netfilter: u32;
    pub static netlink_ip6_fw: u32;
    pub static netlink_dnrtmsg: u32;
    pub static netlink_kobject_uevent: u32;
    pub static netlink_generic: u32;
    pub static netlink_scsitransport: u32;
    pub static netlink_ecryptfs: u32;
    pub static netlink_rdma: u32;
    pub static netlink_crypto: u32;

    pub static nlmsg_noop: u16;
    pub static nlmsg_error: u16;
    pub static nlmsg_done: u16;
    pub static nlmsg_overrun: u16;

    pub static nlm_f_request: u16;
    pub static nlm_f_multi: u16;
    pub static nlm_f_ack: u16;
    pub static nlm_f_echo: u16;
    pub static nlm_f_dump_intr: u16;
    pub static nlm_f_dump_filtered: u16;

    pub static nlm_f_root: u16;
    pub static nlm_f_match: u16;
    pub static nlm_f_atomic: u16;
    pub static nlm_f_dump: u16;

    pub static nlm_f_replace: u16;
    pub static nlm_f_excl: u16;
    pub static nlm_f_create: u16;
    pub static nlm_f_append: u16;

    pub static ctrl_cmd_unspec: u8;
    pub static ctrl_cmd_newfamily: u8;
    pub static ctrl_cmd_delfamily: u8;
    pub static ctrl_cmd_getfamily: u8;
    pub static ctrl_cmd_newops: u8;
    pub static ctrl_cmd_delops: u8;
    pub static ctrl_cmd_getops: u8;
    pub static ctrl_cmd_newmcast_grp: u8;
    pub static ctrl_cmd_delmcast_grp: u8;
    pub static ctrl_cmd_getmcast_grp: u8;

    pub static ctrl_attr_unspec: u16;
    pub static ctrl_attr_family_id: u16;
    pub static ctrl_attr_family_name: u16;
    pub static ctrl_attr_version: u16;
    pub static ctrl_attr_hdrsize: u16;
    pub static ctrl_attr_maxattr: u16;
    pub static ctrl_attr_ops: u16;
    pub static ctrl_attr_mcast_groups: u16;

    pub static genl_id_generate: u16;
    pub static genl_id_ctrl: u16;
    pub static genl_id_vfs_dquot: u16;
    pub static genl_id_pmcraid: u16;

    pub static ctrl_attr_mcast_grp_unspec: u16;
    pub static ctrl_attr_mcast_grp_name: u16;
    pub static ctrl_attr_mcast_grp_id: u16;
}

/// Reimplementation of alignto macro in C
pub fn alignto(len: usize) -> usize {
    (len + unsafe { nla_alignto } - 1) & !(unsafe { nla_alignto } - 1)
}

/// Values for `nl_family` in `NlSocket`
impl_var!(NlFamily, u32,
    Route => netlink_route,
    Unused => netlink_unused,
    Usersock => netlink_usersock,
    Firewall => netlink_firewall,
    SockDiag => netlink_sock_diag,
    Nflog => netlink_nflog,
    Xfrm => netlink_xfrm,
    Selinux => netlink_selinux,
    Iscsi => netlink_iscsi,
    Audit => netlink_audit,
    FibLookup => netlink_fib_lookup,
    Connector => netlink_connector,
    Netfilter => netlink_netfilter,
    Ip6Fw => netlink_ip6_fw,
    Dnrtmsg => netlink_dnrtmsg,
    KobjectUevent => netlink_kobject_uevent,
    Generic => netlink_generic,
    Scsitransport => netlink_scsitransport,
    Ecryptfs => netlink_ecryptfs,
    Rdma => netlink_rdma,
    Crypto => netlink_crypto
);

/// Values for `nl_type` in `NlHdr`
impl_var!(Nlmsg, u16,
    Noop => nlmsg_noop,
    Error => nlmsg_error,
    Done => nlmsg_done,
    Overrun => nlmsg_overrun
);

/// Values for `nl_flags` in `NlHdr`
impl_var!(NlFlags, u16,
    Request => nlm_f_request,
    Multi => nlm_f_multi,
    Ack => nlm_f_ack,
    Echo => nlm_f_echo,
    DumpIntr => nlm_f_dump_intr,
    DumpFiltered => nlm_f_dump_filtered,
    Root => nlm_f_root,
    Match => nlm_f_match,
    Atomic => nlm_f_atomic,
    Dump => nlm_f_dump,
    Replace => nlm_f_replace,
    Excl => nlm_f_excl,
    Create => nlm_f_create,
    Append => nlm_f_append
);

impl_var!(GenlId, u16,
    Generate => genl_id_generate,
    Ctrl => genl_id_ctrl,
    VfsDquot => genl_id_vfs_dquot,
    Pmcraid => genl_id_pmcraid
);

/// Values for `cmd` in `GenlHdr`
impl_var!(CtrlCmd, u8,
    Unspec => ctrl_cmd_unspec,
    Newfamily => ctrl_cmd_newfamily,
    Delfamily => ctrl_cmd_delfamily,
    Getfamily => ctrl_cmd_getfamily,
    Newops => ctrl_cmd_newops,
    Delops => ctrl_cmd_delops,
    Getops => ctrl_cmd_getops,
    NewmcastGrp => ctrl_cmd_newmcast_grp,
    DelmcastGrp => ctrl_cmd_delmcast_grp,
    GetmcastGrp => ctrl_cmd_getmcast_grp
);

/// Values for `nla_type` in `NlaAttrHdr`
impl_var!(CtrlAttr, u16,
    Unspec => ctrl_attr_unspec,
    FamilyId => ctrl_attr_family_id,
    FamilyName => ctrl_attr_family_name,
    Version => ctrl_attr_version,
    Hdrsize => ctrl_attr_hdrsize,
    Maxattr => ctrl_attr_maxattr,
    Ops => ctrl_attr_ops,
    McastGroups => ctrl_attr_mcast_groups
);

/// Values for `nla_type` in `NlaAttrHdr`
impl_var!(CtrlAttrMcastGrp, u16,
    Unspec => ctrl_attr_mcast_grp_unspec,
    Name => ctrl_attr_mcast_grp_name,
    Id => ctrl_attr_mcast_grp_id
);
