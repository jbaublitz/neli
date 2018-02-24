use std::mem;
use libc;

use {Nl,NlSerState,NlDeState};
use err::{SerError,DeError};

macro_rules! eval_safety {
    (unsafe $expr:expr) => { unsafe { $expr } };
    (safe $expr:expr) => { $expr };
}

macro_rules! impl_var {
    ( $name:ident, $ty:ty, $var_def:ident => $val_def:expr,
      $( $var:ident => $val:expr ),* ) => (
          impl_var!($name, $ty, safe, $var_def => $val_def,
            $( $var => $val ),* );
      );

    ( $name:ident, $ty:ty, $safety:ident, $var_def:ident => $val_def:expr,
      $( $var:ident => $val:expr ),* ) => (
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
            UnrecognizedVariant($ty),
        }

        impl From<$ty> for $name {
            fn from(v: $ty) -> Self {
                match v {
                    i if i == eval_safety!{ $safety $val_def } => $name::$var_def,
                    $( i if i == eval_safety!{ $safety $val } => $name::$var,)*
                    i => $name::UnrecognizedVariant(i)
                }
            }
        }

        impl From<$name> for $ty {
            fn from(v: $name) -> Self {
                match v {
                    $name::$var_def => eval_safety!{ $safety $val_def },
                    $( $name::$var => eval_safety!{ $safety $val }, )*
                    $name::UnrecognizedVariant(i) => i,
                }
            }
        }

        impl Nl for $name {
            fn serialize(&self, state: &mut NlSerState) -> Result<(), SerError> {
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
impl_var!(NlFamily, libc::c_int,
    Route => libc::NETLINK_ROUTE,
    Unused => libc::NETLINK_UNUSED,
    Usersock => libc::NETLINK_USERSOCK,
    Firewall => libc::NETLINK_FIREWALL,
    SockOrInetDiag => libc::NETLINK_SOCK_DIAG,
    Nflog => libc::NETLINK_NFLOG,
    Xfrm => libc::NETLINK_XFRM,
    Selinux => libc::NETLINK_SELINUX,
    Iscsi => libc::NETLINK_ISCSI,
    Audit => libc::NETLINK_AUDIT,
    FibLookup => libc::NETLINK_FIB_LOOKUP,
    Connector => libc::NETLINK_CONNECTOR,
    Netfilter => libc::NETLINK_NETFILTER,
    Ip6Fw => libc::NETLINK_IP6_FW,
    Dnrtmsg => libc::NETLINK_DNRTMSG,
    KobjectUevent => libc::NETLINK_KOBJECT_UEVENT,
    Generic => libc::NETLINK_GENERIC,
    Scsitransport => libc::NETLINK_SCSITRANSPORT,
    Ecryptfs => libc::NETLINK_ECRYPTFS,
    Rdma => libc::NETLINK_RDMA,
    Crypto => libc::NETLINK_CRYPTO
);

/// Values for `nl_type` in `NlHdr`
impl_var!(Nlmsg, u16,
    Noop => libc::NLMSG_NOOP as u16,
    Error => libc::NLMSG_ERROR as u16,
    Done => libc::NLMSG_DONE as u16,
    Overrun => libc::NLMSG_OVERRUN as u16
);

/// Values for `nl_flags` in `NlHdr`
impl_var!(NlFlags, u16,
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

impl_var!(GenlId, u16, unsafe,
    Generate => genl_id_generate,
    Ctrl => genl_id_ctrl,
    VfsDquot => genl_id_vfs_dquot,
    Pmcraid => genl_id_pmcraid
);

/// Values for `cmd` in `GenlHdr`
impl_var!(CtrlCmd, u8, unsafe,
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
impl_var!(CtrlAttr, u16, unsafe,
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
impl_var!(CtrlAttrMcastGrp, u16, unsafe,
    Unspec => ctrl_attr_mcast_grp_unspec,
    Name => ctrl_attr_mcast_grp_name,
    Id => ctrl_attr_mcast_grp_id
);
