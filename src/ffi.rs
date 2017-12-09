use std::mem;

use {Nl,NlSerState,NlDeState};
use err::{SerError,DeError};

macro_rules! impl_var {
    ( $name:ident, $ty:ty, $var_def:ident => $val_def:ident,
      $( $var:ident => $val:ident ),* ) => (
        #[derive(Clone,Debug,Eq,PartialEq)]
        pub enum $name {
            $var_def,
            $( $var, )*
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
                    _ => panic!(),
                }
            }
        }

        impl From<$name> for $ty {
            fn from(v: $name) -> Self {
                match v {
                    $name::$var_def => unsafe { $val_def },
                    $( $name::$var => unsafe { $val },)*
                }
            }
        }

        impl Nl for $name {
            type Input = ();

            fn serialize(&mut self, state: &mut NlSerState) -> Result<(), SerError> {
                let mut v: $ty = self.clone().into();
                try!(Nl::serialize(&mut v, state));
                Ok(())
            }

            fn deserialize_with(state: &mut NlDeState, _input: Self::Input)
                                -> Result<Self, DeError> {
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
}

/// Reimplementation of alignto macro in C
pub fn alignto(len: usize) -> usize {
    (len + unsafe { nla_alignto } - 1) & !(unsafe { nla_alignto } - 1)
}

/// Values for `nl_family` in `NlSocket`
impl_var!(NlFamily, u32,
    NlRoute => netlink_route,
    NlUnused => netlink_unused,
    NlUsersock => netlink_usersock,
    NlFirewall => netlink_firewall,
    NlSockDiag => netlink_sock_diag,
    NlNflog => netlink_nflog,
    NlXfrm => netlink_xfrm,
    NlSelinux => netlink_selinux,
    NlIscsi => netlink_iscsi,
    NlAudit => netlink_audit,
    NlFibLookup => netlink_fib_lookup,
    NlConnector => netlink_connector,
    NlNetfilter => netlink_netfilter,
    NlIp6Fw => netlink_ip6_fw,
    NlDnrtmsg => netlink_dnrtmsg,
    NlKobjectUevent => netlink_kobject_uevent,
    NlGeneric => netlink_generic,
    NlScsitransport => netlink_scsitransport,
    NlEcryptfs => netlink_ecryptfs,
    NlRdma => netlink_rdma,
    NlCrypto => netlink_crypto
);

/// Values for `nl_type` in `NlHdr`
impl_var!(NlType, u16,
    NlNoop => nlmsg_noop,
    NlError => nlmsg_error,
    NlDone => nlmsg_done,
    NlOverrun => nlmsg_overrun
);

/// Values for `nl_flags` in `NlHdr`
impl_var!(NlFlags, u16,
    NlRequest => nlm_f_request,
    NlMulti => nlm_f_multi,
    NlAck => nlm_f_ack,
    NlEcho => nlm_f_echo,
    NlDumpIntr => nlm_f_dump_intr,
    NlDumpFiltered => nlm_f_dump_filtered,
    NlRoot => nlm_f_root,
    NlMatch => nlm_f_match,
    NlAtomic => nlm_f_atomic,
    NlDump => nlm_f_dump,
    NlReplace => nlm_f_replace,
    NlExcl => nlm_f_excl,
    NlCreate => nlm_f_create,
    NlAppend => nlm_f_append
);

/// Values for `cmd` in `GenlHdr`
impl_var!(GenlCmds, u8,
    CmdUnspec => ctrl_cmd_unspec,
    CmdNewfamily => ctrl_cmd_newfamily,
    CmdDelfamily => ctrl_cmd_delfamily,
    CmdGetfamily => ctrl_cmd_getfamily,
    CmdNewops => ctrl_cmd_newops,
    CmdDelops => ctrl_cmd_delops,
    CmdGetops => ctrl_cmd_getops,
    CmdNewmcastGrp => ctrl_cmd_newmcast_grp,
    CmdDelmcastGrp => ctrl_cmd_delmcast_grp,
    CmdGetmcastGrp => ctrl_cmd_getmcast_grp
);

/// Values for `nla_type` in `NlaAttrHdr`
impl_var!(NlaTypes, u16,
    AttrUnspec => ctrl_attr_unspec,
    AttrFamilyId => ctrl_attr_family_id,
    AttrFamilyName => ctrl_attr_family_name,
    AttrVersion => ctrl_attr_version,
    AttrHdrsize => ctrl_attr_hdrsize,
    AttrMaxattr => ctrl_attr_maxattr,
    AttrOps => ctrl_attr_ops,
    AttrMcastGroups => ctrl_attr_mcast_groups
);
