macro_rules! impl_var {
    ( $name:ident, $ty:ty, $from_str:tt; $( $var:ident => $val:ident ),* ) => (
        #[derive(Clone,Debug,Eq,PartialEq,Serialize,Deserialize)]
        #[serde(from=$from_str)]
        pub enum $name {
            $( $var, )*
        }

        impl From<$name> for $ty {
            fn from(v: $name) -> Self {
                match v {
                    $( $name::$var => unsafe { $val }, )*
                }
            }
        }

        impl From<$ty> for $name {
            fn from(v: $ty) -> Self {
                match v {
                    $( i if i == unsafe { $val } => $name::$var, )*
                    _ => unimplemented!(),
                }
            }
        }
    );
}

#[link(name = "netlink")]
extern {
    /// Values for nl_family in `NlSocket`
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

    /// Values for nl_type in `NlHdr`
    pub static nlmsg_noop: u16;
    pub static nlmsg_error: u16;
    pub static nlmsg_done: u16;
    pub static nlmsg_overrun: u16;

    /// Values for nl_flags in `NlHdr`
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
}

impl_var!(NlFamily, u32, "u32";
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

impl_var!(NlType, u16, "u16";
    NlNoop => nlmsg_noop,
    NlError => nlmsg_error,
    NlDone => nlmsg_done,
    NlOverrun => nlmsg_overrun
);

impl_var!(NlFlags, u16, "u16";
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

#[cfg(test)]
mod test {
    use super::*;
    use serde::Deserialize;
    use de::NlDeserializer;

    #[test]
    fn test_flags() {
        assert_eq!(unsafe { nlm_f_request }, 1);
        assert_eq!(unsafe { nlm_f_multi }, 2);
        assert_eq!(unsafe { nlm_f_ack }, 4);
    }

    #[test]
    fn test_enum_serde() {
        let mut de = NlDeserializer::new(&[1, 0, 0, 0]);
        let v = match NlFamily::deserialize(&mut de) {
            Ok(val) => val,
            _ => panic!(),
        };
        assert_eq!(v, NlFamily::NlUnused);
    }
}
