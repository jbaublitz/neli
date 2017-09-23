#[link(name = "netlink")]
extern {
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_flags() {
        assert_eq!(unsafe { nlm_f_request }, 1);
        assert_eq!(unsafe { nlm_f_multi }, 2);
        assert_eq!(unsafe { nlm_f_ack }, 4);
    }
}
