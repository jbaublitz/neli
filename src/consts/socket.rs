impl_var!(
    /// General address families for sockets
    AddrFamily, libc::c_int,
    UnixOrLocal => libc::AF_UNIX,
    Inet => libc::AF_INET,
    Inet6 => libc::AF_INET6,
    Ipx => libc::AF_IPX,
    Netlink => libc::AF_NETLINK,
    X25 => libc::AF_X25,
    Ax25 => libc::AF_AX25,
    Atmpvc => libc::AF_ATMPVC,
    Appletalk => libc::AF_APPLETALK,
    Packet => libc::AF_PACKET,
    Alg => libc::AF_ALG
);

impl_var!(
    /// Values for `nl_family` in `NlSocket`
    NlFamily, libc::c_int,
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
