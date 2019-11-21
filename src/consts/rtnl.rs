impl_var!(
    /// Internet address families
    Af, libc::c_uchar,
    Inet => libc::AF_INET as libc::c_uchar,
    Inet6 => libc::AF_INET6 as libc::c_uchar
);

impl_var!(
    /// General address families for sockets
    RtAddrFamily, u8,
    Unspecified => libc::AF_UNSPEC as u8,
    UnixOrLocal => libc::AF_UNIX as u8,
    Inet => libc::AF_INET as u8,
    Inet6 => libc::AF_INET6 as u8,
    Ipx => libc::AF_IPX as u8,
    Netlink => libc::AF_NETLINK as u8,
    X25 => libc::AF_X25 as u8,
    Ax25 => libc::AF_AX25 as u8,
    Atmpvc => libc::AF_ATMPVC as u8,
    Appletalk => libc::AF_APPLETALK as u8,
    Packet => libc::AF_PACKET as u8,
    Alg => libc::AF_ALG as u8
);

impl_var!(
    /// Interface address flags
    IfaF, u32,
    Secondary => libc::IFA_F_SECONDARY,
    Temporary => libc::IFA_F_TEMPORARY,
    Nodad => libc::IFA_F_NODAD,
    Optimistic => libc::IFA_F_OPTIMISTIC,
    Dadfailed => libc::IFA_F_DADFAILED,
    Homeaddress => libc::IFA_F_HOMEADDRESS,
    Deprecated => libc::IFA_F_DEPRECATED,
    Tentative => libc::IFA_F_TENTATIVE,
    Permanent => libc::IFA_F_PERMANENT,
    #[cfg(target_env="gnu")]
    Managetempaddr => libc::IFA_F_MANAGETEMPADDR,
    #[cfg(target_env="gnu")]
    Noprefixroute => libc::IFA_F_NOPREFIXROUTE,
    #[cfg(target_env="gnu")]
    Mcautojoin => libc::IFA_F_MCAUTOJOIN,
    #[cfg(target_env="gnu")]
    StablePrivacy => libc::IFA_F_STABLE_PRIVACY
);

impl_var!(
    /// `rtm_type`
    /// The results of a lookup from a route table
    Rtn, libc::c_uchar,
    Unspec => libc::RTN_UNSPEC,
    Unicast => libc::RTN_UNICAST,
    Local => libc::RTN_LOCAL,
    Broadcast => libc::RTN_BROADCAST,
    Anycast => libc::RTN_ANYCAST,
    Multicast => libc::RTN_MULTICAST,
    Blackhole => libc::RTN_BLACKHOLE,
    Unreachable => libc::RTN_UNREACHABLE,
    Prohibit => libc::RTN_PROHIBIT,
    Throw => libc::RTN_THROW,
    Nat => libc::RTN_NAT,
    Xresolve => libc::RTN_XRESOLVE
);

impl_var!(
    /// `rtm_protocol`
    /// The origins of routes that are defined in the kernel
    Rtprot, libc::c_uchar,
    Unspec => libc::RTPROT_UNSPEC,
    Redirect => libc::RTPROT_REDIRECT,
    Kernel => libc::RTPROT_KERNEL,
    Boot => libc::RTPROT_BOOT,
    Static => libc::RTPROT_STATIC
);

impl_var!(
    /// `rtm_scope`
    /// The distance between destinations
    RtScope, libc::c_uchar,
    Universe => libc::RT_SCOPE_UNIVERSE,
    Site => libc::RT_SCOPE_SITE,
    Link => libc::RT_SCOPE_LINK,
    Host => libc::RT_SCOPE_HOST,
    Nowhere => libc::RT_SCOPE_NOWHERE
);

impl_var!(
    /// `rt_class_t`
    /// Reserved route table identifiers
    RtTable, libc::c_uchar,
    Unspec => libc::RT_TABLE_UNSPEC,
    Compat => libc::RT_TABLE_COMPAT,
    Default => libc::RT_TABLE_DEFAULT,
    Main => libc::RT_TABLE_MAIN,
    Local => libc::RT_TABLE_LOCAL
);

impl_var!(
    /// `rtm_flags`
    /// Flags for rtnetlink messages
    RtmF, libc::c_uint,
    Notify => libc::RTM_F_NOTIFY,
    Cloned => libc::RTM_F_CLONED,
    Equalize => libc::RTM_F_EQUALIZE,
    Prefix => libc::RTM_F_PREFIX,

    #[cfg(target_env="gnu")]
    LookupTable => libc::RTM_F_LOOKUP_TABLE,
    #[cfg(target_env="gnu")]
    FibMatch => libc::RTM_F_FIB_MATCH
);

impl_var!(
    /// Arp neighbor cache entry states
    Nud, u16,
    None => libc::NUD_NONE,
    Incomplete => libc::NUD_INCOMPLETE,
    Reachable => libc::NUD_REACHABLE,
    Stale => libc::NUD_STALE,
    Delay => libc::NUD_DELAY,
    Probe => libc::NUD_PROBE,
    Failed => libc::NUD_FAILED,
    Noarp => libc::NUD_NOARP,
    Permanent => libc::NUD_PERMANENT
);

impl_var!(
    /// Arp neighbor cache entry flags
    Ntf, u8,
    Use => libc::NTF_USE,
    Self_ => libc::NTF_SELF,
    Master => libc::NTF_MASTER,
    Proxy => libc::NTF_PROXY,
    #[cfg(target_env="gnu")]
    ExtLearned => libc::NTF_EXT_LEARNED,
    #[cfg(target_env="gnu")]
    Offloaded => libc::NTF_OFFLOADED,
    Router => libc::NTF_ROUTER
);

impl_trait!(
    /// Marker trait for `Rtattr.rta_type` field
    RtaType,
    libc::c_ushort
);

impl_var_trait!(
    /// Enum for use with `Rtattr.rta_type`.
    /// Values are interface information message attributes. Used with `Ifinfomsg`.
    Ifla, libc::c_ushort, RtaType,
    Unspec => libc::IFLA_UNSPEC,
    Address => libc::IFLA_ADDRESS,
    Broadcast => libc::IFLA_BROADCAST,
    Ifname => libc::IFLA_IFNAME,
    Mtu => libc::IFLA_MTU,
    Link => libc::IFLA_LINK,
    Qdisc => libc::IFLA_QDISC,
    Stats => libc::IFLA_STATS,
    Cost => libc::IFLA_COST,
    Priority => libc::IFLA_PRIORITY,
    Master => libc::IFLA_MASTER,
    Wireless => libc::IFLA_WIRELESS,
    Protinfo => libc::IFLA_PROTINFO,
    Txqlen => libc::IFLA_TXQLEN,
    Map => libc::IFLA_MAP,
    Weight => libc::IFLA_WEIGHT,
    Operstate => libc::IFLA_OPERSTATE,
    Linkmode => libc::IFLA_LINKMODE,
    Linkinfo => libc::IFLA_LINKINFO,
    NetNsPid => libc::IFLA_NET_NS_PID,
    Ifalias => libc::IFLA_IFALIAS,
    NumVf => libc::IFLA_NUM_VF,
    VfinfoList => libc::IFLA_VFINFO_LIST,
    Stats64 => libc::IFLA_STATS64,
    VfPorts => libc::IFLA_VF_PORTS,
    PortSelf => libc::IFLA_PORT_SELF,
    AfSpec => libc::IFLA_AF_SPEC,
    Group => libc::IFLA_GROUP,
    NetNsFd => libc::IFLA_NET_NS_FD,
    ExtMask => libc::IFLA_EXT_MASK,
    Promiscuity => libc::IFLA_PROMISCUITY,
    NumTxQueues => libc::IFLA_NUM_TX_QUEUES,
    NumRxQueues => libc::IFLA_NUM_RX_QUEUES,
    Carrier => libc::IFLA_CARRIER,
    PhysPortId => libc::IFLA_PHYS_PORT_ID,
    CarrierChanges => libc::IFLA_CARRIER_CHANGES,
    PhysSwitchId => libc::IFLA_PHYS_SWITCH_ID,
    LinkNetnsid => libc::IFLA_LINK_NETNSID,
    PhysPortName => libc::IFLA_PHYS_PORT_NAME,
    ProtoDown => libc::IFLA_PROTO_DOWN
);

impl_trait!(
    /// Marker trait for `Rtattr.rta_type` field
    IflaInfoType,
    libc::c_ushort
);

impl_var_trait!(
    /// Enum for use with `Rtattr.rta_type`.
    /// Values are nested attributes to IFLA_LINKMODE.
    IflaInfo, libc::c_ushort, IflaInfoType,
    Unspec => libc::IFLA_INFO_UNSPEC,
    Kind => libc::IFLA_INFO_KIND,
    Data => libc::IFLA_INFO_DATA,
    Xstats => libc::IFLA_INFO_XSTATS,
    SlaveKind => libc::IFLA_INFO_SLAVE_KIND,
    SlaveData => libc::IFLA_INFO_SLAVE_DATA
);

impl_var_trait!(
    /// Enum for use with `Rtattr.rta_type`.
    /// Values are interface address message attributes. Used with `Ifaddrmsg`.
    Ifa, libc::c_ushort, RtaType,
    Unspec => libc::IFA_UNSPEC,
    Address => libc::IFA_ADDRESS,
    Local => libc::IFA_LOCAL,
    Label => libc::IFA_LABEL,
    Broadcast => libc::IFA_BROADCAST,
    Anycast => libc::IFA_ANYCAST,
    Cacheinfo => libc::IFA_CACHEINFO,
    Multicast => libc::IFA_MULTICAST,
    #[cfg(target_env="gnu")]
    Flags => libc::IFA_FLAGS
);

impl_var_trait!(
    /// Enum for use with `Rtattr.rta_type`.
    /// Values are routing message attributes. Used with `Rtmsg`.
    Rta, libc::c_ushort, RtaType,
    Unspec => libc::RTA_UNSPEC,
    Dst => libc::RTA_DST,
    Src => libc::RTA_SRC,
    Iif => libc::RTA_IIF,
    Oif => libc::RTA_OIF,
    Gateway => libc::RTA_GATEWAY,
    Priority => libc::RTA_PRIORITY,
    Prefsrc => libc::RTA_PREFSRC,
    Metrics => libc::RTA_METRICS,
    Multipath => libc::RTA_MULTIPATH,
    Protoinfo => libc::RTA_PROTOINFO, // no longer used in Linux
    Flow => libc::RTA_FLOW,
    Cacheinfo => libc::RTA_CACHEINFO,
    Session => libc::RTA_SESSION, // no longer used in Linux
    MpAlgo => libc::RTA_MP_ALGO, // no longer used in Linux
    Table => libc::RTA_TABLE,
    Mark => libc::RTA_MARK,
    MfcStats => libc::RTA_MFC_STATS,
    #[cfg(target_env="gnu")]
    Via => libc::RTA_VIA,
    #[cfg(target_env="gnu")]
    Newdst => libc::RTA_NEWDST,
    #[cfg(target_env="gnu")]
    Pref => libc::RTA_PREF,
    #[cfg(target_env="gnu")]
    EncapType => libc::RTA_ENCAP_TYPE,
    #[cfg(target_env="gnu")]
    Encap => libc::RTA_ENCAP,
    #[cfg(target_env="gnu")]
    Expires => libc::RTA_EXPIRES,
    #[cfg(target_env="gnu")]
    Pad => libc::RTA_PAD,
    #[cfg(target_env="gnu")]
    Uid => libc::RTA_UID,
    #[cfg(target_env="gnu")]
    TtlPropagate => libc::RTA_TTL_PROPAGATE
);

impl_var_trait!(
    /// Enum for use with `Rtattr.rta_type` -
    /// Values specify queuing discipline attributes. Used with `Tcmsg`.
    Tca, libc::c_ushort, RtaType,
    Unspec => libc::TCA_UNSPEC,
    Kind => libc::TCA_KIND,
    Options => libc::TCA_OPTIONS,
    Stats => libc::TCA_STATS,
    Xstats => libc::TCA_XSTATS,
    Rate => libc::TCA_RATE,
    Fcnt => libc::TCA_FCNT,
    Stats2 => libc::TCA_STATS2,
    Stab => libc::TCA_STAB
);

impl_var_trait!(
    /// Enum for use with `Rtattr.rta_type` -
    /// Values specify neighbor table attributes
    Nda, libc::c_ushort, RtaType,
    Unspec => libc::NDA_UNSPEC,
    Dst => libc::NDA_DST,
    Lladdr => libc::NDA_LLADDR,
    Cacheinfo => libc::NDA_CACHEINFO,
    Probes => libc::NDA_PROBES,
    Vlan => libc::NDA_VLAN,
    Port => libc::NDA_PORT,
    Vni => libc::NDA_VNI,
    Ifindex => libc::NDA_IFINDEX,
    #[cfg(target_env="gnu")]
    Master => libc::NDA_MASTER,
    #[cfg(target_env="gnu")]
    LinkNetnsid => libc::NDA_LINK_NETNSID,
    #[cfg(target_env="gnu")]
    SrcVni => libc::NDA_SRC_VNI
);

impl_var!(
    /// Interface types
    Arphrd, libc::c_ushort,
    Netrom => libc::ARPHRD_NETROM,
    Ether => libc::ARPHRD_ETHER,
    Eether => libc::ARPHRD_EETHER,
    AX25 => libc::ARPHRD_AX25,
    Pronet => libc::ARPHRD_PRONET,
    Chaos => libc::ARPHRD_CHAOS,
    Ieee802 => libc::ARPHRD_IEEE802,
    Arcnet => libc::ARPHRD_ARCNET,
    Appletlk => libc::ARPHRD_APPLETLK,
    Dlci => libc::ARPHRD_DLCI,
    Atm => libc::ARPHRD_APPLETLK,
    Metricom => libc::ARPHRD_METRICOM,
    Ieee1394 => libc::ARPHRD_IEEE1394,
    Eui64 => libc::ARPHRD_EUI64,
    Infiniband => libc::ARPHRD_INFINIBAND,

    // Possibly more types here - need to look into ARP more

    Void => libc::ARPHRD_VOID,
    None => libc::ARPHRD_NONE
);

impl_var!(
    /// Values for `ifi_flags` in `Ifinfomsg`
    Iff, libc::c_uint,
    Up => libc::IFF_UP as libc::c_uint,
    Broadcast => libc::IFF_BROADCAST as libc::c_uint,
    Debug => libc::IFF_DEBUG as libc::c_uint,
    Loopback => libc::IFF_LOOPBACK as libc::c_uint,
    Pointopoint => libc::IFF_POINTOPOINT as libc::c_uint,
    Running => libc::IFF_RUNNING as libc::c_uint,
    Noarp => libc::IFF_NOARP as libc::c_uint,
    Promisc => libc::IFF_PROMISC as libc::c_uint,
    Notrailers => libc::IFF_NOTRAILERS as libc::c_uint,
    Allmulti => libc::IFF_ALLMULTI as libc::c_uint,
    Master => libc::IFF_MASTER as libc::c_uint,
    Slave => libc::IFF_SLAVE as libc::c_uint,
    Multicast => libc::IFF_MULTICAST as libc::c_uint,
    Portsel => libc::IFF_PORTSEL as libc::c_uint,
    Automedia => libc::IFF_AUTOMEDIA as libc::c_uint,
    Dynamic => libc::IFF_DYNAMIC as libc::c_uint,
    LowerUp => libc::IFF_LOWER_UP as libc::c_uint,
    Dormant => libc::IFF_DORMANT as libc::c_uint,
    Echo => libc::IFF_ECHO as libc::c_uint

    // Possibly more types here - need to look into private flags for interfaces
);
