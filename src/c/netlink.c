#include<stdint.h>

#include<linux/netlink.h>

uint32_t netlink_route = NETLINK_ROUTE;
uint32_t netlink_unused = NETLINK_UNUSED;
uint32_t netlink_usersock = NETLINK_USERSOCK;
uint32_t netlink_firewall = NETLINK_FIREWALL;
uint32_t netlink_sock_diag = NETLINK_SOCK_DIAG;
uint32_t netlink_nflog = NETLINK_NFLOG;
uint32_t netlink_xfrm = NETLINK_XFRM;
uint32_t netlink_selinux = NETLINK_SELINUX;
uint32_t netlink_iscsi = NETLINK_ISCSI;
uint32_t netlink_audit = NETLINK_AUDIT;
uint32_t netlink_fib_lookup = NETLINK_FIB_LOOKUP;
uint32_t netlink_connector = NETLINK_CONNECTOR;
uint32_t netlink_netfilter = NETLINK_NETFILTER;
uint32_t netlink_ip6_fw = NETLINK_IP6_FW;
uint32_t netlink_dnrtmsg = NETLINK_DNRTMSG;
uint32_t netlink_kobject_uevent = NETLINK_KOBJECT_UEVENT;
uint32_t netlink_generic = NETLINK_GENERIC;
uint32_t netlink_scsitransport = NETLINK_SCSITRANSPORT;
uint32_t netlink_ecryptfs = NETLINK_ECRYPTFS;
uint32_t netlink_rdma = NETLINK_RDMA;
uint32_t netlink_crypto = NETLINK_CRYPTO;

uint16_t nlm_f_request = NLM_F_REQUEST;
uint16_t nlm_f_multi = NLM_F_MULTI;
uint16_t nlm_f_ack = NLM_F_ACK;
uint16_t nlm_f_echo = NLM_F_ECHO;
uint16_t nlm_f_dump_intr = NLM_F_DUMP_INTR;
uint16_t nlm_f_dump_filtered = NLM_F_DUMP_FILTERED;

uint16_t nlm_f_root = NLM_F_ROOT;
uint16_t nlm_f_match = NLM_F_MATCH;
uint16_t nlm_f_atomic = NLM_F_ATOMIC;
uint16_t nlm_f_dump = NLM_F_DUMP;

uint16_t nlm_f_replace = NLM_F_REPLACE;
uint16_t nlm_f_excl = NLM_F_EXCL;
uint16_t nlm_f_create = NLM_F_CREATE;
uint16_t nlm_f_append = NLM_F_APPEND;
