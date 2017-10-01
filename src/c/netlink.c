#include <stdint.h>

#include <linux/netlink.h>
#include <linux/genetlink.h>

const uint32_t netlink_route = NETLINK_ROUTE;
const uint32_t netlink_unused = NETLINK_UNUSED;
const uint32_t netlink_usersock = NETLINK_USERSOCK;
const uint32_t netlink_firewall = NETLINK_FIREWALL;
const uint32_t netlink_sock_diag = NETLINK_SOCK_DIAG;
const uint32_t netlink_nflog = NETLINK_NFLOG;
const uint32_t netlink_xfrm = NETLINK_XFRM;
const uint32_t netlink_selinux = NETLINK_SELINUX;
const uint32_t netlink_iscsi = NETLINK_ISCSI;
const uint32_t netlink_audit = NETLINK_AUDIT;
const uint32_t netlink_fib_lookup = NETLINK_FIB_LOOKUP;
const uint32_t netlink_connector = NETLINK_CONNECTOR;
const uint32_t netlink_netfilter = NETLINK_NETFILTER;
const uint32_t netlink_ip6_fw = NETLINK_IP6_FW;
const uint32_t netlink_dnrtmsg = NETLINK_DNRTMSG;
const uint32_t netlink_kobject_uevent = NETLINK_KOBJECT_UEVENT;
const uint32_t netlink_generic = NETLINK_GENERIC;
const uint32_t netlink_scsitransport = NETLINK_SCSITRANSPORT;
const uint32_t netlink_ecryptfs = NETLINK_ECRYPTFS;
const uint32_t netlink_rdma = NETLINK_RDMA;
const uint32_t netlink_crypto = NETLINK_CRYPTO;

const uint16_t nlmsg_noop = NLMSG_NOOP;
const uint16_t nlmsg_error = NLMSG_ERROR;
const uint16_t nlmsg_done = NLMSG_DONE;
const uint16_t nlmsg_overrun = NLMSG_OVERRUN;

const uint16_t nlm_f_request = NLM_F_REQUEST;
const uint16_t nlm_f_multi = NLM_F_MULTI;
const uint16_t nlm_f_ack = NLM_F_ACK;
const uint16_t nlm_f_echo = NLM_F_ECHO;
const uint16_t nlm_f_dump_intr = NLM_F_DUMP_INTR;

// To fix linking error for older versions of netlink
#ifdef NLM_F_DUMP_FILTERED
const uint16_t nlm_f_dump_filtered = NLM_F_DUMP_FILTERED;
#else
const uint16_t nlm_f_dump_filtered = 32;
#endif

const uint16_t nlm_f_root = NLM_F_ROOT;
const uint16_t nlm_f_match = NLM_F_MATCH;
const uint16_t nlm_f_atomic = NLM_F_ATOMIC;
const uint16_t nlm_f_dump = NLM_F_DUMP;

const uint16_t nlm_f_replace = NLM_F_REPLACE;
const uint16_t nlm_f_excl = NLM_F_EXCL;
const uint16_t nlm_f_create = NLM_F_CREATE;
const uint16_t nlm_f_append = NLM_F_APPEND;

const uint8_t ctrl_cmd_unspec = CTRL_CMD_UNSPEC;
const uint8_t ctrl_cmd_newfamily = CTRL_CMD_NEWFAMILY;
const uint8_t ctrl_cmd_delfamily = CTRL_CMD_DELFAMILY;
const uint8_t ctrl_cmd_getfamily = CTRL_CMD_GETFAMILY;
const uint8_t ctrl_cmd_newops = CTRL_CMD_NEWOPS;
const uint8_t ctrl_cmd_delops = CTRL_CMD_DELOPS;
const uint8_t ctrl_cmd_getops = CTRL_CMD_GETOPS;
const uint8_t ctrl_cmd_newmcast_grp = CTRL_CMD_NEWMCAST_GRP;
const uint8_t ctrl_cmd_delmcast_grp = CTRL_CMD_DELMCAST_GRP;
const uint8_t ctrl_cmd_getmcast_grp = CTRL_CMD_GETMCAST_GRP;
