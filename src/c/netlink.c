#include <stdint.h>

#include <linux/netlink.h>
#include <linux/genetlink.h>

const uint8_t nla_alignto = NLA_ALIGNTO;

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

const uint16_t ctrl_attr_unspec = CTRL_ATTR_UNSPEC;
const uint16_t ctrl_attr_family_id = CTRL_ATTR_FAMILY_ID;
const uint16_t ctrl_attr_family_name = CTRL_ATTR_FAMILY_NAME;
const uint16_t ctrl_attr_version = CTRL_ATTR_VERSION;
const uint16_t ctrl_attr_hdrsize = CTRL_ATTR_HDRSIZE;
const uint16_t ctrl_attr_maxattr = CTRL_ATTR_MAXATTR;
const uint16_t ctrl_attr_ops = CTRL_ATTR_OPS;
const uint16_t ctrl_attr_mcast_groups = CTRL_ATTR_MCAST_GROUPS;

#ifdef GENL_ID_GENERATE
const uint16_t genl_id_generate = GENL_ID_GENERATE;
#else
const uint16_t genl_id_generate = 0;
#endif
const uint16_t genl_id_ctrl = GENL_ID_CTRL;
const uint16_t genl_id_vfs_dquot = GENL_ID_VFS_DQUOT;
const uint16_t genl_id_pmcraid = GENL_ID_PMCRAID;

const uint16_t ctrl_attr_mcast_grp_unspec = CTRL_ATTR_MCAST_GRP_UNSPEC;
const uint16_t ctrl_attr_mcast_grp_name = CTRL_ATTR_MCAST_GRP_NAME;
const uint16_t ctrl_attr_mcast_grp_id = CTRL_ATTR_MCAST_GRP_ID;
