use std::error::Error;

use neli::{
    consts::{genl::*, nl::*, socket::NlFamily},
    genl::*,
    nl::{NlPayload, Nlmsghdr},
    socket::*,
    types::GenlBuffer,
    utils::U32Bitmask,
};

fn main() -> Result<(), Box<dyn Error>> {
    // Resolve generic netlink family ID
    let family_name = "your_family_name_here";
    let mut sock = NlSocketHandle::connect(NlFamily::Generic, None, U32Bitmask::empty()).unwrap();
    let _pid = sock.get_pid().unwrap(); // resolve the pid that was affected to this socket
    let _id = sock.resolve_genl_family(family_name).unwrap();

    // Resolve generic netlink multicast group ID
    let family_name = "your_family_name_here";
    let group_name = "your_group_name_here";
    let mut sock = NlSocketHandle::connect(NlFamily::Generic, None, U32Bitmask::empty()).unwrap();
    let _id = sock
        .resolve_nl_mcast_group(family_name, group_name)
        .unwrap();

    // The following outlines how to parse netlink attributes

    // This was received from the socket
    let nlmsg = Nlmsghdr::new(
        None,
        GenlId::Ctrl,
        NlmFFlags::empty(),
        None,
        None,
        NlPayload::Payload(Genlmsghdr::new(CtrlCmd::Unspec, 2, GenlBuffer::new())),
    );
    // Get parsing handler for the attributes in this message where the next call
    // to either get_nested_attributes() or get_payload() will expect a u16 type
    // to be provided
    let mut handle = nlmsg.get_payload()?.get_attr_handle();
    // Get the nested attribute where the Nlattr field of nla_type is equal to 1 and return
    // a handler containing only this nested attribute internally
    let next = handle.get_nested_attributes::<u16>(1).unwrap();
    // Get the nested attribute where the Nlattr field of nla_type is equal to 1 and return
    // the payload of this attribute as a u32
    let _thirty_two_bit_integer = next.get_attr_payload_as::<u32>(1).unwrap();
    Ok(())
}
