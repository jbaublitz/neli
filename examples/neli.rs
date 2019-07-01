extern crate neli;

use neli::consts::NlFamily;
use neli::genl::*;
use neli::socket::*;

fn main() {
    // Resolve generic netlink family ID
    let family_name = "your_family_name_here";
    let mut sock = NlSocket::connect(NlFamily::Generic, None, None).unwrap();
    let _id = sock.resolve_genl_family(family_name).unwrap();

    // Resolve generic netlink multicast group ID
    let family_name = "your_family_name_here";
    let group_name = "your_group_name_here";
    let mut sock = NlSocket::connect(NlFamily::Generic, None, None).unwrap();
    let _id = sock
        .resolve_nl_mcast_group(family_name, group_name)
        .unwrap();

    // The following outlines how to parse netlink attributes

    // This was received from the socket
    let nlmsg = neli::nl::Nlmsghdr::new(
        None,
        neli::consts::GenlId::Ctrl,
        Vec::new(),
        None,
        None,
        Genlmsghdr::new(neli::consts::CtrlCmd::Unspec, 2, Vec::new()).unwrap(),
    );
    // Get parsing handler for the attributes in this message where the next call
    // to either get_nested_attributes() or get_payload() will expect a u16 type
    // to be provided
    let mut handle = nlmsg.nl_payload.get_attr_handle();
    // Get the nested attribute where the Nlattr field of nla_type is equal to 1 and return
    // a handler containing only this nested attribute internally
    let next = handle.get_nested_attributes::<u16>(1).unwrap();
    // Get the nested attribute where the Nlattr field of nla_type is equal to 1 and return
    // the payload of this attribute as a u32
    let _thirty_two_bit_integer = next.get_attr_payload_as::<u32>(1).unwrap();
}
