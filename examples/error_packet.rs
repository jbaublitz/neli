use std::error::Error;

use neli::{consts::socket::NlFamily, err::NlError, genl::Genlmsghdr, socket::NlSocketHandle};

fn main() -> Result<(), Box<dyn Error>> {
    // Create a socket and connect to generic netlink.
    let mut sock = NlSocketHandle::connect(NlFamily::Generic, None, &[])?;
    // Attempt to resolve a multicast group that should not exist.
    let error = sock.resolve_nl_mcast_group("not_a", "group");
    match error {
        Ok(_) => panic!("Should not succeed"),
        Err(NlError::Nlmsgerr(e)) => {
            // Check to make sure that the returned payload in the
            // error packet can be parsed as a generic netlink message.
            assert!(e.nlmsg.get_payload_as::<Genlmsghdr<u8, u16>>().is_ok());
        }
        Err(_) => panic!("Should not return any error other than NlError"),
    };
    Ok(())
}
