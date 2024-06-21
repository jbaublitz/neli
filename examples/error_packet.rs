use std::error::Error;

use neli::{
    consts::socket::NlFamily, err::RouterError, router::synchronous::NlRouter, utils::Groups,
};

fn main() -> Result<(), Box<dyn Error>> {
    // Create a socket and connect to generic netlink.
    let (sock, _) = NlRouter::connect(NlFamily::Generic, None, Groups::empty())?;
    // Attempt to resolve a multicast group that should not exist.
    let error = sock.resolve_nl_mcast_group("not_a", "group");
    match error {
        Ok(_) => panic!("Should not succeed"),
        Err(RouterError::Nlmsgerr(e)) => {
            // Should be packet that caused error
            println!("{e:?}");
        }
        Err(_) => panic!("Should not return any error other than NlError"),
    };
    Ok(())
}
