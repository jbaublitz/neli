use std::{env, error::Error};

use neli::{consts::socket::NlFamily, err::MsgError, router::synchronous::NlRouter, utils::Groups};

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let (sock, _) = NlRouter::connect(NlFamily::Generic, None, Groups::empty())?;
    let id = env::args()
        .nth(1)
        .ok_or_else(|| MsgError::new("Integer argument required"))
        .and_then(|arg| arg.parse::<u32>().map_err(|e| MsgError::new(e.to_string())))?;
    let (fam, grp) = sock.lookup_id(id)?;
    println!("Family name: {fam}");
    println!("Multicast group: {grp}");
    Ok(())
}
