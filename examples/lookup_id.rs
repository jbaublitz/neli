extern crate neli;

use std::{env, error::Error};

use neli::{consts::socket::NlFamily, err::NlError, socket::NlSocketHandle};

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let mut sock = NlSocketHandle::connect(NlFamily::Generic, None, &[])?;
    let id = env::args()
        .nth(1)
        .ok_or_else(|| NlError::msg("Integer argument required"))
        .and_then(|arg| arg.parse::<u32>().map_err(|e| NlError::new(e.to_string())))?;
    let (fam, grp) = sock.lookup_id(id)?;
    println!("Family name: {}", fam);
    println!("Multicast group: {}", grp);
    Ok(())
}
