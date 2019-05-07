extern crate buffering;
extern crate libc;
extern crate neli;
#[cfg(feature = "stream")]
extern crate tokio;

use neli::consts;
use neli::genl::Genlmsghdr;
use neli::socket;
#[cfg(feature = "stream")]
use tokio::prelude::{Future,Stream};

#[cfg(feature = "stream")]
fn debug_acpi_stream() -> Result<(), neli::err::NlError> {
    let mut s = socket::NlSocket::connect(consts::NlFamily::Generic,
                                          None, None, true)?;
    let id = s.resolve_nl_mcast_group("acpi_event", "acpi_mc_group")?;
    s.set_mcast_groups(vec![id])?;
    let ss = neli::socket::tokio::NlSocket::<u16, Genlmsghdr<u8>>::new(s)?;
    tokio::run(ss.for_each(|next| {
        println!("{:?}", next);
        Ok(())
    }).map(|_| ()).map_err(|_| ()));
    Ok(())
}

#[cfg(not(feature = "stream"))]
fn debug_acpi_stream() -> Result<(), neli::err::NlError> {
    let mut s = socket::NlSocket::connect(consts::NlFamily::Generic,
                                          None, None, true)?;
    let id = s.resolve_nl_mcast_group("acpi_event", "acpi_mc_group")?;
    s.set_mcast_groups(vec![id])?;
    for next in s.iter::<u16, Genlmsghdr<u8>>() {
        println!("{:?}", next);
    }
    Ok(())
}

pub fn main() {
    #[cfg(feature = "stream")]
    match debug_acpi_stream() {
        Ok(_) => (),
        Err(e) => {
            println!("{}", e);
        }
    };
    #[cfg(not(feature = "stream"))]
    match debug_acpi_stream() {
        Ok(_) => (),
        Err(e) => {
            println!("{}", e);
        }
    };
}
