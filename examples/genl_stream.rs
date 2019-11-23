#[cfg(feature = "stream")]
extern crate futures_util;
extern crate neli;
#[cfg(feature = "stream")]
extern crate tokio;

use std::env;

#[cfg(feature = "stream")]
use futures_util::{FutureExt, StreamExt};
use neli::consts;
use neli::genl::Genlmsghdr;
use neli::socket;

#[cfg(feature = "stream")]
fn debug_stream() -> Result<(), neli::err::NlError> {
    let mut args = env::args();
    let _ = args.next();
    let first_arg = args.next();
    let second_arg = args.next();
    let (family_name, mc_group_name) = match (first_arg, second_arg) {
        (Some(fam_name), Some(mc_name)) => (fam_name, mc_name),
        (_, _) => {
            println!("USAGE: genl_stream FAMILY_NAME MULTICAST_GROUP_NAME");
            std::process::exit(1)
        }
    };
    let mut s = socket::NlSocket::connect(consts::NlFamily::Generic, None, None, true)?;
    let id = s.resolve_nl_mcast_group(&family_name, &mc_group_name)?;
    s.set_mcast_groups(vec![id])?;
    let ss = neli::socket::tokio::NlSocket::<u16, Genlmsghdr<u8, u16>>::new(s)?;
    let mut runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(
        ss.for_each(|next| {
            println!("{:?}", next);
            futures_util::future::ready(())
        })
        .map(|_| ()),
    );
    Ok(())
}

#[cfg(not(feature = "stream"))]
fn debug_stream() -> Result<(), neli::err::NlError> {
    let mut args = env::args();
    let _ = args.next();
    let first_arg = args.next();
    let second_arg = args.next();
    let (family_name, mc_group_name) = match (first_arg, second_arg) {
        (Some(fam_name), Some(mc_name)) => (fam_name, mc_name),
        (_, _) => {
            println!("USAGE: genl_stream FAMILY_NAME MULTICAST_GROUP_NAME");
            std::process::exit(1)
        }
    };
    let mut s = socket::NlSocket::connect(consts::NlFamily::Generic, None, None, true)?;
    let id = s.resolve_nl_mcast_group(&family_name, &mc_group_name)?;
    s.set_mcast_groups(vec![id])?;
    for next in s.iter::<u16, Genlmsghdr<u8, u16>>() {
        println!("{:?}", next?);
    }
    Ok(())
}

pub fn main() {
    #[cfg(feature = "stream")]
    match debug_stream() {
        Ok(_) => (),
        Err(e) => {
            println!("{}", e);
        }
    };
    #[cfg(not(feature = "stream"))]
    match debug_stream() {
        Ok(_) => (),
        Err(e) => {
            println!("{}", e);
        }
    };
}
