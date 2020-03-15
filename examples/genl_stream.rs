use std::{env, error::Error};

use neli::{consts, genl::Genlmsghdr, socket};
#[cfg(feature = "stream")]
use tokio::stream::StreamExt;

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
    let mut runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let mut ss = match neli::socket::tokio::NlSocket::<u16, Genlmsghdr<u8, u16>>::new(s) {
            Ok(s) => s,
            Err(e) => {
                println!("{}", e);
                return;
            }
        };
        while let Ok(Some(next)) = ss.try_next().await {
            println!("{:#?}", next);
        }
    });
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
        println!("{:#?}", next?);
    }
    Ok(())
}

pub fn main() -> Result<(), Box<dyn Error>> {
    #[cfg(feature = "stream")]
    debug_stream()?;
    #[cfg(not(feature = "stream"))]
    debug_stream()?;
    Ok(())
}
