use std::{env, error::Error};

#[cfg(feature = "async")]
use neli::socket::tokio::NlSocket;
use neli::{consts::socket::NlFamily, err::NlError, genl::Genlmsghdr, socket::NlSocketHandle};
#[cfg(feature = "async")]
use tokio_stream::StreamExt;

#[cfg(feature = "async")]
fn debug_stream() -> Result<(), NlError> {
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
    let mut s = NlSocketHandle::connect(NlFamily::Generic, None, &[])?;
    let id = s.resolve_nl_mcast_group(&family_name, &mc_group_name)?;
    s.add_mcast_membership(&[id])?;
    let runtime = ::tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let mut ss = match NlSocket::<u16, Genlmsghdr<u8, u16>>::new(s) {
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

#[cfg(not(feature = "async"))]
fn debug_stream() -> Result<(), NlError> {
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
    let mut s = NlSocketHandle::connect(NlFamily::Generic, None, &[])?;
    let id = s.resolve_nl_mcast_group(&family_name, &mc_group_name)?;
    s.add_mcast_membership(&[id])?;
    for next in s.iter::<Genlmsghdr<u8, u16>>(true) {
        println!("{:#?}", next?);
    }
    Ok(())
}

pub fn main() -> Result<(), Box<dyn Error>> {
    #[cfg(feature = "async")]
    debug_stream()?;
    #[cfg(not(feature = "async"))]
    debug_stream()?;
    Ok(())
}
