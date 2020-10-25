use std::{env, error::Error};

#[cfg(feature = "async")]
use futures_util::{future, stream::StreamExt};
#[cfg(feature = "async")]
use neli::socket::tokio::NlSocket;
use neli::{
    consts,
    err::NlError,
    genl::Genlmsghdr,
    socket::NlSocketHandle,
    utils::{U32BitFlag, U32Bitmask},
};

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
    let mut s = NlSocketHandle::connect(consts::NlFamily::Generic, None, U32Bitmask::empty())?;
    let id = s.resolve_nl_mcast_group(&family_name, &mc_group_name)?;
    let flag = match U32BitFlag::new(id) {
        Ok(f) => f,
        Err(_) => {
            return Err(NlError::new(format!(
                "{} is too large of a group number",
                id
            )))
        }
    };
    s.add_mcast_membership(U32Bitmask::from(flag))?;
    let mut runtime = ::tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let ss = match NlSocket::<u16, Genlmsghdr<u8, u16>>::new(s) {
            Ok(s) => s,
            Err(e) => {
                println!("{}", e);
                return;
            }
        };
        ss.for_each(|next| {
            println!("{:#?}", next);
            future::ready(())
        })
        .await;
    });
    Ok(())
}

#[cfg(not(feature = "async"))]
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
    let mut s = NlSocketHandle::connect(consts::NlFamily::Generic, None, U32Bitmask::empty())?;
    let id = s.resolve_nl_mcast_group(&family_name, &mc_group_name)?;
    let flag = match U32BitFlag::new(id) {
        Ok(f) => f,
        Err(_) => {
            return Err(NlError::new(format!(
                "{} is too large of a group number",
                id
            )))
        }
    };
    s.add_mcast_membership(U32Bitmask::from(flag))?;
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
