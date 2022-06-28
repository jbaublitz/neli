use std::{env, error::Error};

#[cfg(feature = "async")]
use neli::socket::tokio::NlSocket;
use neli::{
    consts::{
        genl::{CtrlAttr, CtrlCmd},
        nl::GenlId,
        socket::NlFamily,
    },
    genl::Genlmsghdr,
    socket::NlSocketHandle,
};

#[cfg(feature = "async")]
fn debug_stream() -> Result<(), Box<dyn Error>> {
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
        let mut ss = NlSocket::new(s)?;
        let mut buffer = Vec::new();
        while let Ok(msgs) = ss
            .recv::<GenlId, Genlmsghdr<CtrlCmd, CtrlAttr>>(&mut buffer)
            .await
        {
            for msg in msgs {
                println!("{:?}", msg);
            }
        }
        Ok(())
    })
}

#[cfg(not(feature = "async"))]
fn debug_stream() -> Result<(), Box<dyn Error>> {
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
    for next in s.iter::<GenlId, Genlmsghdr<CtrlCmd, CtrlAttr>>(true) {
        println!("{:?}", next?);
    }
    Ok(())
}

pub fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    #[cfg(feature = "async")]
    debug_stream()?;
    #[cfg(not(feature = "async"))]
    debug_stream()?;
    Ok(())
}
