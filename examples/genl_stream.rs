use std::{env, error::Error};

use neli::consts::socket::NlFamily;
#[cfg(not(feature = "async"))]
use neli::router::synchronous::NlRouter;
#[cfg(feature = "async")]
use neli::{genl::Genlmsghdr, router::asynchronous::NlRouter};

#[cfg(feature = "async")]
fn debug_stream() -> Result<(), Box<dyn Error>> {
    use neli::utils::Groups;

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
    let runtime = ::tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let (s, mut multicast) =
            NlRouter::connect(NlFamily::Generic, None, Groups::empty()).await?;
        let id = s
            .resolve_nl_mcast_group(&family_name, &mc_group_name)
            .await?;
        s.add_mcast_membership(Groups::new_groups(&[id]))?;
        while let Some(Ok(msg)) = multicast.next::<u16, Genlmsghdr<u8, u16>>().await {
            println!("{msg:?}");
        }
        Ok(())
    })
}

#[cfg(not(feature = "async"))]
fn debug_stream() -> Result<(), Box<dyn Error>> {
    use neli::utils::Groups;

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
    let (s, mc_recv) = NlRouter::connect(NlFamily::Generic, None, Groups::empty())?;
    let id = s.resolve_nl_mcast_group(&family_name, &mc_group_name)?;
    s.add_mcast_membership(Groups::new_groups(&[id]))?;
    for next in mc_recv {
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
