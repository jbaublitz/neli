use std::{env, error::Error};

#[cfg(feature = "async")]
use tokio::runtime::Runtime;

#[cfg(feature = "async")]
use neli::router::asynchronous::NlRouter;
#[cfg(not(feature = "async"))]
use neli::router::synchronous::NlRouter;
use neli::{
    attr::Attribute,
    consts::{genl::*, nl::*, socket::*},
    genl::{Genlmsghdr, GenlmsghdrBuilder},
    nl::NlPayload,
    types::{Buffer, GenlBuffer},
    utils::Groups,
};

const GENL_VERSION: u8 = 2;

// This example attempts to mimic the "genl ctrl list" command. For simplicity, it only outputs
// the name and identifier of each generic netlink family.

#[cfg(feature = "async")]
fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let num_reps = env::args()
        .nth(1)
        .ok_or("Number of loop repetitions required")?
        .parse::<usize>()?;

    Runtime::new()?.block_on(async {
        for _ in 0..num_reps {
            let (socket, _) = NlRouter::connect(NlFamily::Generic, None, Groups::empty()).await?;
            let mut recv = socket
                .send::<_, _, NlTypeWrapper, Genlmsghdr<CtrlCmd, CtrlAttr>>(
                    GenlId::Ctrl,
                    NlmF::DUMP,
                    NlPayload::Payload(
                        GenlmsghdrBuilder::default()
                            .cmd(CtrlCmd::Getfamily)
                            .version(GENL_VERSION)
                            .attrs(GenlBuffer::<u16, Buffer>::new())
                            .build()?,
                    ),
                )
                .await?;

            while let Some(response_result) = recv
                .next::<NlTypeWrapper, Genlmsghdr<CtrlCmd, CtrlAttr>>()
                .await
            {
                let response = response_result?;

                if let Some(p) = response.get_payload() {
                    let handle = p.attrs().get_attr_handle();
                    for attr in handle.iter() {
                        match attr.nla_type().nla_type() {
                            CtrlAttr::FamilyName => {
                                println!("{}", attr.get_payload_as_with_len::<String>()?);
                            }
                            CtrlAttr::FamilyId => {
                                println!("\tID: 0x{:x}", attr.get_payload_as::<u16>()?);
                            }
                            _ => (),
                        }
                    }
                }
            }
        }
        Result::<_, Box<dyn Error>>::Ok(())
    })?;

    Ok(())
}

#[cfg(not(feature = "async"))]
fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let num_reps = env::args()
        .nth(1)
        .ok_or_else(|| "Number of loop repetitions required")?
        .parse::<usize>()?;

    for _ in 0..num_reps {
        let (socket, _) = NlRouter::connect(NlFamily::Generic, None, Groups::empty())?;
        let recv = socket.send::<_, _, NlTypeWrapper, Genlmsghdr<CtrlCmd, CtrlAttr>>(
            GenlId::Ctrl,
            NlmF::DUMP,
            NlPayload::Payload(
                GenlmsghdrBuilder::default()
                    .cmd(CtrlCmd::Getfamily)
                    .version(GENL_VERSION)
                    .attrs(GenlBuffer::<u16, Buffer>::new())
                    .build()?,
            ),
        )?;

        for response_result in recv {
            let response = response_result?;

            if let Some(p) = response.get_payload() {
                let handle = p.attrs().get_attr_handle();
                for attr in handle.iter() {
                    match attr.nla_type().nla_type() {
                        CtrlAttr::FamilyName => {
                            println!("{}", attr.get_payload_as_with_len::<String>()?);
                        }
                        CtrlAttr::FamilyId => {
                            println!("\tID: 0x{:x}", attr.get_payload_as::<u16>()?);
                        }
                        _ => (),
                    }
                }
            }
        }
    }

    Ok(())
}
