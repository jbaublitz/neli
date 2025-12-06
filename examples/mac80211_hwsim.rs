use std::error::Error;

use neli::attr::Attribute;
use neli::consts::mac80211_hwsim::{Mac80211HwsimAttr, Mac80211HwsimCmd};
use neli::router::synchronous::NlRouter;
use neli::{
    consts::{
        nl::{GenlId, NlmF},
        socket::NlFamily,
    },
    genl::{Genlmsghdr, GenlmsghdrBuilder, NoUserHeader},
    nl::{NlPayload, Nlmsghdr},
    utils::Groups,
};

fn handle(msg: Nlmsghdr<GenlId, Genlmsghdr<Mac80211HwsimCmd, Mac80211HwsimAttr>>) {
    // Messages with the NlmF::DUMP flag end with an empty payload message
    // Don't parse message unless receive proper payload (non-error, non-empty, non-ack)
    let payload = match msg.nl_payload() {
        NlPayload::Payload(p) => p,
        _ => return,
    };

    let attr_handle = payload.attrs().get_attr_handle();
    for attr in attr_handle.iter() {
        match attr.nla_type().nla_type() {
            Mac80211HwsimAttr::RadioId => {
                let radio_id = attr.get_payload_as::<u32>().unwrap();
                println!("{:<18}{}", "RadioId:", radio_id);
            }
            Mac80211HwsimAttr::Channels => {
                let channels = attr.get_payload_as::<u32>().unwrap();
                println!("{:<18}{}", "Channels:", channels);
            }
            Mac80211HwsimAttr::SupportP2pDevice => {
                // This is a flag parameter, so its presence indicates support
                println!("{:<18}", "SupportP2pDevice: true");
            }
            Mac80211HwsimAttr::RadioName => {
                let radio_name: &[u8] = attr.get_payload_as_with_len_borrowed().unwrap();
                println!(
                    "{:<18}{}",
                    "RadioName:",
                    std::str::from_utf8(radio_name).unwrap()
                );
            }
            _ => (),
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    // Initialize NlRouter and resolve 'MAC80211_HWSIM' genl family
    let (sock, _) = NlRouter::connect(
        NlFamily::Generic, /* family */
        Some(0),           /* pid */
        Groups::empty(),   /* groups */
    )?;
    let family_id = match sock.resolve_genl_family("MAC80211_HWSIM") {
        Ok(id) => id,
        Err(err) => {
            eprintln!(
                "Failed to query mac80211_hwsim radios. Possibly the kernel module is not loaded ('modprobe mac80211_hwsim')"
            );
            return Err(Box::new(err));
        }
    };

    // Query system for mac80211_hwsim driver WiFi radios using the 'GetRadio' command
    let recv = sock.send(
        family_id,
        NlmF::DUMP | NlmF::ACK,
        NlPayload::Payload(
            GenlmsghdrBuilder::<Mac80211HwsimCmd, Mac80211HwsimAttr, NoUserHeader>::default()
                .cmd(Mac80211HwsimCmd::GetRadio)
                .version(1)
                .build()?,
        ),
    )?;

    // Print response data which contains mac80211_hwsim WiFi radios
    println!("mac80211_hwsim radios:");
    for msg in recv {
        let msg = msg?;
        handle(msg);
        println!();
    }

    Ok(())
}
