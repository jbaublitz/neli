use neli::{
    consts::{
        nl::NlmF,
        rtnl::{Ifla, RtAddrFamily, Rtm},
        socket::NlFamily,
    },
    nl::NlPayload,
    router::synchronous::NlRouter,
    rtnl::{Ifinfomsg, IfinfomsgBuilder},
    utils::Groups,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let (rtnl, _) = NlRouter::connect(NlFamily::Route, None, Groups::empty())?;
    rtnl.enable_ext_ack(true)?;
    rtnl.enable_strict_checking(true)?;
    let ifinfomsg = IfinfomsgBuilder::default()
        .ifi_family(RtAddrFamily::Inet)
        .build()?;

    let recv = rtnl.send::<_, _, Rtm, Ifinfomsg>(
        Rtm::Getlink,
        NlmF::DUMP | NlmF::ACK,
        NlPayload::Payload(ifinfomsg),
    )?;
    for response in recv {
        if let Some(payload) = response?.get_payload() {
            println!(
                "{:?}",
                payload
                    .rtattrs()
                    .get_attr_handle()
                    .get_attr_payload_as_with_len::<String>(Ifla::Ifname)?,
            )
        }
    }

    Ok(())
}
