use neli::{
    consts::{
        nl::{NlmF, NlmsgerrAttr},
        rtnl::Arphrd,
        rtnl::{RtAddrFamily, Rtm},
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
        .ifi_type(Arphrd::None)
        .build()?;

    let recv = rtnl.send::<_, _, Rtm, Ifinfomsg>(
        Rtm::Getlink,
        NlmF::DUMP | NlmF::ACK,
        NlPayload::Payload(ifinfomsg),
    )?;
    for response in recv {
        if let NlPayload::DumpExtAck(ack) = response?.nl_payload() {
            println!("{:?}", ack);
            println!(
                "MSG: {}",
                ack.ext_ack()
                    .get_attr_handle()
                    .get_attr_payload_as_with_len::<String>(NlmsgerrAttr::Msg)?
            );
        }
    }

    Ok(())
}
