use std::{error::Error, iter::once};

#[cfg(feature = "async")]
use neli::router::asynchronous::NlRouter;
#[cfg(not(feature = "async"))]
use neli::router::synchronous::NlRouter;
use neli::{
    attr::Attribute,
    consts::{
        nl::{GenlId, NlmF},
        nl80211::{
            Nl80211Attribute, Nl80211BandAttr, Nl80211BitrateAttr, Nl80211Command, Nl80211FreqAttr,
            Nl80211IfType,
        },
        socket::NlFamily,
    },
    genl::{AttrTypeBuilder, NlattrBuilder},
    genl::{Genlmsghdr, GenlmsghdrBuilder, NoUserHeader},
    nl::{NlPayload, Nlmsghdr},
    types::GenlBuffer,
    utils::Groups,
};

fn handle(msg: Nlmsghdr<GenlId, Genlmsghdr<Nl80211Command, Nl80211Attribute>>) {
    // Messages with the NlmF::DUMP flag end with an empty payload message
    // Don't parse message unless receive proper payload (non-error, non-empty, non-ack)
    let payload = match msg.nl_payload() {
        NlPayload::Payload(p) => p,
        _ => return,
    };

    let attr_handle = payload.attrs().get_attr_handle();
    for attr in attr_handle.iter() {
        match attr.nla_type().nla_type() {
            Nl80211Attribute::Wiphy => {
                let wiphy = attr.get_payload_as::<u32>().unwrap();
                println!("{:<12}{}", "Wiphy:", wiphy);
            }
            Nl80211Attribute::WiphyName => {
                let wiphy_name = attr.get_payload_as_with_len::<String>().unwrap();
                println!("{:<12}{}", "WiphyName:", wiphy_name);
            }
            Nl80211Attribute::Ifname => {
                let ifname = attr.get_payload_as_with_len::<String>().unwrap();
                println!("{:<12}{}", "Ifname:", ifname);
            }
            Nl80211Attribute::Iftype => {
                let iftype = attr.get_payload_as::<Nl80211IfType>().unwrap();
                println!("{:<12}{:?}", "Iftype:", iftype);
            }
            Nl80211Attribute::Wdev => {
                // Wdev is unique 64-bit identifier per WiFi interface containing both the
                // WiFi radio (wiphy, upper 32 bits) and WiFi interface identifiers (lower 32 bits)
                // Print lower 9 bytes (36 bits) to simplify printout and match 'iw wlan0 info' output
                let wdev = attr.get_payload_as::<u64>().unwrap();
                println!("{:<12}0x{:09x}", "Wdev:", wdev);
            }
            Nl80211Attribute::Ssid => {
                // Kernel references this attribute as binary data.
                // For simplicity, just try to parse as UTF-8
                let ssid: &[u8] = attr.get_payload_as_with_len_borrowed().unwrap();
                println!("{:<12}{}", "Ssid:", std::str::from_utf8(ssid).unwrap());
            }
            Nl80211Attribute::WiphyBands => {
                // Bands are nested arrays of each element having nested arrays itself.

                let bands_iter = attr_handle
                    .get_nested_attributes::<Nl80211BandAttr>(Nl80211Attribute::WiphyBands)
                    .unwrap();

                println!("{:<12}", "Bands:");

                for b in bands_iter.iter() {
                    let index = u16::from(b.nla_type());
                    println!("  Band {}:", index);

                    let b = b.get_attr_handle::<Nl80211BandAttr>().unwrap();
                    println!("          {:<12}", "Frequencies:");
                    for f in b
                        .get_nested_attributes::<Nl80211FreqAttr>(Nl80211BandAttr::Freqs)
                        .unwrap()
                        .iter()
                    {
                        let f = f.get_attr_handle::<Nl80211FreqAttr>().unwrap();

                        // presence of attribute means it's true, otherwise false
                        let disabled = f
                            .get_attr_payload_as::<()>(Nl80211FreqAttr::Disabled)
                            .is_ok();
                        let value = f.get_attr_payload_as::<u32>(Nl80211FreqAttr::Freq).unwrap();
                        println!(
                            "            * {value} MHz{}",
                            if disabled { " (disabled) " } else { "" }
                        );
                    }

                    println!("          {:<12}", "Bitrates:");
                    for r in b
                        .get_nested_attributes::<Nl80211BitrateAttr>(Nl80211BandAttr::Rates)
                        .unwrap()
                        .iter()
                    {
                        let r = r.get_attr_handle::<Nl80211BitrateAttr>().unwrap();

                        // presence of attribute means it's true, otherwise false
                        let short_preamble = r
                            .get_attr_payload_as::<()>(Nl80211BitrateAttr::_2ghzShortpreamble)
                            .is_ok();
                        let value = (r
                            .get_attr_payload_as::<u32>(Nl80211BitrateAttr::Rate)
                            .unwrap())
                            / 10;

                        println!(
                            "            * {value} Mbps{}",
                            if short_preamble {
                                " (short preamble supported) "
                            } else {
                                ""
                            }
                        );
                    }
                }
            }
            _ => (),
        }
    }
}

#[cfg(feature = "async")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    // Initialize NlRouter and resolve 'nl80211' genl family
    let (sock, _) = NlRouter::connect(
        NlFamily::Generic, /* family */
        Some(0),           /* pid */
        Groups::empty(),   /* groups */
    )
    .await?;
    let family_id = sock.resolve_genl_family("nl80211").await?;

    // Query system for WiFi radios using the 'GetWiphy' command
    let mut recv = sock
        .send::<_, _, u16, Genlmsghdr<Nl80211Command, Nl80211Attribute>>(
            family_id,
            NlmF::DUMP | NlmF::ACK,
            NlPayload::Payload(
                GenlmsghdrBuilder::<Nl80211Command, Nl80211Attribute, NoUserHeader>::default()
                    .cmd(Nl80211Command::GetWiphy)
                    .version(1)
                    .build()?,
            ),
        )
        .await?;

    // Print response data which contains WiFi radios detected and configured by system
    println!("WiFi radios:");
    while let Some(Ok(msg)) = recv.next().await {
        handle(msg);
        println!();
    }

    // Query system for WiFi interfaces using the 'GetInterface' command
    // Empty payload for 'Ifname' attribute will dump all WiFi interfaces
    let attrs = once(
        NlattrBuilder::default()
            .nla_type(
                AttrTypeBuilder::default()
                    .nla_type(Nl80211Attribute::Ifname)
                    .build()
                    .unwrap(),
            )
            .nla_payload(())
            .build()
            .unwrap(),
    )
    .collect::<GenlBuffer<_, _>>();

    let mut recv = sock
        .send::<_, _, u16, Genlmsghdr<Nl80211Command, Nl80211Attribute>>(
            family_id,
            NlmF::DUMP | NlmF::ACK,
            NlPayload::Payload(
                GenlmsghdrBuilder::<Nl80211Command, Nl80211Attribute, NoUserHeader>::default()
                    .cmd(Nl80211Command::GetInterface)
                    .attrs(attrs)
                    .version(1)
                    .build()?,
            ),
        )
        .await?;

    // Print response data which contains WiFi interfaces detected and configured by system
    println!("WiFi interfaces:");
    while let Some(Ok(msg)) = recv.next().await {
        handle(msg);
        println!();
    }

    Ok(())
}

#[cfg(not(feature = "async"))]
fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    // Initialize NlRouter and resolve 'nl80211' genl family
    let (sock, _) = NlRouter::connect(
        NlFamily::Generic, /* family */
        Some(0),           /* pid */
        Groups::empty(),   /* groups */
    )?;
    let family_id = sock.resolve_genl_family("nl80211")?;

    // Query system for WiFi radios using the 'GetWiphy' command
    let recv = sock.send(
        family_id,
        NlmF::DUMP | NlmF::ACK,
        NlPayload::Payload(
            GenlmsghdrBuilder::<Nl80211Command, Nl80211Attribute, NoUserHeader>::default()
                .cmd(Nl80211Command::GetWiphy)
                .version(1)
                .build()?,
        ),
    )?;

    // Print response data which contains WiFi radios detected and configured by system
    println!("WiFi radios:");
    for msg in recv {
        let msg = msg?;
        handle(msg);
        println!();
    }

    // Query system for WiFi interfaces using the 'GetInterface' command
    // Empty payload for 'Ifname' attribute will dump all WiFi interfaces
    let attrs = once(
        NlattrBuilder::default()
            .nla_type(
                AttrTypeBuilder::default()
                    .nla_type(Nl80211Attribute::Ifname)
                    .build()
                    .unwrap(),
            )
            .nla_payload(())
            .build()
            .unwrap(),
    )
    .collect::<GenlBuffer<_, _>>();

    let recv = sock.send(
        family_id,
        NlmF::DUMP | NlmF::ACK,
        NlPayload::Payload(
            GenlmsghdrBuilder::<Nl80211Command, Nl80211Attribute, NoUserHeader>::default()
                .cmd(Nl80211Command::GetInterface)
                .attrs(attrs)
                .version(1)
                .build()?,
        ),
    )?;

    // Print response data which contains WiFi interfaces detected and configured by system
    println!("WiFi interfaces:");
    for msg in recv {
        let msg = msg?;
        handle(msg);
        println!();
    }

    Ok(())
}
