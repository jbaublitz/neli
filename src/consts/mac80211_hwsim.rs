use neli_proc_macros::neli_enum;

use crate::{self as neli};

/// Supported commands for the Linux `mac80211_hwsim` generic netlink (genl) driver
// NOTE: These constants are only available in an in-driver header file.
// There is presently no way to include these from userspace without directly
// copying the enums or values explicitly. Other popular Linux WiFi tools like 'iwd'
// and 'hostap' define these in their own automation, given this limitation.
#[neli_enum(serialized_type = "u8")]
pub enum Mac80211HwsimCmd {
    /// Unspecified command to catch errors
    Unspec = 0,
    /// Request to register and received all broadcasted frames by any `mac80211_hwsim` radio device.
    Register = 1,
    /// Send/receive a broadcasted frame from/to kernel/user space, uses:
    /// * [`Mac80211HwsimAttr::AddrTransmitter`]
    /// * [`Mac80211HwsimAttr::AddrReceiver`]
    /// * [`Mac80211HwsimAttr::Frame`]
    /// * [`Mac80211HwsimAttr::Flags`]
    /// * [`Mac80211HwsimAttr::RxRate`]
    /// * [`Mac80211HwsimAttr::Signal`]
    /// * [`Mac80211HwsimAttr::Cookie`]
    /// * [`Mac80211HwsimAttr::Freq`] (optional)
    Frame = 2,
    /// Transmission info report from user space to kernel, uses:
    /// * [`Mac80211HwsimAttr::AddrTransmitter`]
    /// * [`Mac80211HwsimAttr::Flags`]
    /// * [`Mac80211HwsimAttr::TxInfo`]
    /// * [`Mac80211HwsimAttr::TxInfoFlags`]
    /// * [`Mac80211HwsimAttr::Signal`]
    /// * [`Mac80211HwsimAttr::Cookie`]
    TxInfoFrame = 3,
    /// Create a new radio with the given parameters, returns the radio ID (>= 0) or negative
    /// on errors, if successful then multicast the result, uses optional parameter:
    /// * [`Mac80211HwsimAttr::RegStrictReg`]
    /// * [`Mac80211HwsimAttr::SupportP2pDevice`]
    /// * [`Mac80211HwsimAttr::DestroyRadioOnClose`]
    /// * [`Mac80211HwsimAttr::Channels`]
    /// * [`Mac80211HwsimAttr::NoVif`]
    /// * [`Mac80211HwsimAttr::RadioName`]
    /// * [`Mac80211HwsimAttr::UseChanctx`]
    /// * [`Mac80211HwsimAttr::RegHintAlpha2`]
    /// * [`Mac80211HwsimAttr::RegCustomReg`]
    /// * [`Mac80211HwsimAttr::PermAddr`]
    NewRadio = 4,
    /// Destroy a radio, reply is multicasted
    DelRadio = 5,
    /// Fetch information about existing radios, uses: [`Mac80211HwsimAttr::RadioId`]
    GetRadio = 6,
    /// Add a receive MAC address (given in the [`Mac80211HwsimAttr::AddrReceiver`] attribute)
    /// to a device identified by [`Mac80211HwsimAttr::AddrTransmitter`]. This lets wmediumd forward
    /// frames to this receiver address for a given station.
    AddMacAddr = 7,
    /// Remove the MAC address again, the attributes are the same as to [`Mac80211HwsimCmd::AddMacAddr`].
    DelMacAddr = 8,
    /// Request to start peer measurement with the [`Mac80211HwsimAttr::PmsrRequest`].
    /// Result will be sent back asynchronously with [`Mac80211HwsimCmd::ReportPmsr`].
    StartPmsr = 9,
    /// Abort previously started peer measurement.
    AbortPmsr = 10,
    /// Report peer measurement data.
    ReportPmsr = 11,
}
impl neli::consts::genl::Cmd for Mac80211HwsimCmd {}

/// Supported attributes for the Linux `mac80211_hwsim` generic netlink (genl) driver
#[neli_enum(serialized_type = "u16")]
pub enum Mac80211HwsimAttr {
    /// Unspecified attribute to catch errors
    Unspec = 0,
    /// MAC address of the radio device that the frame is broadcasted to
    AddrReceiver = 1,
    /// MAC address of the radio device that the frame was broadcasted from
    AddrTransmitter = 2,
    /// Data array
    Frame = 3,
    /// `mac80211` transmission flags, used to process properly the frame at user space
    Flags = 4,
    /// Estimated RX rate index for this frame at user space
    RxRate = 5,
    /// Estimated RX signal for this frame at user space
    Signal = 6,
    /// `ieee80211_tx_rate` array
    TxInfo = 7,
    /// `sk_buff` cookie to identify the frame
    Cookie = 8,
    /// `u32` attribute used with the [`Mac80211HwsimCmd::NewRadio`] command giving the
    /// number of channels supported by the new radio
    Channels = 9,
    /// `u32` attribute used with [`Mac80211HwsimCmd::DelRadio`] only to destroy a radio
    RadioId = 10,
    /// Alpha2 for regulatory driver hint (nla string, length 2)
    RegHintAlpha2 = 11,
    /// Custom regulatory domain index (`u32` attribute)
    RegCustomReg = 12,
    /// Request `REGULATORY_STRICT_REG` (flag attribute)
    RegStrictReg = 13,
    /// Support P2P Device virtual interface (flag)
    SupportP2pDevice = 14,
    /// Used with the [`Mac80211HwsimCmd::NewRadio`] command to force use of channel contexts even
    /// when only a single channel is supported
    UseChanctx = 15,
    /// Used with the [`Mac80211HwsimCmd::NewRadio`] command to force radio removal when process that
    /// created the radio dies
    DestroyRadioOnClose = 16,
    /// Name of radio, e.g. phy666
    RadioName = 17,
    /// Do not create vif (wlanX) when creating radio
    NoVif = 18,
    /// Frequency at which packet is transmitted or received
    Freq = 19,
    /// Padding attribute for 64-bit values, ignore
    Pad = 20,
    /// Additional flags for corresponding rates of [`Mac80211HwsimAttr::TxInfo`]
    TxInfoFlags = 21,
    /// Permanent MAC address of new radio
    PermAddr = 22,
    /// `u32` attribute of supported interface types bits
    IftypeSupport = 23,
    /// `u32` array of supported cipher types
    CipherSupport = 24,
    /// Claim MLO support (exact parameters TBD) for the new radio
    MloSupport = 25,
    /// Nested attribute used with [`Mac80211HwsimCmd::NewRadio`] to provide peer measurement
    /// capabilities (`nl80211_peer_measurement_attrs`)
    PmsrSupport = 26,
    /// Nested attribute used with  [`Mac80211HwsimCmd::StartPmsr`] to provide details about peer
    /// measurement request (`nl80211_peer_measurement_attrs`)
    PmsrRequest = 27,
    /// Nested attributed used with [`Mac80211HwsimCmd::ReportPmsr`]  to provide peer measurement
    /// result (`nl80211_peer_measurement_attrs`)
    PmsrResult = 28,
    /// Register multiple wiphy radios (flag). Adds one radio for each band. Number of supported
    /// channels will be set for each radio instead of for the wiphy.
    MultiRadio = 29,
    /// Support NAN device virtual interface (flag)
    SupportNanDevice = 30,
}
impl neli::consts::genl::NlAttrType for Mac80211HwsimAttr {}

impl_flags!(
    /// Flags to describe transmission info/status
    ///
    /// These flags are used to give the wmediumd extra information in order to
    /// modify its behavior for each frame
    // Must match size of `flags` member of `ieee80211_tx_info`
    pub TxControlFlags: u32 {
        /// Require TX status callback for this frame
        ReqTxStatus = 0,
        /// Tell the wmediumd not to wait for an ack
        NoAck = 1,
        /// Frame was acknowledged
        StatAck = 2,
    }
);

impl_flags!(
    /// Per-rate flags set by the rate control algorithm.
    ///
    /// These flags are set by the Rate control algorithm for each rate during tx,
    /// in the `flags` member of `struct ieee80211_tx_rate`.
    pub Mac80211TxRateFlags: u16 {
        /// Use RTS/CTS exchange for this rate
        UseRtsCts = 0,
        /// CTS-to-self protection is required. This is set if the current BSS requires ERP protection
        UseCtsProtect = 1,
        /// Use short preamble
        UseShortPreamble = 2,
        /// HT rate
        Mcs = 3,
        /// Indicates whether this rate should be used in Greenfield mode
        GreenField= 4,
        /// Indicates if the Channel Width should be 40 MHz
        Width40Mhz= 5,
        /// The frame should be transmitted on both of the adjacent 20 MHz channels,
        /// if the current channel type is `NL80211_CHAN_HT40MINUS` or `NL80211_CHAN_HT40PLUS`
        DupData = 6,
        /// Short Guard interval should be used for this rate
        ShortGi = 7,
        /// VHT MCS rate, in this case the idx field is split into a higher 4 bits (NSS)
        /// and lower 4 bits (MCS number)
        VhtMcs = 8,
        /// Indicates 80 MHz transmission
        Width80Mhz= 9,
        /// Indicates 160 MHz transmission (80+80 isn't supported yet)
        Width160Mhz= 10,
    }
);

/// Bitrate information
///
/// Information about a receiving or transmitting bitrate
/// that can be mapped to `struct rate_info`
// TODO: This is actually u8 data type. Compiler complains if set to u8, though
#[neli_enum(serialized_type = "u16")]
pub enum Mac80211RateInfoAttr {
    /// Reserved, netlink attribute 0 is invalid
    Invalid = 0,
    /// Bitflag of flags from `enum rate_info_flags`
    FoAttrFlags = 1,
    /// MCS index if struct describes an HT/VHT/HE rate
    Mcs = 2,
    /// Bitrate in 100 Kbps for 802.11abg
    Legacy = 3,
    /// Number of streams (VHT and HE only)
    Nss = 4,
    /// Bandwidth (from `enum rate_info_bw`)
    Bw = 5,
    /// HE guard interval (from `enum nl80211_he_gi`)
    HeGi = 6,
    /// HE DCM value
    HeDcm = 7,
    /// HE RU allocation (from `enum nl80211_he_ru_alloc`, only valid if bw is `RATE_INFO_BW_HE_RU`)
    HeRuAlloc = 8,
    /// In case of EDMG the number of bonded channels (1-4)
    NBoundedCh = 9,
    /// EHT guard interval (from `enum nl80211_eht_gi`)
    EhtGi = 10,
    /// EHT RU allocation (from `enum nl80211_eht_ru_alloc`, only valid if bw is `RATE_INFO_BW_EHT_RU`)
    EhtRuAlloc = 11,
}
impl neli::consts::genl::NlAttrType for Mac80211RateInfoAttr {}
