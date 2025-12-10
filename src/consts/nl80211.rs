use linux_raw_sys::netlink::*;
use neli_proc_macros::neli_enum;

use crate::{self as neli};

/// Supported `nl80211` commands
#[allow(missing_docs)]
#[neli_enum(serialized_type = "u8")]
pub enum Nl80211Cmd {
    /// Unspecified command to catch errors
    Unspecified = nl80211_commands::NL80211_CMD_UNSPEC as u8,
    /// Request information about a wiphy or dump request to get a list of all present wiphys.
    GetWiphy = nl80211_commands::NL80211_CMD_GET_WIPHY as u8,
    /// Set wiphy parameters, needs [`Nl80211Attr::Wiphy`] or
    /// [`Nl80211Attr::Ifindex`]; can be used to set [`Nl80211Attr::WiphyName`],
    /// [`Nl80211Attr::WiphyTxqParams`], [`Nl80211Attr::WiphyFreq`], [`Nl80211Attr::WiphyFreqOffset`]
    /// (and the attributes determining the channel width; this is used for setting
    /// monitor mode channel), [`Nl80211Attr::WiphyRetryShort`], [`Nl80211Attr::WiphyRetryLong`],
    /// [`Nl80211Attr::WiphyFragThreshold`], and/or [`Nl80211Attr::WiphyRtsThreshold`].
    /// However, for setting the channel, see [`Nl80211Cmd::SetChannel`] instead,
    /// the support here is for backward compatibility only.
    SetWiphy = nl80211_commands::NL80211_CMD_SET_WIPHY as u8,
    /// Newly created wiphy, response to get request or rename notification.
    /// Has attributes [`Nl80211Attr::Wiphy`] and [`Nl80211Attr::WiphyName`]
    NewWiphy = nl80211_commands::NL80211_CMD_NEW_WIPHY as u8,
    /// Wiphy deleted. Has attributes [`Nl80211Attr::Wiphy`] and [`Nl80211Attr::WiphyName`].
    DelWiphy = nl80211_commands::NL80211_CMD_DEL_WIPHY as u8,
    /// Request an interface's configuration; either a dump request for all interfaces
    /// or a specific get with a single [`Nl80211Attr::Ifindex`] is supported.
    GetInterface = nl80211_commands::NL80211_CMD_GET_INTERFACE as u8,
    /// Set type of a virtual interface, requires [`Nl80211Attr::Ifindex`] and [`Nl80211Attr::Iftype`]
    SetInterface = nl80211_commands::NL80211_CMD_SET_INTERFACE as u8,
    /// Newly created virtual interface or response to [`Nl80211Cmd::GetInterface`].
    /// Has [`Nl80211Attr::Ifindex`], [`Nl80211Attr::Wiphy`], and [`Nl80211Attr::Iftype`]
    /// attributes. Can also be sent from userspace to request creation of a new virtual
    /// interface, then requires attributes [`Nl80211Attr::Wiphy`], [`Nl80211Attr::Iftype`],
    /// and [`Nl80211Attr::Ifname`].
    NewInterface = nl80211_commands::NL80211_CMD_NEW_INTERFACE as u8,
    /// Virtual interface was deleted, has attributes [`Nl80211Attr::Ifindex`] and [`Nl80211Attr::Wiphy`].
    /// Can also be sent from userspace to request deletion of a virtual interface, then requires attribute
    /// [`Nl80211Attr::Ifindex`]. If multiple BSSID advertisements are enabled using [`Nl80211Attr::MbssidConfig`],
    /// [`Nl80211Attr::MbssidElems`], and if this command is used for the transmitting interface, then all
    /// the non-transmitting interfaces are deleted as well.
    DelInterface = nl80211_commands::NL80211_CMD_DEL_INTERFACE as u8,
    GetKey = nl80211_commands::NL80211_CMD_GET_KEY as u8,
    SetKey = nl80211_commands::NL80211_CMD_SET_KEY as u8,
    NewKey = nl80211_commands::NL80211_CMD_NEW_KEY as u8,
    DelKey = nl80211_commands::NL80211_CMD_DEL_KEY as u8,
    /// (Not used)
    GetBeacon = nl80211_commands::NL80211_CMD_GET_BEACON as u8,
    /// Change the beacon on an access point interface using the [`Nl80211Attr::BeaconHead`]
    /// and [`Nl80211Attr::BeaconTail`] attributes. For drivers that generate the beacon and probe
    /// responses internally, the following attributes must be provided: [`Nl80211Attr::Ie`],
    /// [`Nl80211Attr::IeProbeResp`] and [`Nl80211Attr::IeAssocResp`].
    SetBeacon = nl80211_commands::NL80211_CMD_SET_BEACON as u8,
    /// Start AP operation on an AP interface, parameters are like for [`Nl80211Cmd::SetBeacon`],
    /// and additionally parameters that do not change are used, these include
    /// [`Nl80211Attr::BeaconInterval`],
    /// [`Nl80211Attr::DtimPeriod`], [`Nl80211Attr::SSID`],
    /// [`Nl80211Attr::HiddenSsid`], [`Nl80211Attr::CipherSuitesPairwise`],
    /// [`Nl80211Attr::CipherSuiteGroup`], [`Nl80211Attr::WpaVersions`],
    /// [`Nl80211Attr::AkmSuites`], [`Nl80211Attr::Privacy`],
    /// [`Nl80211Attr::AuthType`], [`Nl80211Attr::InactivityTimeout`],
    /// [`Nl80211Attr::AclPolicy`] and [`Nl80211Attr::MacAddrs`].
    /// The channel to use can be set on the interface or be given using the [`Nl80211Attr::WiphyFreq`]
    /// and [`Nl80211Attr::WiphyFreqOffset`], and the attributes determining channel width.
    StartAp = nl80211_commands::NL80211_CMD_START_AP as u8,
    NewBeacon = nl80211_commands::NL80211_CMD_NEW_BEACON as u8,
    StopAp = nl80211_commands::NL80211_CMD_STOP_AP as u8,
    DelBeacon = nl80211_commands::NL80211_CMD_DEL_BEACON as u8,
    GetStation = nl80211_commands::NL80211_CMD_GET_STATION as u8,
    SetStation = nl80211_commands::NL80211_CMD_SET_STATION as u8,
    NewStation = nl80211_commands::NL80211_CMD_NEW_STATION as u8,
    DelStation = nl80211_commands::NL80211_CMD_DEL_STATION as u8,
    GetMpath = nl80211_commands::NL80211_CMD_GET_MPATH as u8,
    SetMpath = nl80211_commands::NL80211_CMD_SET_MPATH as u8,
    NewMpath = nl80211_commands::NL80211_CMD_NEW_MPATH as u8,
    DelMpath = nl80211_commands::NL80211_CMD_DEL_MPATH as u8,
    SetBss = nl80211_commands::NL80211_CMD_SET_BSS as u8,
    SetReg = nl80211_commands::NL80211_CMD_SET_REG as u8,
    ReqSetReg = nl80211_commands::NL80211_CMD_REQ_SET_REG as u8,
    GetMeshConfig = nl80211_commands::NL80211_CMD_GET_MESH_CONFIG as u8,
    SetMeshConfig = nl80211_commands::NL80211_CMD_SET_MESH_CONFIG as u8,
    SetMgmtExtraIe = nl80211_commands::NL80211_CMD_SET_MGMT_EXTRA_IE as u8,
    GetReg = nl80211_commands::NL80211_CMD_GET_REG as u8,
    GetScan = nl80211_commands::NL80211_CMD_GET_SCAN as u8,
    TriggerScan = nl80211_commands::NL80211_CMD_TRIGGER_SCAN as u8,
    NewScanResults = nl80211_commands::NL80211_CMD_NEW_SCAN_RESULTS as u8,
    ScanAborted = nl80211_commands::NL80211_CMD_SCAN_ABORTED as u8,
    RegChange = nl80211_commands::NL80211_CMD_REG_CHANGE as u8,
    Authenticate = nl80211_commands::NL80211_CMD_AUTHENTICATE as u8,
    Associate = nl80211_commands::NL80211_CMD_ASSOCIATE as u8,
    Deauthenticate = nl80211_commands::NL80211_CMD_DEAUTHENTICATE as u8,
    Disassociate = nl80211_commands::NL80211_CMD_DISASSOCIATE as u8,
    MichaelMicFailure = nl80211_commands::NL80211_CMD_MICHAEL_MIC_FAILURE as u8,
    RegBeaconHint = nl80211_commands::NL80211_CMD_REG_BEACON_HINT as u8,
    JoinIbss = nl80211_commands::NL80211_CMD_JOIN_IBSS as u8,
    LeaveIbss = nl80211_commands::NL80211_CMD_LEAVE_IBSS as u8,
    Testmode = nl80211_commands::NL80211_CMD_TESTMODE as u8,
    Connect = nl80211_commands::NL80211_CMD_CONNECT as u8,
    Roam = nl80211_commands::NL80211_CMD_ROAM as u8,
    Disconnect = nl80211_commands::NL80211_CMD_DISCONNECT as u8,
    SetWiphyNetns = nl80211_commands::NL80211_CMD_SET_WIPHY_NETNS as u8,
    GetSurvey = nl80211_commands::NL80211_CMD_GET_SURVEY as u8,
    NewSurveyResults = nl80211_commands::NL80211_CMD_NEW_SURVEY_RESULTS as u8,
    SetPmksa = nl80211_commands::NL80211_CMD_SET_PMKSA as u8,
    DelPmksa = nl80211_commands::NL80211_CMD_DEL_PMKSA as u8,
    FlushPmksa = nl80211_commands::NL80211_CMD_FLUSH_PMKSA as u8,
    RemainOnChannel = nl80211_commands::NL80211_CMD_REMAIN_ON_CHANNEL as u8,
    CancelRemainOnChannel = nl80211_commands::NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL as u8,
    SetTxBitrateMask = nl80211_commands::NL80211_CMD_SET_TX_BITRATE_MASK as u8,
    RegisterFrame = nl80211_commands::NL80211_CMD_REGISTER_FRAME as u8,
    RegisterAction = nl80211_commands::NL80211_CMD_REGISTER_ACTION as u8,
    Frame = nl80211_commands::NL80211_CMD_FRAME as u8,
    Action = nl80211_commands::NL80211_CMD_ACTION as u8,
    FrameTxStatus = nl80211_commands::NL80211_CMD_FRAME_TX_STATUS as u8,
    ActionTxStatus = nl80211_commands::NL80211_CMD_ACTION_TX_STATUS as u8,
    SetPowerSave = nl80211_commands::NL80211_CMD_SET_POWER_SAVE as u8,
    GetPowerSave = nl80211_commands::NL80211_CMD_GET_POWER_SAVE as u8,
    SetCqm = nl80211_commands::NL80211_CMD_SET_CQM as u8,
    NotifyCqm = nl80211_commands::NL80211_CMD_NOTIFY_CQM as u8,
    SetChannel = nl80211_commands::NL80211_CMD_SET_CHANNEL as u8,
    SetWdsPeer = nl80211_commands::NL80211_CMD_SET_WDS_PEER as u8,
    FrameWaitCancel = nl80211_commands::NL80211_CMD_FRAME_WAIT_CANCEL as u8,
    JoinMesh = nl80211_commands::NL80211_CMD_JOIN_MESH as u8,
    LeaveMesh = nl80211_commands::NL80211_CMD_LEAVE_MESH as u8,
    UnprotDeauthenticate = nl80211_commands::NL80211_CMD_UNPROT_DEAUTHENTICATE as u8,
    UnprotDisassociate = nl80211_commands::NL80211_CMD_UNPROT_DISASSOCIATE as u8,
    NewPeerCandidate = nl80211_commands::NL80211_CMD_NEW_PEER_CANDIDATE as u8,
    GetWowlan = nl80211_commands::NL80211_CMD_GET_WOWLAN as u8,
    SetWowlan = nl80211_commands::NL80211_CMD_SET_WOWLAN as u8,
    StartSchedScan = nl80211_commands::NL80211_CMD_START_SCHED_SCAN as u8,
    StopSchedScan = nl80211_commands::NL80211_CMD_STOP_SCHED_SCAN as u8,
    SchedScanResults = nl80211_commands::NL80211_CMD_SCHED_SCAN_RESULTS as u8,
    SchedScanStopped = nl80211_commands::NL80211_CMD_SCHED_SCAN_STOPPED as u8,
    SetRekeyOffload = nl80211_commands::NL80211_CMD_SET_REKEY_OFFLOAD as u8,
    PmksaCandidate = nl80211_commands::NL80211_CMD_PMKSA_CANDIDATE as u8,
    TdlsOper = nl80211_commands::NL80211_CMD_TDLS_OPER as u8,
    TdlsMgmt = nl80211_commands::NL80211_CMD_TDLS_MGMT as u8,
    UnexpectedFrame = nl80211_commands::NL80211_CMD_UNEXPECTED_FRAME as u8,
    ProbeClient = nl80211_commands::NL80211_CMD_PROBE_CLIENT as u8,
    RegisterBeacons = nl80211_commands::NL80211_CMD_REGISTER_BEACONS as u8,
    Unexpected4addrFrame = nl80211_commands::NL80211_CMD_UNEXPECTED_4ADDR_FRAME as u8,
    SetNoackMap = nl80211_commands::NL80211_CMD_SET_NOACK_MAP as u8,
    ChSwitchNotify = nl80211_commands::NL80211_CMD_CH_SWITCH_NOTIFY as u8,
    StartP2pDevice = nl80211_commands::NL80211_CMD_START_P2P_DEVICE as u8,
    StopP2pDevice = nl80211_commands::NL80211_CMD_STOP_P2P_DEVICE as u8,
    ConnFailed = nl80211_commands::NL80211_CMD_CONN_FAILED as u8,
    SetMcastRate = nl80211_commands::NL80211_CMD_SET_MCAST_RATE as u8,
    SetMacAcl = nl80211_commands::NL80211_CMD_SET_MAC_ACL as u8,
    RadarDetect = nl80211_commands::NL80211_CMD_RADAR_DETECT as u8,
    GetProtocolFeatures = nl80211_commands::NL80211_CMD_GET_PROTOCOL_FEATURES as u8,
    UpdateFtIes = nl80211_commands::NL80211_CMD_UPDATE_FT_IES as u8,
    FtEvent = nl80211_commands::NL80211_CMD_FT_EVENT as u8,
    CritProtocolStart = nl80211_commands::NL80211_CMD_CRIT_PROTOCOL_START as u8,
    CritProtocolStop = nl80211_commands::NL80211_CMD_CRIT_PROTOCOL_STOP as u8,
    GetCoalesce = nl80211_commands::NL80211_CMD_GET_COALESCE as u8,
    SetCoalesce = nl80211_commands::NL80211_CMD_SET_COALESCE as u8,
    ChannelSwitch = nl80211_commands::NL80211_CMD_CHANNEL_SWITCH as u8,
    Vendor = nl80211_commands::NL80211_CMD_VENDOR as u8,
    SetQosMap = nl80211_commands::NL80211_CMD_SET_QOS_MAP as u8,
    AddTxTs = nl80211_commands::NL80211_CMD_ADD_TX_TS as u8,
    DelTxTs = nl80211_commands::NL80211_CMD_DEL_TX_TS as u8,
    GetMpp = nl80211_commands::NL80211_CMD_GET_MPP as u8,
    JoinOcb = nl80211_commands::NL80211_CMD_JOIN_OCB as u8,
    LeaveOcb = nl80211_commands::NL80211_CMD_LEAVE_OCB as u8,
    ChSwitchStartedNotify = nl80211_commands::NL80211_CMD_CH_SWITCH_STARTED_NOTIFY as u8,
    TdlsChannelSwitch = nl80211_commands::NL80211_CMD_TDLS_CHANNEL_SWITCH as u8,
    TdlsCancelChannelSwitch = nl80211_commands::NL80211_CMD_TDLS_CANCEL_CHANNEL_SWITCH as u8,
    WiphyRegChange = nl80211_commands::NL80211_CMD_WIPHY_REG_CHANGE as u8,
    AbortScan = nl80211_commands::NL80211_CMD_ABORT_SCAN as u8,
    StartNan = nl80211_commands::NL80211_CMD_START_NAN as u8,
    StopNan = nl80211_commands::NL80211_CMD_STOP_NAN as u8,
    AddNanFunction = nl80211_commands::NL80211_CMD_ADD_NAN_FUNCTION as u8,
    DelNanFunction = nl80211_commands::NL80211_CMD_DEL_NAN_FUNCTION as u8,
    ChangeNanConfig = nl80211_commands::NL80211_CMD_CHANGE_NAN_CONFIG as u8,
    NanMatch = nl80211_commands::NL80211_CMD_NAN_MATCH as u8,
    SetMulticastToUnicast = nl80211_commands::NL80211_CMD_SET_MULTICAST_TO_UNICAST as u8,
    UpdateConnectParams = nl80211_commands::NL80211_CMD_UPDATE_CONNECT_PARAMS as u8,
    SetPmk = nl80211_commands::NL80211_CMD_SET_PMK as u8,
    DelPmk = nl80211_commands::NL80211_CMD_DEL_PMK as u8,
    PortAuthorized = nl80211_commands::NL80211_CMD_PORT_AUTHORIZED as u8,
    ReloadRegdb = nl80211_commands::NL80211_CMD_RELOAD_REGDB as u8,
    ExternalAuth = nl80211_commands::NL80211_CMD_EXTERNAL_AUTH as u8,
    StaOpmodeChanged = nl80211_commands::NL80211_CMD_STA_OPMODE_CHANGED as u8,
    ControlPortFrame = nl80211_commands::NL80211_CMD_CONTROL_PORT_FRAME as u8,
    GetFtmResponderStats = nl80211_commands::NL80211_CMD_GET_FTM_RESPONDER_STATS as u8,
    PeerMeasurementStart = nl80211_commands::NL80211_CMD_PEER_MEASUREMENT_START as u8,
    PeerMeasurementResult = nl80211_commands::NL80211_CMD_PEER_MEASUREMENT_RESULT as u8,
    PeerMeasurementComplete = nl80211_commands::NL80211_CMD_PEER_MEASUREMENT_COMPLETE as u8,
    NotifyRadar = nl80211_commands::NL80211_CMD_NOTIFY_RADAR as u8,
    UpdateOweInfo = nl80211_commands::NL80211_CMD_UPDATE_OWE_INFO as u8,
    ProbeMeshLink = nl80211_commands::NL80211_CMD_PROBE_MESH_LINK as u8,
    SetTidConfig = nl80211_commands::NL80211_CMD_SET_TID_CONFIG as u8,
    UnprotBeacon = nl80211_commands::NL80211_CMD_UNPROT_BEACON as u8,
    ControlPortFrameTxStatus = nl80211_commands::NL80211_CMD_CONTROL_PORT_FRAME_TX_STATUS as u8,
    SetSarSpecs = nl80211_commands::NL80211_CMD_SET_SAR_SPECS as u8,
    ObssColorCollision = nl80211_commands::NL80211_CMD_OBSS_COLOR_COLLISION as u8,
    ColorChangeRequest = nl80211_commands::NL80211_CMD_COLOR_CHANGE_REQUEST as u8,
    ColorChangeStarted = nl80211_commands::NL80211_CMD_COLOR_CHANGE_STARTED as u8,
    ColorChangeAborted = nl80211_commands::NL80211_CMD_COLOR_CHANGE_ABORTED as u8,
    ColorChangeCompleted = nl80211_commands::NL80211_CMD_COLOR_CHANGE_COMPLETED as u8,
    SetFilsAad = nl80211_commands::NL80211_CMD_SET_FILS_AAD as u8,
    AssocComeback = nl80211_commands::NL80211_CMD_ASSOC_COMEBACK as u8,
    AddLink = nl80211_commands::NL80211_CMD_ADD_LINK as u8,
    RemoveLink = nl80211_commands::NL80211_CMD_REMOVE_LINK as u8,
    AddLinkSta = nl80211_commands::NL80211_CMD_ADD_LINK_STA as u8,
    ModifyLinkSta = nl80211_commands::NL80211_CMD_MODIFY_LINK_STA as u8,
    RemoveLinkSta = nl80211_commands::NL80211_CMD_REMOVE_LINK_STA as u8,
    SetHwTimestamp = nl80211_commands::NL80211_CMD_SET_HW_TIMESTAMP as u8,
    LinksRemoved = nl80211_commands::NL80211_CMD_LINKS_REMOVED as u8,
    TidToLinkMapping = nl80211_commands::NL80211_CMD_SET_TID_TO_LINK_MAPPING as u8,
}
impl neli::consts::genl::Cmd for Nl80211Cmd {}

/// `nl80211` netlink attributes
#[allow(missing_docs)]
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211Attr {
    Unspec = nl80211_attrs::NL80211_ATTR_UNSPEC as u16,
    Wiphy = nl80211_attrs::NL80211_ATTR_WIPHY as u16,
    WiphyName = nl80211_attrs::NL80211_ATTR_WIPHY_NAME as u16,
    Ifindex = nl80211_attrs::NL80211_ATTR_IFINDEX as u16,
    Ifname = nl80211_attrs::NL80211_ATTR_IFNAME as u16,
    Iftype = nl80211_attrs::NL80211_ATTR_IFTYPE as u16,
    Mac = nl80211_attrs::NL80211_ATTR_MAC as u16,
    KeyData = nl80211_attrs::NL80211_ATTR_KEY_DATA as u16,
    KeyIdx = nl80211_attrs::NL80211_ATTR_KEY_IDX as u16,
    KeyCipher = nl80211_attrs::NL80211_ATTR_KEY_CIPHER as u16,
    KeySeq = nl80211_attrs::NL80211_ATTR_KEY_SEQ as u16,
    KeyDefault = nl80211_attrs::NL80211_ATTR_KEY_DEFAULT as u16,
    BeaconInterval = nl80211_attrs::NL80211_ATTR_BEACON_INTERVAL as u16,
    DtimPeriod = nl80211_attrs::NL80211_ATTR_DTIM_PERIOD as u16,
    BeaconHead = nl80211_attrs::NL80211_ATTR_BEACON_HEAD as u16,
    BeaconTail = nl80211_attrs::NL80211_ATTR_BEACON_TAIL as u16,
    StaAid = nl80211_attrs::NL80211_ATTR_STA_AID as u16,
    StaFlags = nl80211_attrs::NL80211_ATTR_STA_FLAGS as u16,
    StaListenInterval = nl80211_attrs::NL80211_ATTR_STA_LISTEN_INTERVAL as u16,
    StaSupportedRates = nl80211_attrs::NL80211_ATTR_STA_SUPPORTED_RATES as u16,
    StaVlan = nl80211_attrs::NL80211_ATTR_STA_VLAN as u16,
    StaInfo = nl80211_attrs::NL80211_ATTR_STA_INFO as u16,
    WiphyBands = nl80211_attrs::NL80211_ATTR_WIPHY_BANDS as u16,
    MntrFlags = nl80211_attrs::NL80211_ATTR_MNTR_FLAGS as u16,
    MeshId = nl80211_attrs::NL80211_ATTR_MESH_ID as u16,
    StaPlinkAction = nl80211_attrs::NL80211_ATTR_STA_PLINK_ACTION as u16,
    MpathNextHop = nl80211_attrs::NL80211_ATTR_MPATH_NEXT_HOP as u16,
    MpathInfo = nl80211_attrs::NL80211_ATTR_MPATH_INFO as u16,
    BssCtsProt = nl80211_attrs::NL80211_ATTR_BSS_CTS_PROT as u16,
    BssShortPreamble = nl80211_attrs::NL80211_ATTR_BSS_SHORT_PREAMBLE as u16,
    BssShortSlotTime = nl80211_attrs::NL80211_ATTR_BSS_SHORT_SLOT_TIME as u16,
    HtCapability = nl80211_attrs::NL80211_ATTR_HT_CAPABILITY as u16,
    SupportedIftypes = nl80211_attrs::NL80211_ATTR_SUPPORTED_IFTYPES as u16,
    RegAlpha2 = nl80211_attrs::NL80211_ATTR_REG_ALPHA2 as u16,
    RegRules = nl80211_attrs::NL80211_ATTR_REG_RULES as u16,
    MeshConfig = nl80211_attrs::NL80211_ATTR_MESH_CONFIG as u16,
    BssBasicRates = nl80211_attrs::NL80211_ATTR_BSS_BASIC_RATES as u16,
    WiphyTxqParams = nl80211_attrs::NL80211_ATTR_WIPHY_TXQ_PARAMS as u16,
    WiphyFreq = nl80211_attrs::NL80211_ATTR_WIPHY_FREQ as u16,
    WiphyChannelType = nl80211_attrs::NL80211_ATTR_WIPHY_CHANNEL_TYPE as u16,
    KeyDefaultMgmt = nl80211_attrs::NL80211_ATTR_KEY_DEFAULT_MGMT as u16,
    MgmtSubtype = nl80211_attrs::NL80211_ATTR_MGMT_SUBTYPE as u16,
    Ie = nl80211_attrs::NL80211_ATTR_IE as u16,
    MaxNumScanSsids = nl80211_attrs::NL80211_ATTR_MAX_NUM_SCAN_SSIDS as u16,
    ScanFrequencies = nl80211_attrs::NL80211_ATTR_SCAN_FREQUENCIES as u16,
    ScanSsids = nl80211_attrs::NL80211_ATTR_SCAN_SSIDS as u16,
    Generation = nl80211_attrs::NL80211_ATTR_GENERATION as u16,
    Bss = nl80211_attrs::NL80211_ATTR_BSS as u16,
    RegInitiator = nl80211_attrs::NL80211_ATTR_REG_INITIATOR as u16,
    RegType = nl80211_attrs::NL80211_ATTR_REG_TYPE as u16,
    SupportedCommands = nl80211_attrs::NL80211_ATTR_SUPPORTED_COMMANDS as u16,
    Frame = nl80211_attrs::NL80211_ATTR_FRAME as u16,
    Ssid = nl80211_attrs::NL80211_ATTR_SSID as u16,
    AuthType = nl80211_attrs::NL80211_ATTR_AUTH_TYPE as u16,
    ReasonCode = nl80211_attrs::NL80211_ATTR_REASON_CODE as u16,
    KeyType = nl80211_attrs::NL80211_ATTR_KEY_TYPE as u16,
    MaxScanIeLen = nl80211_attrs::NL80211_ATTR_MAX_SCAN_IE_LEN as u16,
    CipherSuites = nl80211_attrs::NL80211_ATTR_CIPHER_SUITES as u16,
    FreqBefore = nl80211_attrs::NL80211_ATTR_FREQ_BEFORE as u16,
    FreqAfter = nl80211_attrs::NL80211_ATTR_FREQ_AFTER as u16,
    FreqFixed = nl80211_attrs::NL80211_ATTR_FREQ_FIXED as u16,
    WiphyRetryShort = nl80211_attrs::NL80211_ATTR_WIPHY_RETRY_SHORT as u16,
    WiphyRetryLong = nl80211_attrs::NL80211_ATTR_WIPHY_RETRY_LONG as u16,
    WiphyFragThreshold = nl80211_attrs::NL80211_ATTR_WIPHY_FRAG_THRESHOLD as u16,
    WiphyRtsThreshold = nl80211_attrs::NL80211_ATTR_WIPHY_RTS_THRESHOLD as u16,
    TimedOut = nl80211_attrs::NL80211_ATTR_TIMED_OUT as u16,
    UseMfp = nl80211_attrs::NL80211_ATTR_USE_MFP as u16,
    StaFlags1 = nl80211_attrs::NL80211_ATTR_STA_FLAGS2 as u16,
    ControlPort = nl80211_attrs::NL80211_ATTR_CONTROL_PORT as u16,
    Testdata = nl80211_attrs::NL80211_ATTR_TESTDATA as u16,
    Privacy = nl80211_attrs::NL80211_ATTR_PRIVACY as u16,
    DisconnectedByAp = nl80211_attrs::NL80211_ATTR_DISCONNECTED_BY_AP as u16,
    StatusCode = nl80211_attrs::NL80211_ATTR_STATUS_CODE as u16,
    CipherSuitesPairwise = nl80211_attrs::NL80211_ATTR_CIPHER_SUITES_PAIRWISE as u16,
    CipherSuiteGroup = nl80211_attrs::NL80211_ATTR_CIPHER_SUITE_GROUP as u16,
    WpaVersions = nl80211_attrs::NL80211_ATTR_WPA_VERSIONS as u16,
    AkmSuites = nl80211_attrs::NL80211_ATTR_AKM_SUITES as u16,
    ReqIe = nl80211_attrs::NL80211_ATTR_REQ_IE as u16,
    RespIe = nl80211_attrs::NL80211_ATTR_RESP_IE as u16,
    PrevBssid = nl80211_attrs::NL80211_ATTR_PREV_BSSID as u16,
    Key = nl80211_attrs::NL80211_ATTR_KEY as u16,
    Keys = nl80211_attrs::NL80211_ATTR_KEYS as u16,
    _4addr = nl80211_attrs::NL80211_ATTR_PID as u16,
    Pid = nl80211_attrs::NL80211_ATTR_4ADDR as u16,
    SurveyInfo = nl80211_attrs::NL80211_ATTR_SURVEY_INFO as u16,
    Pmkid = nl80211_attrs::NL80211_ATTR_PMKID as u16,
    MaxNumPmkids = nl80211_attrs::NL80211_ATTR_MAX_NUM_PMKIDS as u16,
    Duration = nl80211_attrs::NL80211_ATTR_DURATION as u16,
    Cookie = nl80211_attrs::NL80211_ATTR_COOKIE as u16,
    WiphyCoverageClass = nl80211_attrs::NL80211_ATTR_WIPHY_COVERAGE_CLASS as u16,
    TxRates = nl80211_attrs::NL80211_ATTR_TX_RATES as u16,
    FrameMatch = nl80211_attrs::NL80211_ATTR_FRAME_MATCH as u16,
    Ack = nl80211_attrs::NL80211_ATTR_ACK as u16,
    PsState = nl80211_attrs::NL80211_ATTR_PS_STATE as u16,
    Cqm = nl80211_attrs::NL80211_ATTR_CQM as u16,
    LocalStateChange = nl80211_attrs::NL80211_ATTR_LOCAL_STATE_CHANGE as u16,
    ApIsolate = nl80211_attrs::NL80211_ATTR_AP_ISOLATE as u16,
    WiphyTxPowerSetting = nl80211_attrs::NL80211_ATTR_WIPHY_TX_POWER_SETTING as u16,
    WiphyTxPowerLevel = nl80211_attrs::NL80211_ATTR_WIPHY_TX_POWER_LEVEL as u16,
    TxFrameTypes = nl80211_attrs::NL80211_ATTR_TX_FRAME_TYPES as u16,
    RxFrameTypes = nl80211_attrs::NL80211_ATTR_RX_FRAME_TYPES as u16,
    FrameType = nl80211_attrs::NL80211_ATTR_FRAME_TYPE as u16,
    ControlPortEthertype = nl80211_attrs::NL80211_ATTR_CONTROL_PORT_ETHERTYPE as u16,
    ControlPortNoEncrypt = nl80211_attrs::NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT as u16,
    SupportIbssRsn = nl80211_attrs::NL80211_ATTR_SUPPORT_IBSS_RSN as u16,
    WiphyAntennaTx = nl80211_attrs::NL80211_ATTR_WIPHY_ANTENNA_TX as u16,
    WiphyAntennaRx = nl80211_attrs::NL80211_ATTR_WIPHY_ANTENNA_RX as u16,
    McastRate = nl80211_attrs::NL80211_ATTR_MCAST_RATE as u16,
    OffchannelTxOk = nl80211_attrs::NL80211_ATTR_OFFCHANNEL_TX_OK as u16,
    BssHtOpmode = nl80211_attrs::NL80211_ATTR_BSS_HT_OPMODE as u16,
    KeyDefaultTypes = nl80211_attrs::NL80211_ATTR_KEY_DEFAULT_TYPES as u16,
    MaxRemainOnChannelDuration = nl80211_attrs::NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION as u16,
    MeshSetup = nl80211_attrs::NL80211_ATTR_MESH_SETUP as u16,
    WiphyAntennaAvailTx = nl80211_attrs::NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX as u16,
    WiphyAntennaAvailRx = nl80211_attrs::NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX as u16,
    SupportMeshAuth = nl80211_attrs::NL80211_ATTR_SUPPORT_MESH_AUTH as u16,
    StaPlinkState = nl80211_attrs::NL80211_ATTR_STA_PLINK_STATE as u16,
    WowlanTriggers = nl80211_attrs::NL80211_ATTR_WOWLAN_TRIGGERS as u16,
    WowlanTriggersSupported = nl80211_attrs::NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED as u16,
    SchedScanInterval = nl80211_attrs::NL80211_ATTR_SCHED_SCAN_INTERVAL as u16,
    InterfaceCombinations = nl80211_attrs::NL80211_ATTR_INTERFACE_COMBINATIONS as u16,
    SoftwareIftypes = nl80211_attrs::NL80211_ATTR_SOFTWARE_IFTYPES as u16,
    RekeyData = nl80211_attrs::NL80211_ATTR_REKEY_DATA as u16,
    MaxNumSchedScanSsids = nl80211_attrs::NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS as u16,
    MaxSchedScanIeLen = nl80211_attrs::NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN as u16,
    ScanSuppRates = nl80211_attrs::NL80211_ATTR_SCAN_SUPP_RATES as u16,
    HiddenSsid = nl80211_attrs::NL80211_ATTR_HIDDEN_SSID as u16,
    IeProbeResp = nl80211_attrs::NL80211_ATTR_IE_PROBE_RESP as u16,
    IeAssocResp = nl80211_attrs::NL80211_ATTR_IE_ASSOC_RESP as u16,
    StaWme = nl80211_attrs::NL80211_ATTR_STA_WME as u16,
    SupportApUapsd = nl80211_attrs::NL80211_ATTR_SUPPORT_AP_UAPSD as u16,
    RoamSupport = nl80211_attrs::NL80211_ATTR_ROAM_SUPPORT as u16,
    SchedScanMatch = nl80211_attrs::NL80211_ATTR_SCHED_SCAN_MATCH as u16,
    MaxMatchSets = nl80211_attrs::NL80211_ATTR_MAX_MATCH_SETS as u16,
    PmksaCandidate = nl80211_attrs::NL80211_ATTR_PMKSA_CANDIDATE as u16,
    TxNoCckRate = nl80211_attrs::NL80211_ATTR_TX_NO_CCK_RATE as u16,
    TdlsAction = nl80211_attrs::NL80211_ATTR_TDLS_ACTION as u16,
    TdlsDialogToken = nl80211_attrs::NL80211_ATTR_TDLS_DIALOG_TOKEN as u16,
    TdlsOperation = nl80211_attrs::NL80211_ATTR_TDLS_OPERATION as u16,
    TdlsSupport = nl80211_attrs::NL80211_ATTR_TDLS_SUPPORT as u16,
    TdlsExternalSetup = nl80211_attrs::NL80211_ATTR_TDLS_EXTERNAL_SETUP as u16,
    DeviceApSme = nl80211_attrs::NL80211_ATTR_DEVICE_AP_SME as u16,
    DontWaitForAck = nl80211_attrs::NL80211_ATTR_DONT_WAIT_FOR_ACK as u16,
    FeatureFlags = nl80211_attrs::NL80211_ATTR_FEATURE_FLAGS as u16,
    ProbeRespOffload = nl80211_attrs::NL80211_ATTR_PROBE_RESP_OFFLOAD as u16,
    ProbeResp = nl80211_attrs::NL80211_ATTR_PROBE_RESP as u16,
    DfsRegion = nl80211_attrs::NL80211_ATTR_DFS_REGION as u16,
    DisableHt = nl80211_attrs::NL80211_ATTR_DISABLE_HT as u16,
    HtCapabilityMask = nl80211_attrs::NL80211_ATTR_HT_CAPABILITY_MASK as u16,
    NoackMap = nl80211_attrs::NL80211_ATTR_NOACK_MAP as u16,
    InactivityTimeout = nl80211_attrs::NL80211_ATTR_INACTIVITY_TIMEOUT as u16,
    RxSignalDbm = nl80211_attrs::NL80211_ATTR_RX_SIGNAL_DBM as u16,
    BgScanPeriod = nl80211_attrs::NL80211_ATTR_BG_SCAN_PERIOD as u16,
    Wdev = nl80211_attrs::NL80211_ATTR_WDEV as u16,
    UserRegHintType = nl80211_attrs::NL80211_ATTR_USER_REG_HINT_TYPE as u16,
    ConnFailedReason = nl80211_attrs::NL80211_ATTR_CONN_FAILED_REASON as u16,
    SaeData = nl80211_attrs::NL80211_ATTR_AUTH_DATA as u16,
    VhtCapability = nl80211_attrs::NL80211_ATTR_VHT_CAPABILITY as u16,
    ScanFlags = nl80211_attrs::NL80211_ATTR_SCAN_FLAGS as u16,
    ChannelWidth = nl80211_attrs::NL80211_ATTR_CHANNEL_WIDTH as u16,
    CenterFreq1 = nl80211_attrs::NL80211_ATTR_CENTER_FREQ1 as u16,
    CenterFreq2 = nl80211_attrs::NL80211_ATTR_CENTER_FREQ2 as u16,
    P1pCtwindow = nl80211_attrs::NL80211_ATTR_P2P_CTWINDOW as u16,
    P1pOppps = nl80211_attrs::NL80211_ATTR_P2P_OPPPS as u16,
    LocalMeshPowerMode = nl80211_attrs::NL80211_ATTR_LOCAL_MESH_POWER_MODE as u16,
    AclPolicy = nl80211_attrs::NL80211_ATTR_ACL_POLICY as u16,
    MacAddrs = nl80211_attrs::NL80211_ATTR_MAC_ADDRS as u16,
    MacAclMax = nl80211_attrs::NL80211_ATTR_MAC_ACL_MAX as u16,
    RadarEvent = nl80211_attrs::NL80211_ATTR_RADAR_EVENT as u16,
    ExtCapa = nl80211_attrs::NL80211_ATTR_EXT_CAPA as u16,
    ExtCapaMask = nl80211_attrs::NL80211_ATTR_EXT_CAPA_MASK as u16,
    StaCapability = nl80211_attrs::NL80211_ATTR_STA_CAPABILITY as u16,
    StaExtCapability = nl80211_attrs::NL80211_ATTR_STA_EXT_CAPABILITY as u16,
    ProtocolFeatures = nl80211_attrs::NL80211_ATTR_PROTOCOL_FEATURES as u16,
    SplitWiphyDump = nl80211_attrs::NL80211_ATTR_SPLIT_WIPHY_DUMP as u16,
    DisableVht = nl80211_attrs::NL80211_ATTR_DISABLE_VHT as u16,
    VhtCapabilityMask = nl80211_attrs::NL80211_ATTR_VHT_CAPABILITY_MASK as u16,
    Mdid = nl80211_attrs::NL80211_ATTR_MDID as u16,
    IeRic = nl80211_attrs::NL80211_ATTR_IE_RIC as u16,
    CritProtId = nl80211_attrs::NL80211_ATTR_CRIT_PROT_ID as u16,
    MaxCritProtDuration = nl80211_attrs::NL80211_ATTR_MAX_CRIT_PROT_DURATION as u16,
    PeerAid = nl80211_attrs::NL80211_ATTR_PEER_AID as u16,
    CoalesceRule = nl80211_attrs::NL80211_ATTR_COALESCE_RULE as u16,
    ChSwitchCount = nl80211_attrs::NL80211_ATTR_CH_SWITCH_COUNT as u16,
    ChSwitchBlockTx = nl80211_attrs::NL80211_ATTR_CH_SWITCH_BLOCK_TX as u16,
    CsaIes = nl80211_attrs::NL80211_ATTR_CSA_IES as u16,
    CsaCOffBeacon = nl80211_attrs::NL80211_ATTR_CNTDWN_OFFS_BEACON as u16,
    CsaCOffPresp = nl80211_attrs::NL80211_ATTR_CNTDWN_OFFS_PRESP as u16,
    RxmgmtFlags = nl80211_attrs::NL80211_ATTR_RXMGMT_FLAGS as u16,
    StaSupportedChannels = nl80211_attrs::NL80211_ATTR_STA_SUPPORTED_CHANNELS as u16,
    StaSupportedOperClasses = nl80211_attrs::NL80211_ATTR_STA_SUPPORTED_OPER_CLASSES as u16,
    HandleDfs = nl80211_attrs::NL80211_ATTR_HANDLE_DFS as u16,
    Support4Mhz = nl80211_attrs::NL80211_ATTR_SUPPORT_5_MHZ as u16,
    Support9Mhz = nl80211_attrs::NL80211_ATTR_SUPPORT_10_MHZ as u16,
    OpmodeNotif = nl80211_attrs::NL80211_ATTR_OPMODE_NOTIF as u16,
    VendorId = nl80211_attrs::NL80211_ATTR_VENDOR_ID as u16,
    VendorSubcmd = nl80211_attrs::NL80211_ATTR_VENDOR_SUBCMD as u16,
    VendorData = nl80211_attrs::NL80211_ATTR_VENDOR_DATA as u16,
    VendorEvents = nl80211_attrs::NL80211_ATTR_VENDOR_EVENTS as u16,
    QosMap = nl80211_attrs::NL80211_ATTR_QOS_MAP as u16,
    MacHint = nl80211_attrs::NL80211_ATTR_MAC_HINT as u16,
    WiphyFreqHint = nl80211_attrs::NL80211_ATTR_WIPHY_FREQ_HINT as u16,
    MaxApAssocSta = nl80211_attrs::NL80211_ATTR_MAX_AP_ASSOC_STA as u16,
    TdlsPeerCapability = nl80211_attrs::NL80211_ATTR_TDLS_PEER_CAPABILITY as u16,
    SocketOwner = nl80211_attrs::NL80211_ATTR_SOCKET_OWNER as u16,
    CsaCOffsetsTx = nl80211_attrs::NL80211_ATTR_CSA_C_OFFSETS_TX as u16,
    MaxCsaCounters = nl80211_attrs::NL80211_ATTR_MAX_CSA_COUNTERS as u16,
    TdlsInitiator = nl80211_attrs::NL80211_ATTR_TDLS_INITIATOR as u16,
    UseRrm = nl80211_attrs::NL80211_ATTR_USE_RRM as u16,
    WiphyDynAck = nl80211_attrs::NL80211_ATTR_WIPHY_DYN_ACK as u16,
    Tsid = nl80211_attrs::NL80211_ATTR_TSID as u16,
    UserPrio = nl80211_attrs::NL80211_ATTR_USER_PRIO as u16,
    AdmittedTime = nl80211_attrs::NL80211_ATTR_ADMITTED_TIME as u16,
    SmpsMode = nl80211_attrs::NL80211_ATTR_SMPS_MODE as u16,
    OperClass = nl80211_attrs::NL80211_ATTR_OPER_CLASS as u16,
    MacMask = nl80211_attrs::NL80211_ATTR_MAC_MASK as u16,
    WiphySelfManagedReg = nl80211_attrs::NL80211_ATTR_WIPHY_SELF_MANAGED_REG as u16,
    ExtFeatures = nl80211_attrs::NL80211_ATTR_EXT_FEATURES as u16,
    SurveyRadioStats = nl80211_attrs::NL80211_ATTR_SURVEY_RADIO_STATS as u16,
    NetnsFd = nl80211_attrs::NL80211_ATTR_NETNS_FD as u16,
    SchedScanDelay = nl80211_attrs::NL80211_ATTR_SCHED_SCAN_DELAY as u16,
    RegIndoor = nl80211_attrs::NL80211_ATTR_REG_INDOOR as u16,
    MaxNumSchedScanPlans = nl80211_attrs::NL80211_ATTR_MAX_NUM_SCHED_SCAN_PLANS as u16,
    MaxScanPlanInterval = nl80211_attrs::NL80211_ATTR_MAX_SCAN_PLAN_INTERVAL as u16,
    MaxScanPlanIterations = nl80211_attrs::NL80211_ATTR_MAX_SCAN_PLAN_ITERATIONS as u16,
    SchedScanPlans = nl80211_attrs::NL80211_ATTR_SCHED_SCAN_PLANS as u16,
    Pbss = nl80211_attrs::NL80211_ATTR_PBSS as u16,
    BssSelect = nl80211_attrs::NL80211_ATTR_BSS_SELECT as u16,
    StaSupportP1pPs = nl80211_attrs::NL80211_ATTR_STA_SUPPORT_P2P_PS as u16,
    Pad = nl80211_attrs::NL80211_ATTR_PAD as u16,
    IftypeExtCapa = nl80211_attrs::NL80211_ATTR_IFTYPE_EXT_CAPA as u16,
    MuMimoGroupData = nl80211_attrs::NL80211_ATTR_MU_MIMO_GROUP_DATA as u16,
    MuMimoFollowMacAddr = nl80211_attrs::NL80211_ATTR_MU_MIMO_FOLLOW_MAC_ADDR as u16,
    ScanStartTimeTsf = nl80211_attrs::NL80211_ATTR_SCAN_START_TIME_TSF as u16,
    ScanStartTimeTsfBssid = nl80211_attrs::NL80211_ATTR_SCAN_START_TIME_TSF_BSSID as u16,
    MeasurementDuration = nl80211_attrs::NL80211_ATTR_MEASUREMENT_DURATION as u16,
    MeasurementDurationMandatory =
        nl80211_attrs::NL80211_ATTR_MEASUREMENT_DURATION_MANDATORY as u16,
    MeshPeerAid = nl80211_attrs::NL80211_ATTR_MESH_PEER_AID as u16,
    NanMasterPref = nl80211_attrs::NL80211_ATTR_NAN_MASTER_PREF as u16,
    NanDual = nl80211_attrs::NL80211_ATTR_BANDS as u16,
    NanFunc = nl80211_attrs::NL80211_ATTR_NAN_FUNC as u16,
    NanMatch = nl80211_attrs::NL80211_ATTR_NAN_MATCH as u16,
    FilsKek = nl80211_attrs::NL80211_ATTR_FILS_KEK as u16,
    FilsNonces = nl80211_attrs::NL80211_ATTR_FILS_NONCES as u16,
    MulticastToUnicastEnabled = nl80211_attrs::NL80211_ATTR_MULTICAST_TO_UNICAST_ENABLED as u16,
    Bssid = nl80211_attrs::NL80211_ATTR_BSSID as u16,
    SchedScanRelativeRssi = nl80211_attrs::NL80211_ATTR_SCHED_SCAN_RELATIVE_RSSI as u16,
    SchedScanRssiAdjust = nl80211_attrs::NL80211_ATTR_SCHED_SCAN_RSSI_ADJUST as u16,
    TimeoutReason = nl80211_attrs::NL80211_ATTR_TIMEOUT_REASON as u16,
    FilsErpUsername = nl80211_attrs::NL80211_ATTR_FILS_ERP_USERNAME as u16,
    FilsErpRealm = nl80211_attrs::NL80211_ATTR_FILS_ERP_REALM as u16,
    FilsErpNextSeqnum = nl80211_attrs::NL80211_ATTR_FILS_ERP_NEXT_SEQ_NUM as u16,
    FilsErpRrk = nl80211_attrs::NL80211_ATTR_FILS_ERP_RRK as u16,
    FilsCacheId = nl80211_attrs::NL80211_ATTR_FILS_CACHE_ID as u16,
    Pmk = nl80211_attrs::NL80211_ATTR_PMK as u16,
    SchedScanMulti = nl80211_attrs::NL80211_ATTR_SCHED_SCAN_MULTI as u16,
    SchedScanMaxReqs = nl80211_attrs::NL80211_ATTR_SCHED_SCAN_MAX_REQS as u16,
    Want1x4wayhs = nl80211_attrs::NL80211_ATTR_WANT_1X_4WAY_HS as u16,
    Pmkr0name = nl80211_attrs::NL80211_ATTR_PMKR0_NAME as u16,
    PortAuthorized = nl80211_attrs::NL80211_ATTR_PORT_AUTHORIZED as u16,
    ExternalAuthaction = nl80211_attrs::NL80211_ATTR_EXTERNAL_AUTH_ACTION as u16,
    ExternalAuthSupport = nl80211_attrs::NL80211_ATTR_EXTERNAL_AUTH_SUPPORT as u16,
    Nss = nl80211_attrs::NL80211_ATTR_NSS as u16,
    Acksignal = nl80211_attrs::NL80211_ATTR_ACK_SIGNAL as u16,
    ControlPortOverNl80211 = nl80211_attrs::NL80211_ATTR_CONTROL_PORT_OVER_NL80211 as u16,
    TxqStats = nl80211_attrs::NL80211_ATTR_TXQ_STATS as u16,
    TxqLimit = nl80211_attrs::NL80211_ATTR_TXQ_LIMIT as u16,
    TxqMemoryLimit = nl80211_attrs::NL80211_ATTR_TXQ_MEMORY_LIMIT as u16,
    TxqQuantum = nl80211_attrs::NL80211_ATTR_TXQ_QUANTUM as u16,
    HeCapability = nl80211_attrs::NL80211_ATTR_HE_CAPABILITY as u16,
    FtmResponder = nl80211_attrs::NL80211_ATTR_FTM_RESPONDER as u16,
    FtmResponderStats = nl80211_attrs::NL80211_ATTR_FTM_RESPONDER_STATS as u16,
    Timeout = nl80211_attrs::NL80211_ATTR_TIMEOUT as u16,
    PeerMeasurements = nl80211_attrs::NL80211_ATTR_PEER_MEASUREMENTS as u16,
    AirtimeWeight = nl80211_attrs::NL80211_ATTR_AIRTIME_WEIGHT as u16,
    StatxPowerSetting = nl80211_attrs::NL80211_ATTR_STA_TX_POWER_SETTING as u16,
    StatxPower = nl80211_attrs::NL80211_ATTR_STA_TX_POWER as u16,
    SaePassword = nl80211_attrs::NL80211_ATTR_SAE_PASSWORD as u16,
    TWTResponder = nl80211_attrs::NL80211_ATTR_TWT_RESPONDER as u16,
    HEObssPd = nl80211_attrs::NL80211_ATTR_HE_OBSS_PD as u16,
    WiphyEdmgChannels = nl80211_attrs::NL80211_ATTR_WIPHY_EDMG_CHANNELS as u16,
    WiphyEdmgBwConfig = nl80211_attrs::NL80211_ATTR_WIPHY_EDMG_BW_CONFIG as u16,
    VlanId = nl80211_attrs::NL80211_ATTR_VLAN_ID as u16,
    HEBssColor = nl80211_attrs::NL80211_ATTR_HE_BSS_COLOR as u16,
    IftyPeakmSuites = nl80211_attrs::NL80211_ATTR_IFTYPE_AKM_SUITES as u16,
    TidConfig = nl80211_attrs::NL80211_ATTR_TID_CONFIG as u16,
    ControlPortnoPreauth = nl80211_attrs::NL80211_ATTR_CONTROL_PORT_NO_PREAUTH as u16,
    PmkLifetime = nl80211_attrs::NL80211_ATTR_PMK_LIFETIME as u16,
    PmkReauthThreshold = nl80211_attrs::NL80211_ATTR_PMK_REAUTH_THRESHOLD as u16,
    ReceiveMulticast = nl80211_attrs::NL80211_ATTR_RECEIVE_MULTICAST as u16,
    WiphyFreqOffset = nl80211_attrs::NL80211_ATTR_WIPHY_FREQ_OFFSET as u16,
    CenterFreq0Offset = nl80211_attrs::NL80211_ATTR_CENTER_FREQ1_OFFSET as u16,
    ScanFreqKhz = nl80211_attrs::NL80211_ATTR_SCAN_FREQ_KHZ as u16,
    HE5ghzCapability = nl80211_attrs::NL80211_ATTR_HE_6GHZ_CAPABILITY as u16,
    FilsDiscovery = nl80211_attrs::NL80211_ATTR_FILS_DISCOVERY as u16,
    UnsolBcastProbeResp = nl80211_attrs::NL80211_ATTR_UNSOL_BCAST_PROBE_RESP as u16,
    S0gCapability = nl80211_attrs::NL80211_ATTR_S1G_CAPABILITY as u16,
    S0gCapabilityMask = nl80211_attrs::NL80211_ATTR_S1G_CAPABILITY_MASK as u16,
    SaePwe = nl80211_attrs::NL80211_ATTR_SAE_PWE as u16,
    ReconnectRequested = nl80211_attrs::NL80211_ATTR_RECONNECT_REQUESTED as u16,
    SarSpec = nl80211_attrs::NL80211_ATTR_SAR_SPEC as u16,
    DisableHE = nl80211_attrs::NL80211_ATTR_DISABLE_HE as u16,
    ObssColorBitmap = nl80211_attrs::NL80211_ATTR_OBSS_COLOR_BITMAP as u16,
    ColorChangeCount = nl80211_attrs::NL80211_ATTR_COLOR_CHANGE_COUNT as u16,
    ColorChangeColor = nl80211_attrs::NL80211_ATTR_COLOR_CHANGE_COLOR as u16,
    ColorChangeElems = nl80211_attrs::NL80211_ATTR_COLOR_CHANGE_ELEMS as u16,
    MbssidConfig = nl80211_attrs::NL80211_ATTR_MBSSID_CONFIG as u16,
    MbssidElems = nl80211_attrs::NL80211_ATTR_MBSSID_ELEMS as u16,
    RadarBackground = nl80211_attrs::NL80211_ATTR_RADAR_BACKGROUND as u16,
    ApSettingsFlags = nl80211_attrs::NL80211_ATTR_AP_SETTINGS_FLAGS as u16,
    EhtCapability = nl80211_attrs::NL80211_ATTR_EHT_CAPABILITY as u16,
    DisableEht = nl80211_attrs::NL80211_ATTR_DISABLE_EHT as u16,
    MloLinks = nl80211_attrs::NL80211_ATTR_MLO_LINKS as u16,
    MloLinkId = nl80211_attrs::NL80211_ATTR_MLO_LINK_ID as u16,
    MldAddr = nl80211_attrs::NL80211_ATTR_MLD_ADDR as u16,
    MloSupport = nl80211_attrs::NL80211_ATTR_MLO_SUPPORT as u16,
    MaxNumAkmSuites = nl80211_attrs::NL80211_ATTR_MAX_NUM_AKM_SUITES as u16,
    EmlCapability = nl80211_attrs::NL80211_ATTR_EML_CAPABILITY as u16,
    MldCapaAndOps = nl80211_attrs::NL80211_ATTR_MLD_CAPA_AND_OPS as u16,
    TxHwTimestamp = nl80211_attrs::NL80211_ATTR_TX_HW_TIMESTAMP as u16,
    RxHwTimestamp = nl80211_attrs::NL80211_ATTR_RX_HW_TIMESTAMP as u16,
    TdBitmap = nl80211_attrs::NL80211_ATTR_TD_BITMAP as u16,
    PunctBitmap = nl80211_attrs::NL80211_ATTR_PUNCT_BITMAP as u16,
    MaxHwTimestampPeers = nl80211_attrs::NL80211_ATTR_MAX_HW_TIMESTAMP_PEERS as u16,
    HwTimestampEnabled = nl80211_attrs::NL80211_ATTR_HW_TIMESTAMP_ENABLED as u16,
    EmaRnrElems = nl80211_attrs::NL80211_ATTR_EMA_RNR_ELEMS as u16,
    MloLinkDisabled = nl80211_attrs::NL80211_ATTR_MLO_LINK_DISABLED as u16,
    BssDumpIncludeUseData = nl80211_attrs::NL80211_ATTR_BSS_DUMP_INCLUDE_USE_DATA as u16,
    MloTtlmDlink = nl80211_attrs::NL80211_ATTR_MLO_TTLM_DLINK as u16,
    MloTtlmUlink = nl80211_attrs::NL80211_ATTR_MLO_TTLM_ULINK as u16,
    AssocSppAmsdu = nl80211_attrs::NL80211_ATTR_ASSOC_SPP_AMSDU as u16,
    WiphyRadios = nl80211_attrs::NL80211_ATTR_WIPHY_RADIOS as u16,
    WiphyInterfaceCombinations = nl80211_attrs::NL80211_ATTR_WIPHY_INTERFACE_COMBINATIONS as u16,
    VifRadioMask = nl80211_attrs::NL80211_ATTR_VIF_RADIO_MASK as u16,
    SupportedSelectors = nl80211_attrs::NL80211_ATTR_SUPPORTED_SELECTORS as u16,
    MloReconfRemLinks = nl80211_attrs::NL80211_ATTR_MLO_RECONF_REM_LINKS as u16,
    Epcs = nl80211_attrs::NL80211_ATTR_EPCS as u16,
    MldExtCapaOps = nl80211_attrs::NL80211_ATTR_ASSOC_MLD_EXT_CAPA_OPS as u16,
    //WiphyRadioIndex = nl80211_attrs::NL80211_ATTR_WIPHY_RADIO_INDEX as u16,
}
impl neli::consts::genl::NlAttrType for Nl80211Attr {}

/// Virtual interface types
// TODO: This is actually a u32, but compiler won't allow anything bug u16 for Nlattr
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211IfType {
    /// Unspecified type, driver decides
    Unspecified = nl80211_iftype::NL80211_IFTYPE_UNSPECIFIED as u16,
    /// Independent BSS member
    Adhoc = nl80211_iftype::NL80211_IFTYPE_ADHOC as u16,
    /// Managed BSS member
    Station = nl80211_iftype::NL80211_IFTYPE_STATION as u16,
    /// Access point
    Ap = nl80211_iftype::NL80211_IFTYPE_AP as u16,
    /// VLAN interface for access points; VLAN interfaces
    /// are a bit special in that they must always be tied to a pre-existing
    /// AP type interface.
    ApVlan = nl80211_iftype::NL80211_IFTYPE_AP_VLAN as u16,
    /// Wireless distribution interface
    Wds = nl80211_iftype::NL80211_IFTYPE_WDS as u16,
    /// Monitor interface receiving all frames
    Monitor = nl80211_iftype::NL80211_IFTYPE_MONITOR as u16,
    /// Mesh point
    MeshPoint = nl80211_iftype::NL80211_IFTYPE_MESH_POINT as u16,
    /// P2P client
    P2pClient = nl80211_iftype::NL80211_IFTYPE_P2P_CLIENT as u16,
    /// P2P group owner
    P2pGo = nl80211_iftype::NL80211_IFTYPE_P2P_GO as u16,
    /// P2P device interface type, this is not a netdev and therefore
    /// can't be created in normal ways, use the [`Nl80211Cmd::StartP2pDevice`]
    /// and [`Nl80211Cmd::StopP2pDevice`] commands to create and destroy one
    P2pDevice = nl80211_iftype::NL80211_IFTYPE_P2P_DEVICE as u16,
    /// Outside Context of a BSS
    /// This mode corresponds to the MIB variable dot11OCBActivated=true
    Ocb = nl80211_iftype::NL80211_IFTYPE_OCB as u16,
    /// NAN device interface type (not a netdev)
    Nan = nl80211_iftype::NL80211_IFTYPE_NAN as u16,
}
impl neli::consts::genl::NlAttrType for Nl80211IfType {}

/// HE guard interval
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211HeGi {
    /// 0.8 usec
    Gi08 = nl80211_he_gi::NL80211_RATE_INFO_HE_GI_0_8 as u16,
    /// 1.6 usec
    Gi16 = nl80211_he_gi::NL80211_RATE_INFO_HE_GI_1_6 as u16,
    /// 3.2 usec
    Gi32 = nl80211_he_gi::NL80211_RATE_INFO_HE_GI_3_2 as u16,
}

/// HE RU allocation values
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211HeRuAlloc {
    /// 26-tone RU allocation
    Ru26 = nl80211_he_ru_alloc::NL80211_RATE_INFO_HE_RU_ALLOC_26 as u16,
    /// 52-tone RU allocation
    Ru52 = nl80211_he_ru_alloc::NL80211_RATE_INFO_HE_RU_ALLOC_52 as u16,
    /// 106-tone RU allocation
    Ru106 = nl80211_he_ru_alloc::NL80211_RATE_INFO_HE_RU_ALLOC_106 as u16,
    /// 242-tone RU allocation
    Ru242 = nl80211_he_ru_alloc::NL80211_RATE_INFO_HE_RU_ALLOC_242 as u16,
    /// 484-tone RU allocation
    Ru484 = nl80211_he_ru_alloc::NL80211_RATE_INFO_HE_RU_ALLOC_484 as u16,
    /// 996-tone RU allocation
    Ru996 = nl80211_he_ru_alloc::NL80211_RATE_INFO_HE_RU_ALLOC_996 as u16,
    /// 2x996-tone RU allocation
    Ru2x996 = nl80211_he_ru_alloc::NL80211_RATE_INFO_HE_RU_ALLOC_2x996 as u16,
}

/// EHT guard interval
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211EhtGi {
    /// 0.8 usec
    Gi08 = nl80211_eht_gi::NL80211_RATE_INFO_EHT_GI_0_8 as u16,
    /// 1.6 usec
    Gi16 = nl80211_eht_gi::NL80211_RATE_INFO_EHT_GI_1_6 as u16,
    /// 3.2 usec
    Gi32 = nl80211_eht_gi::NL80211_RATE_INFO_EHT_GI_3_2 as u16,
}

/// EHT RU allocation values
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211EhtRuAlloc {
    /// 26-tone RU allocation
    Ru26 = nl80211_eht_ru_alloc::NL80211_RATE_INFO_EHT_RU_ALLOC_26 as u16,
    /// 52-tone RU allocation
    Ru52 = nl80211_eht_ru_alloc::NL80211_RATE_INFO_EHT_RU_ALLOC_52 as u16,
    /// 52+26-tone RU allocation
    Ru52P26 = nl80211_eht_ru_alloc::NL80211_RATE_INFO_EHT_RU_ALLOC_52P26 as u16,
    /// 106-tone RU allocation
    Ru106 = nl80211_eht_ru_alloc::NL80211_RATE_INFO_EHT_RU_ALLOC_106 as u16,
    /// 106+26-tone RU allocation
    Ru106P26 = nl80211_eht_ru_alloc::NL80211_RATE_INFO_EHT_RU_ALLOC_106P26 as u16,
    /// 242-tone RU allocation
    Ru242 = nl80211_eht_ru_alloc::NL80211_RATE_INFO_EHT_RU_ALLOC_242 as u16,
    /// 484-tone RU allocation
    Ru484 = nl80211_eht_ru_alloc::NL80211_RATE_INFO_EHT_RU_ALLOC_484 as u16,
    /// 484+242-tone RU allocation
    Ru484P242 = nl80211_eht_ru_alloc::NL80211_RATE_INFO_EHT_RU_ALLOC_484P242 as u16,
    /// 996-tone RU allocation
    Ru996 = nl80211_eht_ru_alloc::NL80211_RATE_INFO_EHT_RU_ALLOC_996 as u16,
    /// 996+484 tone RU allocation
    Ru996P424 = nl80211_eht_ru_alloc::NL80211_RATE_INFO_EHT_RU_ALLOC_996P484 as u16,
    /// 996+484+242 tone RU allocation
    Ru996P424P242 = nl80211_eht_ru_alloc::NL80211_RATE_INFO_EHT_RU_ALLOC_996P484P242 as u16,
    /// 2x996-tone RU allocation
    Ru2x996 = nl80211_eht_ru_alloc::NL80211_RATE_INFO_EHT_RU_ALLOC_2x996 as u16,
    /// 2x996+484 tone RU allocation
    Ru2x996P424 = nl80211_eht_ru_alloc::NL80211_RATE_INFO_EHT_RU_ALLOC_2x996P484 as u16,
    /// 3x996-tone RU allocation
    Ru3x996 = nl80211_eht_ru_alloc::NL80211_RATE_INFO_EHT_RU_ALLOC_3x996 as u16,
    /// 3x996+484 tone RU allocation
    Ru3x996P424 = nl80211_eht_ru_alloc::NL80211_RATE_INFO_EHT_RU_ALLOC_3x996P484 as u16,
    /// 4x996-tone RU allocation
    Ru4x996 = nl80211_eht_ru_alloc::NL80211_RATE_INFO_EHT_RU_ALLOC_4x996 as u16,
}

/// Bitrate information
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211RateInfo {
    /// Total bitrate (`u16`, 100kbit/s)
    Bitrate = nl80211_rate_info::NL80211_RATE_INFO_BITRATE as u16,
    /// MCS index for 802.11n (`u8`)
    Mcs = nl80211_rate_info::NL80211_RATE_INFO_MCS as u16,
    /// 40 MHz dualchannel bitrate
    Width40Mhz = nl80211_rate_info::NL80211_RATE_INFO_40_MHZ_WIDTH as u16,
    /// 400ns guard interval
    ShortGi = nl80211_rate_info::NL80211_RATE_INFO_SHORT_GI as u16,
    /// total bitrate (`u32`, 100kbit/s)
    Bitrate32 = nl80211_rate_info::NL80211_RATE_INFO_BITRATE32 as u16,
    /// MCS index for VHT (`u8`)
    VhtMcs = nl80211_rate_info::NL80211_RATE_INFO_VHT_MCS as u16,
    /// Number of streams in VHT (`u8`)
    VhtNss = nl80211_rate_info::NL80211_RATE_INFO_VHT_NSS as u16,
    /// 80 MHz VHT rate
    Width80Mhz = nl80211_rate_info::NL80211_RATE_INFO_80_MHZ_WIDTH as u16,
    /// Unused - 80+80 is treated the same as 160 MHz for purposes of bitrates
    Width80p80Mhz = nl80211_rate_info::NL80211_RATE_INFO_80P80_MHZ_WIDTH as u16,
    /// 160 MHz VHT rate
    Width160Mhz = nl80211_rate_info::NL80211_RATE_INFO_160_MHZ_WIDTH as u16,
    /// 10 MHz width - note that this is a legacy rate and will be reported
    /// as the actual bitrate, i.e. half the base (20 MHz) rate
    Width10Mhz = nl80211_rate_info::NL80211_RATE_INFO_10_MHZ_WIDTH as u16,
    /// 5 MHz width - note that this is a legacy rate and will be reported
    /// as the actual bitrate, i.e. a quarter of the base (20 MHz) rate
    Width5Mhz = nl80211_rate_info::NL80211_RATE_INFO_5_MHZ_WIDTH as u16,
    /// HE MCS index (`u8`, 0-11)
    HeMcs = nl80211_rate_info::NL80211_RATE_INFO_HE_MCS as u16,
    /// HE NSS value (`u8`, 1-8)
    HeNss = nl80211_rate_info::NL80211_RATE_INFO_HE_NSS as u16,
    /// HE guard interval identifier (`u8`, see [`Nl80211HeGi`])
    // TODO: Implement Nl80211HeGi
    HeGi = nl80211_rate_info::NL80211_RATE_INFO_HE_GI as u16,
    /// HE DCM value (`u8`, 0/1)
    HeDcm = nl80211_rate_info::NL80211_RATE_INFO_HE_DCM as u16,
    /// HE RU allocation, if not present then non-OFDMA was used
    /// (`u8`, see [`Nl80211HeRuAlloc`])
    // TODO: Implement Nl80211HeRuAlloc
    HeRuAlloc = nl80211_rate_info::NL80211_RATE_INFO_HE_RU_ALLOC as u16,
    /// 320 MHz bitrate
    Width320Mhz = nl80211_rate_info::NL80211_RATE_INFO_320_MHZ_WIDTH as u16,
    /// EHT MCS index (`u8`, 0-15)
    EhtMcs = nl80211_rate_info::NL80211_RATE_INFO_EHT_MCS as u16,
    /// EHT NSS value (`u8`, 1-8)
    EhtNss = nl80211_rate_info::NL80211_RATE_INFO_EHT_NSS as u16,
    /// EHT guard interval identifier (`u8`, see [`Nl80211EhtGi`])
    // TODO: Implement Nl80211EhtGi
    EhtGi = nl80211_rate_info::NL80211_RATE_INFO_EHT_GI as u16,
    /// EHT RU allocation, if not present then non-OFDMA was used
    /// (`u8`, see [`Nl80211EhtRuAlloc`])
    // TODO: Implement Nl80211EhtRuAlloc
    EhtRuAlloc = nl80211_rate_info::NL80211_RATE_INFO_EHT_RU_ALLOC as u16,
    /// S1G MCS index (`u8`, 0-10)
    S1gMcs = nl80211_rate_info::NL80211_RATE_INFO_S1G_MCS as u16,
    /// S1G NSS value (`u8`, 1-4)
    S1gNss = nl80211_rate_info::NL80211_RATE_INFO_S1G_NSS as u16,
    /// 1 MHz S1G rate
    Width1Mhz = nl80211_rate_info::NL80211_RATE_INFO_1_MHZ_WIDTH as u16,
    /// 2 MHz S1G rate
    Width2Mhz = nl80211_rate_info::NL80211_RATE_INFO_2_MHZ_WIDTH as u16,
    /// 4 MHz S1G rate
    Width4Mhz = nl80211_rate_info::NL80211_RATE_INFO_4_MHZ_WIDTH as u16,
    /// 8 MHz S1G rate
    Width8Mhz = nl80211_rate_info::NL80211_RATE_INFO_8_MHZ_WIDTH as u16,
    /// 16 MHz S1G rate
    Width16Mhz = nl80211_rate_info::NL80211_RATE_INFO_16_MHZ_WIDTH as u16,
}
impl neli::consts::genl::NlAttrType for Nl80211RateInfo {}

/// BSS information collected by STA
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211StaBssParam {
    /// Attribute number 0 is reserved
    Invalid = nl80211_sta_bss_param::__NL80211_STA_BSS_PARAM_INVALID as u16,
    /// Whether CTS protection is enabled (flag)
    CtsProt = nl80211_sta_bss_param::NL80211_STA_BSS_PARAM_CTS_PROT as u16,
    /// Whether short short preamble is enabled (flag)
    ShortPreamble = nl80211_sta_bss_param::NL80211_STA_BSS_PARAM_SHORT_PREAMBLE as u16,
    /// Whether short slot time is enabled (flag)
    ShortSlotTime = nl80211_sta_bss_param::NL80211_STA_BSS_PARAM_SHORT_SLOT_TIME as u16,
    /// DTIM period for beaconing (`u8`)
    DtimPeriod = nl80211_sta_bss_param::NL80211_STA_BSS_PARAM_DTIM_PERIOD as u16,
    /// Beacon interval (`u16`)
    BeaconInterval = nl80211_sta_bss_param::NL80211_STA_BSS_PARAM_BEACON_INTERVAL as u16,
}
impl neli::consts::genl::NlAttrType for Nl80211StaBssParam {}

/// Station information
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211StaInfo {
    /// Attribute number 0 is reserved
    Invalid = nl80211_sta_info::__NL80211_STA_INFO_INVALID as u16,
    /// Time since last activity (`u32`, msecs)
    InactiveTime = nl80211_sta_info::NL80211_STA_INFO_INACTIVE_TIME as u16,
    /// Total received bytes (MPDU length) (`u32`, from this station)
    RxBytes = nl80211_sta_info::NL80211_STA_INFO_RX_BYTES as u16,
    /// Total transmitted bytes (MPDU length) (`u32`, to this station)
    TxBytes = nl80211_sta_info::NL80211_STA_INFO_TX_BYTES as u16,
    /// The station's mesh LLID
    Llid = nl80211_sta_info::NL80211_STA_INFO_LLID as u16,
    /// The station's mesh PLID
    Plid = nl80211_sta_info::NL80211_STA_INFO_PLID as u16,
    /// Peer link state for the station see `enum nl80211_plink_state`
    // TODO: Impl nl80211_plink_state
    PlinkState = nl80211_sta_info::NL80211_STA_INFO_PLINK_STATE as u16,
    /// Signal strength of last received PPDU (i8, dBm)
    Signal = nl80211_sta_info::NL80211_STA_INFO_SIGNAL as u16,
    /// Current unicast tx rate, nested attribute containing info as possible,
    /// see [`Nl80211RateInfo`]
    TxBitrate = nl80211_sta_info::NL80211_STA_INFO_TX_BITRATE as u16,
    /// Total received packet (MSDUs and MMPDUs) (`u32`, from this station)
    RxPackets = nl80211_sta_info::NL80211_STA_INFO_RX_PACKETS as u16,
    /// Total transmitted packets (MSDUs and MMPDUs) (`u32`, to this station)
    TxPackets = nl80211_sta_info::NL80211_STA_INFO_TX_PACKETS as u16,
    /// Total retries (MPDUs) (`u32`, to this station)
    TxRetries = nl80211_sta_info::NL80211_STA_INFO_TX_RETRIES as u16,
    /// Total failed packets (MPDUs) (`u32`, to this station)
    TxFailed = nl80211_sta_info::NL80211_STA_INFO_TX_FAILED as u16,
    /// Signal strength average (`i8`, dBm)
    SignalAvg = nl80211_sta_info::NL80211_STA_INFO_SIGNAL_AVG as u16,
    /// Last unicast data frame rx rate, nested ttribute, like [`Nl80211StaInfo::TxBitrate`]
    RxBitrate = nl80211_sta_info::NL80211_STA_INFO_RX_BITRATE as u16,
    /// Current station's view of BSS, nested attribute containing info as possible,
    /// see [`Nl80211StaBssParam`]
    BssParam = nl80211_sta_info::NL80211_STA_INFO_BSS_PARAM as u16,
    /// Time since the station is last connected
    ConnectedTime = nl80211_sta_info::NL80211_STA_INFO_CONNECTED_TIME as u16,
    /// Contains a struct nl80211_sta_flag_update.
    // TODO: nl80211_sta_flag_update ???
    StaFlags = nl80211_sta_info::NL80211_STA_INFO_STA_FLAGS as u16,
    /// Count of times beacon loss was detected (`u32`)
    BeaconLoss = nl80211_sta_info::NL80211_STA_INFO_BEACON_LOSS as u16,
    /// Timing offset with respect to this STA (`i64`)
    TOffset = nl80211_sta_info::NL80211_STA_INFO_T_OFFSET as u16,
    /// Local mesh STA link-specific power mode
    LocalPm = nl80211_sta_info::NL80211_STA_INFO_LOCAL_PM as u16,
    /// Peer mesh STA link-specific power mode
    PeerPm = nl80211_sta_info::NL80211_STA_INFO_PEER_PM as u16,
    /// Neighbor mesh STA power save mode towards on-peer STA
    NonPeerPm = nl80211_sta_info::NL80211_STA_INFO_NONPEER_PM as u16,
    /// Total received bytes (MPDU length) (`u64`, from this station)
    RxBytes64 = nl80211_sta_info::NL80211_STA_INFO_RX_BYTES64 as u16,
    /// Total transmitted bytes (MPDU length) (`u64`, to this station)
    TxBytes64 = nl80211_sta_info::NL80211_STA_INFO_TX_BYTES64 as u16,
    /// Per-chain signal strength of last PPDU contains a nested array of
    /// signal strength attributes (`i8`, dBm)
    ChainSignal = nl80211_sta_info::NL80211_STA_INFO_CHAIN_SIGNAL as u16,
    /// Per-chain signal strength average. Same format as [`Nl80211StaInfo::ChainSignal`].
    ChainSignalAvg = nl80211_sta_info::NL80211_STA_INFO_CHAIN_SIGNAL_AVG as u16,
    /// Expected throughput considering also the 802.11 header (`u32`, kbps)
    ExpectedThroughput = nl80211_sta_info::NL80211_STA_INFO_EXPECTED_THROUGHPUT as u16,
    /// RX packets dropped for unspecified reasons (`u64`)
    RxDropMisc = nl80211_sta_info::NL80211_STA_INFO_RX_DROP_MISC as u16,
    /// Number of beacons received from this peer (`u64`)
    BeaconRx = nl80211_sta_info::NL80211_STA_INFO_BEACON_RX as u16,
    /// Signal strength average for beacons only (`u8`, dBm)
    BeaconSignalAvg = nl80211_sta_info::NL80211_STA_INFO_BEACON_SIGNAL_AVG as u16,
    /// Per-TID statistics (see `enum nl80211_tid_stats`). This is a nested attribute
    /// where each the inner attribute number is the TID+1 and the special TID 16
    /// (i.e. value 17) is used for non-QoS frames; each one of those is again nested
    /// with `enum nl80211_tid_stats` attributes carrying the actual values.
    // TODO: Impl nl80211_tid_stats
    TidStats = nl80211_sta_info::NL80211_STA_INFO_TID_STATS as u16,
    /// Aggregate PPDU duration for all frames received from the station (`u64`, usec)
    RxDuration = nl80211_sta_info::NL80211_STA_INFO_RX_DURATION as u16,
    /// Attribute used for padding for 64-bit alignment
    Pad = nl80211_sta_info::NL80211_STA_INFO_PAD as u16,
    /// Signal strength of the last ACK frame (`u8`, dBm)
    AckSignal = nl80211_sta_info::NL80211_STA_INFO_ACK_SIGNAL as u16,
    /// Avg signal strength of ACK frames (`i8`, dBm)
    AckSignalAvg = nl80211_sta_info::NL80211_STA_INFO_ACK_SIGNAL_AVG as u16,
    /// Total number of received packets (MPDUs) (`u32`, from this station)
    RxMpdus = nl80211_sta_info::NL80211_STA_INFO_RX_MPDUS as u16,
    /// Total number of packets (MPDUs) received with an FCS error (u32, from this station).
    /// This count may not include some packets with an FCS error due to TA corruption. Hence
    /// this counter might not be fully accurate.
    FcsErrorCount = nl80211_sta_info::NL80211_STA_INFO_FCS_ERROR_COUNT as u16,
    /// Set to true if STA has a path to a mesh gate (`u8`, 0 or 1)
    ConnectedToGate = nl80211_sta_info::NL80211_STA_INFO_CONNECTED_TO_GATE as u16,
    /// Aggregate PPDU duration for all frames sent to the station (`u64`, usec)
    TxDuration = nl80211_sta_info::NL80211_STA_INFO_TX_DURATION as u16,
    /// Current airtime weight for station (`u16`)
    AirtimeWeight = nl80211_sta_info::NL80211_STA_INFO_AIRTIME_WEIGHT as u16,
    /// Airtime link metric for mesh station
    AirtimeLinkMetric = nl80211_sta_info::NL80211_STA_INFO_AIRTIME_LINK_METRIC as u16,
    /// Timestamp (CLOCK_BOOTTIME, nanoseconds) of STA's association
    AssocAtBoottime = nl80211_sta_info::NL80211_STA_INFO_ASSOC_AT_BOOTTIME as u16,
    /// Set to true if STA has a path to authentication server (`u8`, 0 or 1)
    ConnectedToAs = nl80211_sta_info::NL80211_STA_INFO_CONNECTED_TO_AS as u16,
}
impl neli::consts::genl::NlAttrType for Nl80211StaInfo {}

/// Regulatory rule attributes
// TODO: This is actually u32?
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211RegRuleAttr {
    /// Attribute number 0 is reserved
    Invalid = nl80211_reg_rule_attr::__NL80211_REG_RULE_ATTR_INVALID as u16,
    /// A set of flags which specify additional considerations for a given frequency range.
    /// These are the TODO &enum nl80211_reg_rule_flags.
    Flags = nl80211_reg_rule_attr::NL80211_ATTR_REG_RULE_FLAGS as u16,
    /// Starting frequencry for the regulatory rule in KHz. This is not a center of frequency
    /// but an actual regulatory band edge.
    FreqRangeStart = nl80211_reg_rule_attr::NL80211_ATTR_FREQ_RANGE_START as u16,
    /// Ending frequency for the regulatory rule in KHz. This is not a center a frequency but
    /// an actual regulatory band edge.
    FreqRangeEnd = nl80211_reg_rule_attr::NL80211_ATTR_FREQ_RANGE_END as u16,
    /// Maximum allowed bandwidth for this frequency range, in KHz.
    FreqRangeMax = nl80211_reg_rule_attr::NL80211_ATTR_FREQ_RANGE_MAX_BW as u16,
    /// The maximum allowed antenna gain for a given frequency range. The value is in
    /// mBi (100 * dBi). If you don't have one then don't send this.
    PowerRuleMaxAntGain = nl80211_reg_rule_attr::NL80211_ATTR_POWER_RULE_MAX_ANT_GAIN as u16,
    /// The maximum allowed EIRP for a given frequency range. The value is in mBm (100 * dBm).
    PowerRuleMaxEirp = nl80211_reg_rule_attr::NL80211_ATTR_POWER_RULE_MAX_EIRP as u16,
    /// DFS CAC time in milliseconds. If not present or 0 default CAC time will be used.
    DfsCacTime = nl80211_reg_rule_attr::NL80211_ATTR_DFS_CAC_TIME as u16,
    /// Power spectral density (in dBm). This could be negative.
    PowerRulePsd = nl80211_reg_rule_attr::NL80211_ATTR_POWER_RULE_PSD as u16,
}
impl neli::consts::genl::NlAttrType for Nl80211RegRuleAttr {}

/// Regulatory DFS regions
#[neli_enum(serialized_type = "u8")]
pub enum Nl80211DfsRegions {
    /// Country has no DFS master region specified
    Unset = nl80211_dfs_regions::NL80211_DFS_UNSET as u8,
    /// Country follows DFS master rules from FCC
    Fcc = nl80211_dfs_regions::NL80211_DFS_FCC as u8,
    /// Country follows DFS master rules from ETSI
    Etsi = nl80211_dfs_regions::NL80211_DFS_ETSI as u8,
    /// Country follows DFS master rules from JP/MKK/Telec
    Jp = nl80211_dfs_regions::NL80211_DFS_JP as u8,
}

/// Channel type
///
/// Mostly useful for identifying legacy (pre-802.11n) channel widths
/// and differentiating between the two 40 MHz channel bonding configurations
/// (secondary channel below or above the control channel). Comparing
/// the center frequency to the control frequency can also distinguish
/// between the two 40 MHz configurations.
#[neli_enum(serialized_type = "u32")]
pub enum Nl80211ChannelType {
    /// 20 MHz, non-HT channel
    NoHt = nl80211_channel_type::NL80211_CHAN_NO_HT as u32,
    /// 20 MHz HT channel
    Ht20 = nl80211_channel_type::NL80211_CHAN_HT20 as u32,
    /// 40 MHz HT channel, secondary channel below the control channel
    Ht40Plus = nl80211_channel_type::NL80211_CHAN_HT40PLUS as u32,
    /// 40 MHz HT channel, secondary channel above the control channel
    Ht40Minus = nl80211_channel_type::NL80211_CHAN_HT40MINUS as u32,
}

/// Channel width definitions
#[neli_enum(serialized_type = "u32")]
pub enum Nl80211ChannelWidth {
    /// 20 MHz, non-HT channel
    Width20NoHT = nl80211_chan_width::NL80211_CHAN_WIDTH_20_NOHT as u32,
    /// 20 MHz HT channel
    Width20 = nl80211_chan_width::NL80211_CHAN_WIDTH_20 as u32,
    /// 40 MHz channel, the [`Nl80211Attr::CenterFreq1`] attribute must be provided as well
    Width40 = nl80211_chan_width::NL80211_CHAN_WIDTH_40 as u32,
    /// 80 MHz channel, the [`Nl80211Attr::CenterFreq1`] attribute must be provided as well
    Width80 = nl80211_chan_width::NL80211_CHAN_WIDTH_80 as u32,
    /// 80+80 MHz channel, the [`Nl80211Attr::CenterFreq1`] and [`Nl80211Attr::CenterFreq2`] attributes must be provided as well
    Width80P80 = nl80211_chan_width::NL80211_CHAN_WIDTH_80P80 as u32,
    /// 160 MHz channel, the [`Nl80211Attr::CenterFreq1`] attribute must be provided as well
    Width160 = nl80211_chan_width::NL80211_CHAN_WIDTH_160 as u32,
    /// 5 MHz OFDM channel
    Width5 = nl80211_chan_width::NL80211_CHAN_WIDTH_5 as u32,
    /// 10 MHz OFDM channel
    Width10 = nl80211_chan_width::NL80211_CHAN_WIDTH_10 as u32,
    /// 1 MHz OFDM channel
    Width1 = nl80211_chan_width::NL80211_CHAN_WIDTH_1 as u32,
    /// 2 MHz OFDM channel
    Width2 = nl80211_chan_width::NL80211_CHAN_WIDTH_2 as u32,
    /// 4 MHz OFDM channel
    Width4 = nl80211_chan_width::NL80211_CHAN_WIDTH_4 as u32,
    /// 8 MHz OFDM channel
    Width8 = nl80211_chan_width::NL80211_CHAN_WIDTH_8 as u32,
    /// 16 MHz OFDM channel
    Width16 = nl80211_chan_width::NL80211_CHAN_WIDTH_16 as u32,
    /// 320 MHz channel, the [`Nl80211Attr::CenterFreq1`] attribute must be provided as well
    Width320 = nl80211_chan_width::NL80211_CHAN_WIDTH_320 as u32,
}

/// Netlink attributes for a BSS
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211Bss {
    /// BSSID of the BSS (6 octets)
    Bssid = nl80211_bss::NL80211_BSS_BSSID as u16,
    /// Frequency in MHz (`u32`)
    Frequency = nl80211_bss::NL80211_BSS_FREQUENCY as u16,
    /// TSF of the received probe response/beacon (u64) (if [`Nl80211Bss::PrespData`] is present then
    /// this is known to be from a probe response, otherwise it may be from the same beacon that the
    /// [`Nl80211Bss::BeaconTsf`] will be from)
    Tsf = nl80211_bss::NL80211_BSS_TSF as u16,
    /// Beacon interval of the (I)BSS (u16)
    BeaconInterval = nl80211_bss::NL80211_BSS_BEACON_INTERVAL as u16,
    /// Capability field (CPU order, u16)
    Capability = nl80211_bss::NL80211_BSS_CAPABILITY as u16,
    /// Binary attribute containing the raw information elements from the probe response/beacon (bin);
    ///	if the [`Nl80211Bss::BeaconIes`] attribute is present and the data is different then the IEs here
    /// are from a Probe Response frame; otherwise they are from a Beacon frame. However, if the driver
    /// does not indicate the source of the IEs, these IEs may be from either frame subtype. If present,
    /// the [`Nl80211Bss::PrespData`] attribute indicates that the data here is known to be from a probe
    /// response, without any heuristics.
    InformationElements = nl80211_bss::NL80211_BSS_INFORMATION_ELEMENTS as u16,
    /// Signal strength of probe response/beacon in mBm (100 * dBm) (`i32`)
    SignalMbm = nl80211_bss::NL80211_BSS_SIGNAL_MBM as u16,
    /// Signal strength of the probe response/beacon in unspecified units, scaled to 0..100 (`u8`)
    SignalUnspec = nl80211_bss::NL80211_BSS_SIGNAL_UNSPEC as u16,
    /// Status, if this BSS is "used"
    Status = nl80211_bss::NL80211_BSS_STATUS as u16,
    /// Age of this BSS entry in ms
    SeenMsAgo = nl80211_bss::NL80211_BSS_SEEN_MS_AGO as u16,
    /// Binary attribute containing the raw information elements from a Beacon frame (bin);
    /// not present if no Beacon frame has yet been received
    BeaconIes = nl80211_bss::NL80211_BSS_BEACON_IES as u16,
    /// No longer used. Channel width of the control channel (`u32`, `enum nl80211_bss_scan_width`)
    ChanWidth = nl80211_bss::NL80211_BSS_CHAN_WIDTH as u16,
    /// TSF of the last received beacon (`u64`) (not present if no beacon frame has been received yet)
    BeaconTsf = nl80211_bss::NL80211_BSS_BEACON_TSF as u16,
    /// The data in [`Nl80211Bss::InformationElements`] and [`Nl80211Bss::Tsf`] is known to be from a
    /// probe response (flag attribute)
    PrespData = nl80211_bss::NL80211_BSS_PRESP_DATA as u16,
    /// `CLOCK_BOOTTIME` timestamp when this entry was last updated by a received frame. The value is
    /// expected to be accurate to about 10ms. (`u64`, nanoseconds)
    LastSeenSinceBootTime = nl80211_bss::NL80211_BSS_LAST_SEEN_BOOTTIME as u16,
    /// Attribute used for padding for 64-bit alignment
    Pad = nl80211_bss::NL80211_BSS_PAD as u16,
    /// The time at the start of reception of the first octet of the timestamp field of the last
    /// beacon/probe received for this BSS. The time is the TSF of the BSS specified by
    ///	[`Nl80211Bss::ParentBssid`]. (`u64`).
    ParentTsf = nl80211_bss::NL80211_BSS_PARENT_TSF as u16,
    /// The BSS according to which [`Nl80211Bss::ParentTsf`] is set.
    ParentBssid = nl80211_bss::NL80211_BSS_PARENT_BSSID as u16,
    /// Per-chain signal strength of last BSS update. Contains a nested array of signal strength
    /// attributes (`u8`, dBm), using the nesting index as the antenna number.
    ChainSignal = nl80211_bss::NL80211_BSS_CHAIN_SIGNAL as u16,
    /// Frequency offset in KHz
    FrequencyOffset = nl80211_bss::NL80211_BSS_FREQUENCY_OFFSET as u16,
    /// MLO link ID of the BSS (`u8`).
    MloLinkId = nl80211_bss::NL80211_BSS_MLO_LINK_ID as u16,
    /// MLD address of this BSS if connected to it.
    MldAddr = nl80211_bss::NL80211_BSS_MLD_ADDR as u16,
    /// `u32` bitmap attribute indicating what the BSS can be used for, see [`enum nl80211_bss_use_for`].
    // TODO: Add nl80211_bss_use_for
    UseFor = nl80211_bss::NL80211_BSS_USE_FOR as u16,
    /// Indicates the reason that this BSS cannot be used for all or some of the possible uses by the
    /// device reporting it, even though its presence was detected. This is a u64 attribute containing
    /// a bitmap of values from [`enum nl80211_cannot_use_reasons`], note that the attribute may be missing
    ///	if no reasons are specified.
    // TODO: Add nl80211_cannot_use_reasons
    CannotUseReasons = nl80211_bss::NL80211_BSS_CANNOT_USE_REASONS as u16,
}
impl neli::consts::genl::NlAttrType for Nl80211Bss {}

/// Authentication type
#[neli_enum(serialized_type = "u32")]
pub enum Nl80211AuthType {
    /// Open System authentication
    OpenSystem = nl80211_auth_type::NL80211_AUTHTYPE_OPEN_SYSTEM as u32,
    /// Shared Key authentication (WEP only)
    SharedKey = nl80211_auth_type::NL80211_AUTHTYPE_SHARED_KEY as u32,
    /// Fast BSS Transition (IEEE 802.11r)
    FT = nl80211_auth_type::NL80211_AUTHTYPE_FT as u32,
    /// Network EAP (some Cisco APs and mainly LEAP)
    NetworkEap = nl80211_auth_type::NL80211_AUTHTYPE_NETWORK_EAP as u32,
    /// Simultaneous authentication of equals
    Sae = nl80211_auth_type::NL80211_AUTHTYPE_SAE as u32,
    /// Fast Initial Link Setup shared key
    FilsSk = nl80211_auth_type::NL80211_AUTHTYPE_FILS_SK as u32,
    /// Fast Initial Link Setup shared key with PFS
    FilsSkPfs = nl80211_auth_type::NL80211_AUTHTYPE_FILS_SK_PFS as u32,
    /// Fast Initial Link Setup public key
    FilsPk = nl80211_auth_type::NL80211_AUTHTYPE_FILS_PK as u32,
}

/// Frequency band
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211Band {
    /// 2.4 GHz ISM band
    Band2Ghz = nl80211_band::NL80211_BAND_2GHZ as u16,
    /// Around 5 GHz band (4.9 - 5.7 GHz)
    Band5Ghz = nl80211_band::NL80211_BAND_5GHZ as u16,
    /// Around 60 GHz band (58.32 - 69.12 GHz)
    Band60Ghz = nl80211_band::NL80211_BAND_60GHZ as u16,
    /// Around 6 GHz band (5.9 - 7.2 GHz)
    Band6Ghz = nl80211_band::NL80211_BAND_6GHZ as u16,
    /// Around 900MHz, supported by S1G PHYs
    BandS1Ghz = nl80211_band::NL80211_BAND_S1GHZ as u16,
    /// Light communication band (placeholder)
    BandLc = nl80211_band::NL80211_BAND_LC as u16,
}

///  Connection quality monitor attributes
// TODO: Verify this is actually u16?
#[neli_enum(serialized_type = "u16")]
pub enum Nl80211AttrCqm {
    /// Invalid
    Invalid = nl80211_attr_cqm::__NL80211_ATTR_CQM_INVALID as u16,
    // TODO: Add NL80211_EXT_FEATURE
    /// RSSI threshold in dBm. This value specifies the threshold for the RSSI level
    /// at which an event will be sent. Zero to disable.
    ///
    /// Alternatively, if `%NL80211_EXT_FEATURE_CQM_RSSI_LIST` is set, multiple values
    /// can be supplied as a low-to-high sorted array of threshold values in dBm.
    /// Events will be sent when the RSSI value crosses any of the thresholds.
    RssiThold = nl80211_attr_cqm::NL80211_ATTR_CQM_RSSI_THOLD as u16,
    /// RSSI hysteresis in dBm. This value specifies the minimum amount the RSSI level
    /// must change after an event before a new event may be issued (to reduce effects
    /// of RSSI oscillation).
    RssiHyst = nl80211_attr_cqm::NL80211_ATTR_CQM_RSSI_HYST as u16,
    /// RSSI threshold event
    RssiThresholdEvent = nl80211_attr_cqm::NL80211_ATTR_CQM_RSSI_THRESHOLD_EVENT as u16,
    /// `u32` value indicating that this many consecutive packets were not acknowledged by the peer
    PktLossEvent = nl80211_attr_cqm::NL80211_ATTR_CQM_PKT_LOSS_EVENT as u16,
    /// TX error rate in %. Minimum % of TX failures during the given [`Nl80211AttrCqm::TxeIntvl`]
    /// before an [`Nl80211Cmd::NotifyCqm`] with reported [`Nl80211AttrCqm::TxeRate`]
    /// [`Nl80211AttrCqm::TxePkts`] is generated.
    // TODO: Verify if this is only used in ath6kl
    TxeRate = nl80211_attr_cqm::NL80211_ATTR_CQM_TXE_RATE as u16,
    /// Number of attempted packets in a given [`Nl80211AttrCqm::TxeIntvl`] before
    /// [`Nl80211AttrCqm::TxeRate`] is checked.
    // TODO: Verify if this is only used in ath6kl
    TxePkts = nl80211_attr_cqm::NL80211_ATTR_CQM_TXE_PKTS as u16,
    /// Interval in seconds. Specifies the periodic interval in which [`Nl80211AttrCqm::TxePkts`]
    /// and [`Nl80211AttrCqm::TxeRate`] must be satisfied before generating an
    /// [`Nl80211Cmd::NotifyCqm`]. Set to 0 to turn off TX error reporting.
    // TODO: Verify if this is only used in ath6kl
    TxeIntvl = nl80211_attr_cqm::NL80211_ATTR_CQM_TXE_INTVL as u16,
    /// Flag attribute that's set in a beacon loss event
    BeaconLossEvent = nl80211_attr_cqm::NL80211_ATTR_CQM_BEACON_LOSS_EVENT as u16,
    /// The RSSI value in dBm that triggered the RSSI threshold event.
    RssiLevel = nl80211_attr_cqm::NL80211_ATTR_CQM_RSSI_LEVEL as u16,
}
impl neli::consts::genl::NlAttrType for Nl80211AttrCqm {}

/// RSSI threshold event
#[neli_enum(serialized_type = "u32")]
pub enum Nl80211CqmRssiThresholdEvent {
    /// The RSSI level is lower than the configured threshold
    Low = nl80211_cqm_rssi_threshold_event::NL80211_CQM_RSSI_THRESHOLD_EVENT_LOW as u32,
    /// The RSSI is higher than the configured threshold
    High = nl80211_cqm_rssi_threshold_event::NL80211_CQM_RSSI_THRESHOLD_EVENT_HIGH as u32,
    /// Reserved, never sent
    BeaconLoss = nl80211_cqm_rssi_threshold_event::NL80211_CQM_RSSI_BEACON_LOSS_EVENT as u32,
}

/// TX power adjustment
#[neli_enum(serialized_type = "u32")]
pub enum Nl80211TxpowerSetting {
    /// Automatically determine transmit power
    Automatic = nl80211_tx_power_setting::NL80211_TX_POWER_AUTOMATIC as u32,
    /// Limit TX power by the mBm parameter
    Limited = nl80211_tx_power_setting::NL80211_TX_POWER_LIMITED as u32,
    /// Fix TX power to the mBm parameter
    Fixed = nl80211_tx_power_setting::NL80211_TX_POWER_FIXED as u32,
}

impl_flags!(
    /// Scan request control flags
    pub Nl80211ScanFlag: u32 {
        /// Scan request has low priority. Driver must indicate support in [`Nl80211Attr::FeatureFlags`]
        LowPriority = nl80211_scan_flags::NL80211_SCAN_FLAG_LOW_PRIORITY as u32,
        /// Flush cache before scanning
        Flush = nl80211_scan_flags::NL80211_SCAN_FLAG_FLUSH as u32,
        /// Force a scan even if the interface is configured as AP and the beaconing has already been configured.
        ///
        /// This attribute is dangerous because will destroy stations performance as a lot of frames
        /// will be lost while scanning off-channel, therefore it must be used only when really needed
        Ap = nl80211_scan_flags::NL80211_SCAN_FLAG_AP as u32,
        /// Use a random MAC address for this scan (or for scheduled scan, a different one for every scan iteration).
        ///
        /// When the flag is set, depending on device capabilities the [`Nl80211Attr::Mac`] and [`Nl80211Attr::MacMask`]
        /// attributes may also be given in which case only the masked bits will be preserved from the MAC address
        /// and the remainder randomised. If the attributes are not given full randomisation (46 bits,
        /// locally administered 1, multicast 0) is assumed.
        ///
        /// This flag must not be requested when the feature isn't supported, check [`Nl80211Attr::FeatureFlags`] for the device.
        RandomAddr = nl80211_scan_flags::NL80211_SCAN_FLAG_RANDOM_ADDR as u32,
        /// Fill the dwell time in the FILS request parameters IE in the probe request
        FilsMaxChannelTime = nl80211_scan_flags::NL80211_SCAN_FLAG_FILS_MAX_CHANNEL_TIME as u32,
        /// Accept broadcast probe responses
        AcceptBcastProbeResp = nl80211_scan_flags::NL80211_SCAN_FLAG_ACCEPT_BCAST_PROBE_RESP as u32,
        /// Send probe request frames at rate of at least 5.5M. In case non-OCE AP is discovered in the channel,
        /// only the first probe req in the channel will be sent in high rate.
        OceProbeReqHighTxRate = nl80211_scan_flags::NL80211_SCAN_FLAG_OCE_PROBE_REQ_HIGH_TX_RATE as u32,
        /// Allow probe request tx deferral (dot11FILSProbeDelay shall be set to 15ms) and suppression
        /// (if it has received a broadcast Probe Response frame, Beacon frame or FILS Discovery frame
        /// from an AP that the STA considers a suitable candidate for (re-)association - suitable in terms of
        /// SSID and/or RSSI.
        OceProbeReqDeferralSuppression = nl80211_scan_flags::NL80211_SCAN_FLAG_OCE_PROBE_REQ_DEFERRAL_SUPPRESSION as u32,
        /// Span corresponds to the total time taken to accomplish the scan. Thus, this flag intends the
        /// driver to perform the scan request with lesser span/duration. It is specific to the driver
        /// implementations on how this is accomplished. Scan accuracy may be impacted with this flag.
        LowSpan = nl80211_scan_flags::NL80211_SCAN_FLAG_LOW_SPAN as u32,
        /// This flag intends the scan attempts to consume optimal possible power. Drivers can resort to
        /// their specific means to optimize the power. Scan accuracy may be impacted with this flag.
        LowPower = nl80211_scan_flags::NL80211_SCAN_FLAG_LOW_POWER as u32,
        /// Accuracy here intends to the extent of scan results obtained. Thus [`ScanFlag::HighAccuracy`] scan flag aims
        /// to get maximum possible scan results. This flag hints the driver to use the best possible scan
        /// configuration to improve the accuracy in scanning. Latency and power use may be impacted with
        /// this flag.
        HighAccuracy = nl80211_scan_flags::NL80211_SCAN_FLAG_HIGH_ACCURACY as u32,
        /// Randomize the sequence number in probe request frames from this scan to avoid correlation/tracking
        /// being possible.
        RandomSn = nl80211_scan_flags::NL80211_SCAN_FLAG_RANDOM_SN as u32,
        /// Minimize probe request content to only have supported rates and no additional capabilities
        /// (unless added by userspace explicitly).
        MinPreqContent = nl80211_scan_flags::NL80211_SCAN_FLAG_MIN_PREQ_CONTENT as u32,
        /// Report scan results with [`Nl80211Attr::ScanFreqKhz`]. This also means [`Nl80211Attr::ScanFrequencies`]
        /// will not be included.
        FreqKhz = nl80211_scan_flags::NL80211_SCAN_FLAG_FREQ_KHZ as u32,
        /// Scan for collocated APs reported by 2.4/5 GHz APs.
        ///
        /// When the flag is set, the scan logic will use the information from the RNR element found in beacons/probe
        /// responses received on the 2.4/5 GHz channels to actively scan only the 6 GHz channels on which APs are
        /// expected to be found.
        ///
        /// Note that when not set, the scan logic would scan all 6GHz channels, but since transmission of probe requests
        /// on non-PSC channels is limited, it is highly likely that these channels would passively be scanned. Also note
        /// that when the flag is set, in addition to the colocated APs, PSC channels would also be scanned if the user
        /// space has asked for it.
        Colocated6GHz = nl80211_scan_flags::NL80211_SCAN_FLAG_COLOCATED_6GHZ as u32,
    }
);
