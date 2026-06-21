use linux_raw_sys::netlink::{
    nl80211_attrs, nl80211_band_attr, nl80211_bitrate_attr, nl80211_commands,
    nl80211_frequency_attr, nl80211_iftype,
};

use crate as neli;

#[neli::neli_enum(serialized_type = "u8")]
pub enum Nl80211Command {
    Unspecified = nl80211_commands::NL80211_CMD_UNSPEC as u8,
    GetWiphy = nl80211_commands::NL80211_CMD_GET_WIPHY as u8,
    SetWiphy = nl80211_commands::NL80211_CMD_SET_WIPHY as u8,
    NewWiphy = nl80211_commands::NL80211_CMD_NEW_WIPHY as u8,
    DelWiphy = nl80211_commands::NL80211_CMD_DEL_WIPHY as u8,
    GetInterface = nl80211_commands::NL80211_CMD_GET_INTERFACE as u8,
    SetInterface = nl80211_commands::NL80211_CMD_SET_INTERFACE as u8,
    NewInterface = nl80211_commands::NL80211_CMD_NEW_INTERFACE as u8,
    DelInterface = nl80211_commands::NL80211_CMD_DEL_INTERFACE as u8,
    GetKey = nl80211_commands::NL80211_CMD_GET_KEY as u8,
    SetKey = nl80211_commands::NL80211_CMD_SET_KEY as u8,
    NewKey = nl80211_commands::NL80211_CMD_NEW_KEY as u8,
    DelKey = nl80211_commands::NL80211_CMD_DEL_KEY as u8,
    GetBeacon = nl80211_commands::NL80211_CMD_GET_BEACON as u8,
    SetBeacon = nl80211_commands::NL80211_CMD_SET_BEACON as u8,
    StartAp = nl80211_commands::NL80211_CMD_START_AP as u8,
    StopAp = nl80211_commands::NL80211_CMD_STOP_AP as u8,
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
    Frame = nl80211_commands::NL80211_CMD_FRAME as u8,
    FrameTxStatus = nl80211_commands::NL80211_CMD_FRAME_TX_STATUS as u8,
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
    SetTidToLinkMapping = nl80211_commands::NL80211_CMD_SET_TID_TO_LINK_MAPPING as u8,
    AssocMloReconf = nl80211_commands::NL80211_CMD_ASSOC_MLO_RECONF as u8,
    EpcsCfg = nl80211_commands::NL80211_CMD_EPCS_CFG as u8,
}

impl neli::consts::genl::Cmd for Nl80211Command {}

#[neli::neli_enum(serialized_type = "u16")]
pub enum Nl80211Attr {
    Unspecified = nl80211_attrs::NL80211_ATTR_UNSPEC as u16,
    /// `NL80211_ATTR_WIPHY`
    Wiphy = nl80211_attrs::NL80211_ATTR_WIPHY as u16,
    /// `NL80211_ATTR_WIPHY_NAME`
    WiphyName = nl80211_attrs::NL80211_ATTR_WIPHY_NAME as u16,
    /// `NL80211_ATTR_IFNAME`
    Ifname = nl80211_attrs::NL80211_ATTR_IFNAME as u16,
    /// `NL80211_ATTR_IFTYPE`
    Iftype = nl80211_attrs::NL80211_ATTR_IFTYPE as u16,
    /// `NL80211_ATTR_WIPHY_BANDS`
    WiphyBands = nl80211_attrs::NL80211_ATTR_WIPHY_BANDS as u16,
    /// `NL80211_ATTR_SSID`
    Ssid = nl80211_attrs::NL80211_ATTR_SSID as u16,
    /// ``NL80211_ATTR_WDEV`
    Wdev = nl80211_attrs::NL80211_ATTR_WDEV as u16,
    /* Literally hundreds elided */
}
impl neli::consts::genl::NlAttrType for Nl80211Attr {}

// TODO: Interface types may also be passed as attributes, but
//       presently there is not an ergonomic way to support
//       serializing attributes as any size other than u16
#[neli::neli_enum(serialized_type = "u32")]
pub enum Nl80211Iftype {
    Unspecified = nl80211_iftype::NL80211_IFTYPE_UNSPECIFIED as u32,
    Adhoc = nl80211_iftype::NL80211_IFTYPE_ADHOC as u32,
    Station = nl80211_iftype::NL80211_IFTYPE_STATION as u32,
    Ap = nl80211_iftype::NL80211_IFTYPE_AP as u32,
    ApVlan = nl80211_iftype::NL80211_IFTYPE_AP_VLAN as u32,
    Wds = nl80211_iftype::NL80211_IFTYPE_WDS as u32,
    Monitor = nl80211_iftype::NL80211_IFTYPE_MONITOR as u32,
    MeshPoint = nl80211_iftype::NL80211_IFTYPE_MESH_POINT as u32,
    P2pClient = nl80211_iftype::NL80211_IFTYPE_P2P_CLIENT as u32,
    P2pGo = nl80211_iftype::NL80211_IFTYPE_P2P_GO as u32,
    P2pDevice = nl80211_iftype::NL80211_IFTYPE_P2P_DEVICE as u32,
    Ocb = nl80211_iftype::NL80211_IFTYPE_OCB as u32,
    Nan = nl80211_iftype::NL80211_IFTYPE_NAN as u32,
}

/// `enum nl80211_band_attr - band attributes`
///
/// Payload for `Nl80211Attribute::WiphyBands`
#[neli::neli_enum(serialized_type = "u16")]
pub enum Nl80211BandAttr {
    Invalid = nl80211_band_attr::__NL80211_BAND_ATTR_INVALID as u16,
    /// `NL80211_BAND_ATTR_FREQS`
    Freqs = nl80211_band_attr::NL80211_BAND_ATTR_FREQS as u16,
    /// `NL80211_BAND_ATTR_RATES`
    Rates = nl80211_band_attr::NL80211_BAND_ATTR_RATES as u16,
    /// `NL80211_BAND_ATTR_HT_MCS_SET`
    HtMcsSet = nl80211_band_attr::NL80211_BAND_ATTR_HT_MCS_SET as u16,
    /// `NL80211_BAND_ATTR_HT_CAPA`
    HtCapa = nl80211_band_attr::NL80211_BAND_ATTR_HT_CAPA as u16,
    /// `NL80211_BAND_ATTR_HT_AMPDU_FACTOR`
    HtAmpduFactor = nl80211_band_attr::NL80211_BAND_ATTR_HT_AMPDU_FACTOR as u16,
    /// `NL80211_BAND_ATTR_HT_AMPDU_DENSITY`
    HtAmpduDensity = nl80211_band_attr::NL80211_BAND_ATTR_HT_AMPDU_DENSITY as u16,
    /// `NL80211_BAND_ATTR_VHT_MCS_SET`
    VhtMcsSet = nl80211_band_attr::NL80211_BAND_ATTR_VHT_MCS_SET as u16,
    /// `NL80211_BAND_ATTR_VHT_CAPA`
    VhtCapa = nl80211_band_attr::NL80211_BAND_ATTR_VHT_CAPA as u16,
    /// `NL80211_BAND_ATTR_IFTYPE_DATA`
    IftypeData = nl80211_band_attr::NL80211_BAND_ATTR_IFTYPE_DATA as u16,
    /// `NL80211_BAND_ATTR_EDMG_CHANNELS`
    EdmgChannels = nl80211_band_attr::NL80211_BAND_ATTR_EDMG_CHANNELS as u16,
    /// `NL80211_BAND_ATTR_EDMG_BW_CONFIG`
    EdmgBwConfig = nl80211_band_attr::NL80211_BAND_ATTR_EDMG_BW_CONFIG as u16,
    /// `NL80211_BAND_ATTR_S1G_MCS_NSS_SET`
    S1gMcsNssSet = nl80211_band_attr::NL80211_BAND_ATTR_S1G_MCS_NSS_SET as u16,
    /// `NL80211_BAND_ATTR_S1G_CAPA`
    S1gCapa = nl80211_band_attr::NL80211_BAND_ATTR_S1G_CAPA as u16,
}
impl neli::consts::genl::NlAttrType for Nl80211BandAttr {}

/// `enum nl80211_freq_attr`
#[neli::neli_enum(serialized_type = "u16")]
pub enum Nl80211FrequencyAttr {
    /// `NL80211_FREQUENCY_ATTR_INVALID`
    Invalid = nl80211_frequency_attr::__NL80211_FREQUENCY_ATTR_INVALID as u16,
    /// `NL80211_FREQUENCY_ATTR_FREQ`
    Freq = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_FREQ as u16,
    /// `NL80211_FREQUENCY_ATTR_DISABLED`
    Disabled = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_DISABLED as u16,
    /// `NL80211_FREQUENCY_ATTR_NO_IR`
    NoIr = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_NO_IR as u16,
    /// `NL80211_FREQUENCY_ATTR_NO_IBSS`
    NoIbss = nl80211_frequency_attr::__NL80211_FREQUENCY_ATTR_NO_IBSS as u16,
    /// `NL80211_FREQUENCY_ATTR_RADAR`
    Radar = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_RADAR as u16,
    /// `NL80211_FREQUENCY_ATTR_MAX_TX_POWER`
    MaxTxPower = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_MAX_TX_POWER as u16,
    /// `NL80211_FREQUENCY_ATTR_DFS_STATE`
    DfsState = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_DFS_STATE as u16,
    /// `NL80211_FREQUENCY_ATTR_DFS_TIME`
    DfsTime = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_DFS_TIME as u16,
    /// `NL80211_FREQUENCY_ATTR_NO_HT40_MINUS`
    NoHt40Minus = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_NO_HT40_MINUS as u16,
    /// `NL80211_FREQUENCY_ATTR_NO_HT40_PLUS`
    NoHt40Plus = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_NO_HT40_PLUS as u16,
    /// `NL80211_FREQUENCY_ATTR_NO_80MHZ`
    No80Mhz = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_NO_80MHZ as u16,
    /// `NL80211_FREQUENCY_ATTR_NO_160MHZ`
    No160Mhz = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_NO_160MHZ as u16,
    /// `NL80211_FREQUENCY_ATTR_DFS_CAC_TIME`
    DfsCacTime = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_DFS_CAC_TIME as u16,
    /// `NL80211_FREQUENCY_ATTR_INDOOR_ONLY`
    IndoorOnly = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_INDOOR_ONLY as u16,
    /// `NL80211_FREQUENCY_ATTR_IR_CONCURRENT`
    IrConcurrent = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_IR_CONCURRENT as u16,
    /// `NL80211_FREQUENCY_ATTR_NO_20MHZ`
    No20Mhz = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_NO_20MHZ as u16,
    /// `NL80211_FREQUENCY_ATTR_NO_10MHZ`
    No10Mhz = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_NO_10MHZ as u16,
    /// `NL80211_FREQUENCY_ATTR_WMM`
    Wmm = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_WMM as u16,
    /// `NL80211_FREQUENCY_ATTR_NO_HE`
    NoHe = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_NO_HE as u16,
    /// `NL80211_FREQUENCY_ATTR_OFFSET`
    Offset = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_OFFSET as u16,
    /// `NL80211_FREQUENCY_ATTR_1MHZ`
    _1Mhz = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_1MHZ as u16,
    /// `NL80211_FREQUENCY_ATTR_2MHZ`
    _2Mhz = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_2MHZ as u16,
    /// `NL80211_FREQUENCY_ATTR_4MHZ`
    _4Mhz = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_4MHZ as u16,
    /// `NL80211_FREQUENCY_ATTR_8MHZ`
    _8Mhz = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_8MHZ as u16,
    /// `NL80211_FREQUENCY_ATTR_16MHZ`
    _16Mhz = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_16MHZ as u16,
    /// `NL80211_FREQUENCY_ATTR_NO_320MHZ`
    No320Mhz = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_NO_320MHZ as u16,
    /// `NL80211_FREQUENCY_ATTR_NO_EHT`
    NoEht = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_NO_EHT as u16,
    /// `NL80211_FREQUENCY_ATTR_PSD`
    Psd = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_PSD as u16,
    /// `NL80211_FREQUENCY_ATTR_DFS_CONCURRENT`
    DfsConcurrent = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_DFS_CONCURRENT as u16,
    /// `NL80211_FREQUENCY_ATTR_NO_6GHZ_VLP_CLIENT`
    No6ghzVlpClient = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_NO_6GHZ_VLP_CLIENT as u16,
    /// `NL80211_FREQUENCY_ATTR_NO_6GHZ_AFC_CLIENT`
    No6ghzAfcClient = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_NO_6GHZ_AFC_CLIENT as u16,
    /// `NL80211_FREQUENCY_ATTR_CAN_MONITOR`
    CanMonitor = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_CAN_MONITOR as u16,
    /// `NL80211_FREQUENCY_ATTR_ALLOW_6GHZ_VLP_AP`
    Allow6ghzVlpAp = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_ALLOW_6GHZ_VLP_AP as u16,
    /// `NL80211_FREQUENCY_ATTR_ALLOW_20MHZ_ACTIVITY`
    Allow20mhzActivity = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_ALLOW_20MHZ_ACTIVITY as u16,
}
impl neli::consts::genl::NlAttrType for Nl80211FrequencyAttr {}

/// `enum nl80211_bitrate_attr`
#[neli::neli_enum(serialized_type = "u16")]
pub enum Nl80211BitrateAttr {
    /// `__NL80211_BITRATE_ATTR_INVALID`
    Invalid = nl80211_bitrate_attr::__NL80211_BITRATE_ATTR_INVALID as u16,
    /// `NL80211_BITRATE_ATTR_RATE`
    Rate = nl80211_bitrate_attr::NL80211_BITRATE_ATTR_RATE as u16,
    /// `NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE`
    _2GhzShortpreamble = nl80211_bitrate_attr::NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE as u16,
}
impl neli::consts::genl::NlAttrType for Nl80211BitrateAttr {}
