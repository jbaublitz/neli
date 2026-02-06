//! This is the module that contains the error types used in `neli`
//!
//! There are five main types:
//! * [`Nlmsgerr`] - an application error
//!   returned from netlink as a packet.
//! * [`RouterError`] - errors returned by
//!   [`NlRouter`][crate::router::synchronous::NlRouter].
//! * [`SocketError`] - errors returned by
//!   [`NlSocketHandle`][crate::socket::synchronous::NlSocketHandle].
//! * [`DeError`] - error while deserializing
//! * [`SerError`] - error while serializing
//!
//! # Design decisions
//! All errors implement [`std::error::Error`] in an attempt to allow
//! them to be used in conjunction with [`Result`] for easier error
//! management even at the protocol error level.

use std::{
    error::Error,
    fmt::{self, Debug, Display},
    io::{self, Cursor, ErrorKind},
    str::Utf8Error,
    string::FromUtf8Error,
    sync::Arc,
};

use derive_builder::{Builder, UninitializedFieldError};
use getset::Getters;

use crate::{
    self as neli,
    consts::nl::{NlType, NlmF, NlmsgerrAttr},
    genl::{AttrTypeBuilderError, GenlmsghdrBuilderError, NlattrBuilderError},
    nl::{Nlmsghdr, NlmsghdrBuilderError},
    rtnl::{
        IfaddrmsgBuilderError, IfinfomsgBuilderError, IfstatsmsgBuilderError,
        NdaCacheinfoBuilderError, NdmsgBuilderError, RtattrBuilderError, RtgenmsgBuilderError,
        RtmsgBuilderError, TcmsgBuilderError,
    },
    types::{Buffer, GenlBuffer},
    FromBytes, FromBytesWithInput, Header, Size, ToBytes, TypeSize,
};

/// A special struct that represents the contents of an ACK
/// returned at the application level.
#[derive(Builder, Getters, Clone, Debug, PartialEq, Eq, Size, ToBytes, FromBytes)]
#[neli(header_bound = "T: TypeSize")]
#[neli(from_bytes_bound = "T: NlType")]
#[builder(pattern = "owned")]
pub struct NlmsghdrAck<T> {
    /// Length of the netlink message
    #[getset(get = "pub")]
    nl_len: u32,
    /// Type of the netlink message
    #[getset(get = "pub")]
    nl_type: T,
    /// Flags indicating properties of the request or response
    #[getset(get = "pub")]
    nl_flags: NlmF,
    /// Sequence number for netlink protocol
    #[getset(get = "pub")]
    nl_seq: u32,
    /// ID of the netlink destination for requests and source for
    /// responses.
    #[getset(get = "pub")]
    nl_pid: u32,
}

impl NlmsghdrAck<u16> {
    /// Create a typed ACK from an ACK that can represent all types.
    pub fn to_typed<T, P>(self) -> Result<NlmsghdrAck<T>, RouterError<T, P>>
    where
        T: NlType,
    {
        Ok(NlmsghdrAckBuilder::default()
            .nl_len(self.nl_len)
            .nl_type(T::from(self.nl_type))
            .nl_flags(self.nl_flags)
            .nl_seq(self.nl_seq)
            .nl_pid(self.nl_pid)
            .build()?)
    }
}

/// A special struct that represents the contents of an error
/// returned at the application level.
#[derive(Builder, Getters, Clone, Debug, PartialEq, Eq, Size, ToBytes, FromBytes, Header)]
#[neli(header_bound = "T: TypeSize")]
#[neli(from_bytes_bound = "T: NlType + TypeSize")]
#[neli(from_bytes_bound = "P: FromBytesWithInput<Input = usize>")]
#[builder(build_fn(skip))]
#[builder(pattern = "owned")]
pub struct NlmsghdrErr<T, P> {
    /// Length of the netlink message
    #[getset(get = "pub")]
    #[builder(setter(skip))]
    nl_len: u32,
    /// Type of the netlink message
    #[getset(get = "pub")]
    nl_type: T,
    /// Flags indicating properties of the request or response
    #[getset(get = "pub")]
    nl_flags: NlmF,
    /// Sequence number for netlink protocol
    #[getset(get = "pub")]
    nl_seq: u32,
    /// ID of the netlink destination for requests and source for
    /// responses.
    #[getset(get = "pub")]
    nl_pid: u32,
    /// Payload of netlink message
    #[neli(input = "nl_len as usize - Self::header_size()")]
    #[getset(get = "pub")]
    nl_payload: P,
}

impl<T, P> NlmsghdrErrBuilder<T, P>
where
    T: NlType,
    P: Size + FromBytesWithInput<Input = usize>,
{
    /// Build [`NlmsghdrErr`].
    pub fn build(self) -> Result<NlmsghdrErr<T, P>, NlmsghdrErrBuilderError> {
        let nl_type = self.nl_type.ok_or_else(|| {
            NlmsghdrErrBuilderError::from(UninitializedFieldError::new("nl_type"))
        })?;
        let nl_flags = self.nl_flags.unwrap_or(NlmF::empty());
        let nl_seq = self.nl_seq.unwrap_or(0);
        let nl_pid = self.nl_pid.unwrap_or(0);
        let nl_payload = self.nl_payload.ok_or_else(|| {
            NlmsghdrErrBuilderError::from(UninitializedFieldError::new("nl_payload"))
        })?;

        let mut nl = NlmsghdrErr {
            nl_len: 0,
            nl_type,
            nl_flags,
            nl_seq,
            nl_pid,
            nl_payload,
        };
        nl.nl_len = nl.padded_size() as u32;
        Ok(nl)
    }
}

impl NlmsghdrErr<u16, Buffer> {
    /// Create a typed error from an error that can represent all types.
    pub fn to_typed<T, P>(self) -> Result<NlmsghdrErr<T, P>, RouterError<T, P>>
    where
        T: NlType,
        P: Size + FromBytesWithInput<Input = usize>,
    {
        Ok(NlmsghdrErrBuilder::default()
            .nl_type(T::from(self.nl_type))
            .nl_flags(self.nl_flags)
            .nl_seq(self.nl_seq)
            .nl_pid(self.nl_pid)
            .nl_payload(P::from_bytes_with_input(
                &mut Cursor::new(self.nl_payload),
                self.nl_len as usize - Self::header_size(),
            )?)
            .build()?)
    }
}

/// Struct representing netlink packets containing errors
#[derive(Builder, Getters, Clone, Debug, PartialEq, Eq, Size, FromBytesWithInput, ToBytes)]
#[neli(from_bytes_bound = "M: Size + FromBytes")]
#[builder(pattern = "owned")]
pub struct Nlmsgerr<M> {
    /// Error code
    #[builder(default = "0")]
    #[getset(get = "pub")]
    error: libc::c_int,
    /// Packet header for request that failed
    #[getset(get = "pub")]
    #[neli(skip_debug)]
    nlmsg: M,
    #[neli(input = "input - error.padded_size() - nlmsg.padded_size()")]
    /// Contains attributes representing the extended ACK
    #[builder(default = "GenlBuffer::new()")]
    #[getset(get = "pub")]
    ext_ack: GenlBuffer<NlmsgerrAttr, Buffer>,
}

impl<M> Display for Nlmsgerr<M> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", io::Error::from_raw_os_error(-self.error))
    }
}

impl<M> Error for Nlmsgerr<M> where M: Debug {}

impl Nlmsgerr<NlmsghdrErr<u16, Buffer>> {
    /// Create a typed error from an error that can represent all types.
    pub fn to_typed<T, P>(self) -> Result<Nlmsgerr<NlmsghdrErr<T, P>>, RouterError<T, P>>
    where
        T: NlType,
        P: Size + FromBytesWithInput<Input = usize>,
    {
        Ok(NlmsgerrBuilder::default()
            .error(self.error)
            .nlmsg(self.nlmsg.to_typed()?)
            .build()?)
    }
}

impl Nlmsgerr<NlmsghdrAck<u16>> {
    /// Create a typed ACK from an ACK that can represent all types.
    pub fn to_typed<T, P>(self) -> Result<Nlmsgerr<NlmsghdrAck<T>>, RouterError<T, P>>
    where
        T: NlType,
    {
        Ok(NlmsgerrBuilder::default()
            .error(self.error)
            .nlmsg(self.nlmsg.to_typed()?)
            .build()?)
    }
}

#[derive(Debug)]
#[allow(missing_docs)]
pub enum BuilderError {
    #[allow(missing_docs)]
    Nlmsghdr(NlmsghdrBuilderError),
    #[allow(missing_docs)]
    Nlmsgerr(NlmsgerrBuilderError),
    #[allow(missing_docs)]
    NlmsghdrErr(NlmsghdrErrBuilderError),
    #[allow(missing_docs)]
    Genlmsghdr(GenlmsghdrBuilderError),
    #[allow(missing_docs)]
    Nlattr(NlattrBuilderError),
    #[allow(missing_docs)]
    AttrType(AttrTypeBuilderError),
    #[allow(missing_docs)]
    Ifinfomsg(IfinfomsgBuilderError),
    #[allow(missing_docs)]
    Ifaddrmsg(IfaddrmsgBuilderError),
    #[allow(missing_docs)]
    Rtgenmsg(RtgenmsgBuilderError),
    #[allow(missing_docs)]
    Rtmsg(RtmsgBuilderError),
    #[allow(missing_docs)]
    Ndmsg(NdmsgBuilderError),
    #[allow(missing_docs)]
    NdaCacheinfo(NdaCacheinfoBuilderError),
    #[allow(missing_docs)]
    Tcmsg(TcmsgBuilderError),
    #[allow(missing_docs)]
    Rtattr(RtattrBuilderError),
    #[allow(missing_docs)]
    NlmsghdrAck(NlmsghdrAckBuilderError),
    #[allow(missing_docs)]
    Ifstatsmsg(IfstatsmsgBuilderError),
}

impl Error for BuilderError {}

impl Display for BuilderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BuilderError::Nlmsghdr(err) => write!(f, "{err}"),
            BuilderError::Nlmsgerr(err) => write!(f, "{err}"),
            BuilderError::NlmsghdrErr(err) => write!(f, "{err}"),
            BuilderError::Genlmsghdr(err) => write!(f, "{err}"),
            BuilderError::Nlattr(err) => write!(f, "{err}"),
            BuilderError::AttrType(err) => write!(f, "{err}"),
            BuilderError::Ifinfomsg(err) => write!(f, "{err}"),
            BuilderError::Ifaddrmsg(err) => write!(f, "{err}"),
            BuilderError::Rtgenmsg(err) => write!(f, "{err}"),
            BuilderError::Rtmsg(err) => write!(f, "{err}"),
            BuilderError::Ndmsg(err) => write!(f, "{err}"),
            BuilderError::NdaCacheinfo(err) => write!(f, "{err}"),
            BuilderError::Tcmsg(err) => write!(f, "{err}"),
            BuilderError::Rtattr(err) => write!(f, "{err}"),
            BuilderError::NlmsghdrAck(err) => write!(f, "{err}"),
            BuilderError::Ifstatsmsg(err) => write!(f, "{err}"),
        }
    }
}

impl From<NlmsghdrBuilderError> for BuilderError {
    fn from(e: NlmsghdrBuilderError) -> Self {
        BuilderError::Nlmsghdr(e)
    }
}

impl From<NlmsgerrBuilderError> for BuilderError {
    fn from(e: NlmsgerrBuilderError) -> Self {
        BuilderError::Nlmsgerr(e)
    }
}

impl From<NlmsghdrErrBuilderError> for BuilderError {
    fn from(e: NlmsghdrErrBuilderError) -> Self {
        BuilderError::NlmsghdrErr(e)
    }
}

impl From<GenlmsghdrBuilderError> for BuilderError {
    fn from(e: GenlmsghdrBuilderError) -> Self {
        BuilderError::Genlmsghdr(e)
    }
}

impl From<NlattrBuilderError> for BuilderError {
    fn from(e: NlattrBuilderError) -> Self {
        BuilderError::Nlattr(e)
    }
}

impl From<AttrTypeBuilderError> for BuilderError {
    fn from(e: AttrTypeBuilderError) -> Self {
        BuilderError::AttrType(e)
    }
}

impl From<IfinfomsgBuilderError> for BuilderError {
    fn from(e: IfinfomsgBuilderError) -> Self {
        BuilderError::Ifinfomsg(e)
    }
}

impl From<IfaddrmsgBuilderError> for BuilderError {
    fn from(e: IfaddrmsgBuilderError) -> Self {
        BuilderError::Ifaddrmsg(e)
    }
}

impl From<RtgenmsgBuilderError> for BuilderError {
    fn from(e: RtgenmsgBuilderError) -> Self {
        BuilderError::Rtgenmsg(e)
    }
}

impl From<RtmsgBuilderError> for BuilderError {
    fn from(e: RtmsgBuilderError) -> Self {
        BuilderError::Rtmsg(e)
    }
}

impl From<NdmsgBuilderError> for BuilderError {
    fn from(e: NdmsgBuilderError) -> Self {
        BuilderError::Ndmsg(e)
    }
}

impl From<NdaCacheinfoBuilderError> for BuilderError {
    fn from(e: NdaCacheinfoBuilderError) -> Self {
        BuilderError::NdaCacheinfo(e)
    }
}

impl From<TcmsgBuilderError> for BuilderError {
    fn from(e: TcmsgBuilderError) -> Self {
        BuilderError::Tcmsg(e)
    }
}

impl From<RtattrBuilderError> for BuilderError {
    fn from(e: RtattrBuilderError) -> Self {
        BuilderError::Rtattr(e)
    }
}

impl From<NlmsghdrAckBuilderError> for BuilderError {
    fn from(e: NlmsghdrAckBuilderError) -> Self {
        BuilderError::NlmsghdrAck(e)
    }
}

impl From<IfstatsmsgBuilderError> for BuilderError {
    fn from(e: IfstatsmsgBuilderError) -> Self {
        BuilderError::Ifstatsmsg(e)
    }
}

/// Sendable, clonable error that can be sent across channels in the router infrastructure
/// to provide typed errors to all receivers indicating what went wrong.
#[derive(Clone, Debug)]
pub enum RouterError<T, P> {
    /// Arbitrary message
    Msg(MsgError),
    /// errno indicating what went wrong in an IO error.
    Io(ErrorKind),
    /// Deserialization error.
    De(DeError),
    /// Error from socket infrastructure.
    Socket(SocketError),
    /// An error packet sent back by netlink.
    Nlmsgerr(Nlmsgerr<NlmsghdrErr<T, P>>),
    /// A bad sequence number or PID was received.
    BadSeqOrPid(Nlmsghdr<T, P>),
    /// No ack was received when
    /// [`NlmF::Ack`][crate::consts::nl::NlmF] was specified in the
    /// request.
    NoAck,
    /// An ack was received when
    /// [`NlmF::Ack`][crate::consts::nl::NlmF] was not specified in the
    /// request.
    UnexpectedAck,
    /// A channel has closed and message processing cannot continue.
    ClosedChannel,
}

impl<T, P> RouterError<T, P> {
    /// Create a new arbitrary error message.
    pub fn new<D>(d: D) -> Self
    where
        D: Display,
    {
        RouterError::Msg(MsgError::new(d.to_string()))
    }
}

impl RouterError<u16, Buffer> {
    /// Convert to typed router error from a router error that can represent all types.
    pub fn to_typed<T, P>(self) -> Result<RouterError<T, P>, RouterError<T, P>>
    where
        T: NlType,
        P: Size + FromBytesWithInput<Input = usize>,
    {
        match self {
            RouterError::Msg(msg) => Ok(RouterError::Msg(msg)),
            RouterError::Io(kind) => Ok(RouterError::Io(kind)),
            RouterError::De(err) => Ok(RouterError::De(err)),
            RouterError::Socket(err) => Ok(RouterError::Socket(err)),
            RouterError::Nlmsgerr(err) => Ok(RouterError::Nlmsgerr(err.to_typed()?)),
            RouterError::BadSeqOrPid(msg) => Ok(RouterError::BadSeqOrPid(msg.to_typed()?)),
            RouterError::NoAck => Ok(RouterError::NoAck),
            RouterError::UnexpectedAck => Ok(RouterError::UnexpectedAck),
            RouterError::ClosedChannel => Ok(RouterError::ClosedChannel),
        }
    }
}

impl<T, P> Display for RouterError<T, P>
where
    T: Debug,
    P: Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RouterError::Msg(msg) => write!(f, "{msg}"),
            RouterError::Io(kind) => write!(f, "IO error: {kind}"),
            RouterError::De(err) => write!(f, "Deserialization failed: {err}"),
            RouterError::Socket(err) => write!(f, "Socket error: {err}"),
            RouterError::Nlmsgerr(msg) => {
                write!(f, "Application error was returned by netlink: {msg:?}")
            }
            RouterError::BadSeqOrPid(msg) => {
                write!(f, "A bad sequence number or PID was received: {msg:?}")
            }
            RouterError::NoAck => write!(f, "No ACK received"),
            RouterError::UnexpectedAck => write!(f, "ACK received when none was expected"),
            RouterError::ClosedChannel => {
                write!(f, "A channel required for message processing closed")
            }
        }
    }
}

impl<E, T, P> From<E> for RouterError<T, P>
where
    BuilderError: From<E>,
{
    fn from(e: E) -> Self {
        RouterError::new(BuilderError::from(e).to_string())
    }
}

impl<T, P> From<DeError> for RouterError<T, P> {
    fn from(e: DeError) -> Self {
        RouterError::De(e)
    }
}

impl<T, P> From<SocketError> for RouterError<T, P> {
    fn from(e: SocketError) -> Self {
        RouterError::Socket(e)
    }
}

impl<T, P> From<MsgError> for RouterError<T, P> {
    fn from(e: MsgError) -> Self {
        RouterError::Msg(e)
    }
}

impl<T, P> Error for RouterError<T, P>
where
    T: Debug,
    P: Debug,
{
}

/// General netlink error
#[derive(Clone, Debug)]
pub enum SocketError {
    /// Variant for [`String`]-based messages.
    Msg(MsgError),
    /// A serialization error.
    Ser(SerError),
    /// A deserialization error.
    De(DeError),
    /// IO error.
    Io(Arc<io::Error>),
}

impl From<SerError> for SocketError {
    fn from(err: SerError) -> Self {
        SocketError::Ser(err)
    }
}

impl From<DeError> for SocketError {
    fn from(err: DeError) -> Self {
        SocketError::De(err)
    }
}

impl From<io::Error> for SocketError {
    fn from(err: io::Error) -> Self {
        SocketError::Io(Arc::new(err))
    }
}

impl<E> From<E> for SocketError
where
    BuilderError: From<E>,
{
    fn from(err: E) -> Self {
        SocketError::new(BuilderError::from(err).to_string())
    }
}

impl From<MsgError> for SocketError {
    fn from(e: MsgError) -> Self {
        SocketError::Msg(e)
    }
}

impl SocketError {
    /// Create new error from a data type implementing
    /// [`Display`]
    pub fn new<D>(s: D) -> Self
    where
        D: Display,
    {
        SocketError::Msg(MsgError::new(s))
    }
}

impl Display for SocketError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SocketError::Msg(ref msg) => write!(f, "{msg}"),
            SocketError::Ser(ref err) => {
                write!(f, "Serialization error: {err}")
            }
            SocketError::De(ref err) => {
                write!(f, "Deserialization error: {err}")
            }
            SocketError::Io(ref err) => {
                write!(f, "IO error: {err}")
            }
        }
    }
}

impl Error for SocketError {}

/// [`String`] or [`str`] UTF error.
#[derive(Clone, Debug)]
pub enum Utf8 {
    #[allow(missing_docs)]
    Str(Utf8Error),
    #[allow(missing_docs)]
    String(FromUtf8Error),
}

impl Display for Utf8 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Utf8::Str(e) => write!(f, "{e}"),
            Utf8::String(e) => write!(f, "{e}"),
        }
    }
}

/// Serialization error
#[derive(Clone, Debug)]
pub enum SerError {
    /// Abitrary error message.
    Msg(MsgError),
    /// IO error.
    Io(ErrorKind),
    /// String UTF conversion error.
    Utf8(Utf8),
}

impl SerError {
    /// Create a new error with the given message as description.
    pub fn new<D>(msg: D) -> Self
    where
        D: Display,
    {
        SerError::Msg(MsgError::new(msg))
    }
}

impl Display for SerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SerError::Msg(ref s) => write!(f, "{s}"),
            SerError::Io(ref err) => write!(f, "IO error: {err}"),
            SerError::Utf8(ref err) => write!(f, "UTF error: {err}"),
        }
    }
}

impl Error for SerError {}

impl From<io::Error> for SerError {
    fn from(err: io::Error) -> Self {
        SerError::Io(err.kind())
    }
}

impl From<Utf8Error> for SerError {
    fn from(err: Utf8Error) -> Self {
        SerError::Utf8(Utf8::Str(err))
    }
}

impl From<FromUtf8Error> for SerError {
    fn from(err: FromUtf8Error) -> Self {
        SerError::Utf8(Utf8::String(err))
    }
}

impl From<MsgError> for SerError {
    fn from(e: MsgError) -> Self {
        SerError::Msg(e)
    }
}

/// Deserialization error
#[derive(Clone, Debug)]
pub enum DeError {
    /// Abitrary error message.
    Msg(MsgError),
    /// IO error
    Io(ErrorKind),
    /// String UTF conversion error.
    Utf8(Utf8),
    /// Invalid input parameter for [`FromBytesWithInput`].
    InvalidInput(usize),
}

impl DeError {
    /// Create new error from a type implementing
    /// [`Display`]
    pub fn new<D>(s: D) -> Self
    where
        D: Display,
    {
        DeError::Msg(MsgError::new(s))
    }
}

impl Display for DeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DeError::Msg(s) => write!(f, "{s}"),
            DeError::Utf8(err) => write!(f, "UTF8 error: {err}"),
            DeError::Io(err) => write!(f, "IO error: {err}"),
            DeError::InvalidInput(input) => write!(f, "Invalid input was provided: {input}"),
        }
    }
}

impl Error for DeError {}

impl From<io::Error> for DeError {
    fn from(err: io::Error) -> Self {
        DeError::Io(err.kind())
    }
}

impl From<Utf8Error> for DeError {
    fn from(err: Utf8Error) -> Self {
        DeError::Utf8(Utf8::Str(err))
    }
}

impl From<FromUtf8Error> for DeError {
    fn from(err: FromUtf8Error) -> Self {
        DeError::Utf8(Utf8::String(err))
    }
}

impl<E> From<E> for DeError
where
    BuilderError: From<E>,
{
    fn from(err: E) -> Self {
        DeError::new(BuilderError::from(err).to_string())
    }
}

impl From<MsgError> for DeError {
    fn from(e: MsgError) -> Self {
        DeError::Msg(e)
    }
}

/// Arbitrary error message.
#[derive(Clone, Debug)]
pub struct MsgError(String);

impl MsgError {
    /// Construct a new error message.
    pub fn new<D>(d: D) -> Self
    where
        D: Display,
    {
        MsgError(d.to_string())
    }
}

impl Display for MsgError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for MsgError {}
