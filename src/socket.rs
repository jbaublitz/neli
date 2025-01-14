//! This module provides code that glues all of the other modules
//! together and allows message send and receive operations.
//!
//! ## Important methods
//! * [`NlSocket::send`] and [`NlSocket::recv`] methods are meant to
//!   be the most low level calls. They essentially do what the C
//!   system calls `send` and `recv` do with very little abstraction.
//! * [`NlSocketHandle::send`] and [`NlSocketHandle::recv`] methods
//!   are meant to provide an interface that is more idiomatic for
//!   the library.
//! * [`NlSocketHandle::iter`] provides a loop based iteration
//!   through messages that are received in a stream over the socket.
//!
//! ## Features
//! The `async` feature exposed by `cargo` allows the socket to use
//! Rust's [tokio](https://tokio.rs) for async IO.
//!
//! ## Additional methods
//!
//! There are methods for blocking and non-blocking, resolving
//! generic netlink multicast group IDs, and other convenience
//! functions so see if your use case is supported. If it isn't,
//! please open a Github issue and submit a feature request.
//!
//! ## Design decisions
//!
//! The buffer allocated in the [`NlSocketHandle`] structure should
//! be allocated on the heap. This is intentional as a buffer
//! that large could be a problem on the stack.

use std::{
    fmt::Debug,
    io::{self, Cursor},
    mem::{size_of, zeroed, MaybeUninit},
    os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
};

use libc::{self, c_int, c_void};
use log::debug;

use crate::{
    consts::{genl::*, nl::*, socket::*, MAX_NL_LENGTH},
    err::{NlError, SerError},
    genl::{Genlmsghdr, Nlattr},
    iter::{IterationBehavior, NlMessageIter},
    nl::{NlPayload, Nlmsghdr},
    parse::packet_length_u32,
    types::{GenlBuffer, NlBuffer},
    utils::NetlinkBitArray,
    FromBytes, FromBytesWithInput, ToBytes,
};

/// Low level access to a netlink socket.
pub struct NlSocket {
    fd: c_int,
}

impl NlSocket {
    /// Wrapper around `socket()` syscall filling in the
    /// netlink-specific information.
    pub fn new(proto: NlFamily) -> Result<Self, io::Error> {
        let fd =
            match unsafe { libc::socket(AddrFamily::Netlink.into(), libc::SOCK_RAW, proto.into()) }
            {
                i if i >= 0 => Ok(i),
                _ => Err(io::Error::last_os_error()),
            }?;
        Ok(NlSocket { fd })
    }

    /// Equivalent of `socket` and `bind` calls.
    pub fn connect(proto: NlFamily, pid: Option<u32>, groups: &[u32]) -> Result<Self, io::Error> {
        let s = NlSocket::new(proto)?;
        s.bind(pid, groups)?;
        Ok(s)
    }

    /// Set underlying socket file descriptor to be blocking.
    pub fn block(&self) -> Result<(), io::Error> {
        match unsafe {
            libc::fcntl(
                self.fd,
                libc::F_SETFL,
                libc::fcntl(self.fd, libc::F_GETFL, 0) & !libc::O_NONBLOCK,
            )
        } {
            i if i < 0 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    }

    /// Set underlying socket file descriptor to be non blocking.
    pub fn nonblock(&self) -> Result<(), io::Error> {
        match unsafe {
            libc::fcntl(
                self.fd,
                libc::F_SETFL,
                libc::fcntl(self.fd, libc::F_GETFL, 0) | libc::O_NONBLOCK,
            )
        } {
            i if i < 0 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    }

    /// Determines if underlying file descriptor is blocking.
    pub fn is_blocking(&self) -> Result<bool, io::Error> {
        let is_blocking = match unsafe { libc::fcntl(self.fd, libc::F_GETFL, 0) } {
            i if i >= 0 => i & libc::O_NONBLOCK == 0,
            _ => return Err(io::Error::last_os_error()),
        };
        Ok(is_blocking)
    }

    /// Use this function to bind to a netlink ID and subscribe to
    /// groups. See netlink(7) man pages for more information on
    /// netlink IDs and groups.
    pub fn bind(&self, pid: Option<u32>, groups: &[u32]) -> Result<(), io::Error> {
        let mut nladdr = unsafe { zeroed::<libc::sockaddr_nl>() };
        nladdr.nl_family = libc::c_int::from(AddrFamily::Netlink) as u16;
        nladdr.nl_pid = pid.unwrap_or(0);
        nladdr.nl_groups = 0;
        match unsafe {
            libc::bind(
                self.fd,
                &nladdr as *const _ as *const libc::sockaddr,
                size_of::<libc::sockaddr_nl>() as u32,
            )
        } {
            i if i >= 0 => (),
            _ => return Err(io::Error::last_os_error()),
        };
        if !groups.is_empty() {
            self.add_mcast_membership(groups)?;
        }
        Ok(())
    }

    /// Join multicast groups for a socket.
    pub fn add_mcast_membership(&self, groups: &[u32]) -> Result<(), io::Error> {
        for group in groups {
            match unsafe {
                libc::setsockopt(
                    self.fd,
                    libc::SOL_NETLINK,
                    libc::NETLINK_ADD_MEMBERSHIP,
                    group as *const _ as *const libc::c_void,
                    size_of::<u32>() as libc::socklen_t,
                )
            } {
                0 => (),
                _ => return Err(io::Error::last_os_error()),
            }
        }
        Ok(())
    }

    /// Leave multicast groups for a socket.
    pub fn drop_mcast_membership(&self, groups: &[u32]) -> Result<(), io::Error> {
        for group in groups {
            match unsafe {
                libc::setsockopt(
                    self.fd,
                    libc::SOL_NETLINK,
                    libc::NETLINK_DROP_MEMBERSHIP,
                    group as *const _ as *const libc::c_void,
                    size_of::<u32>() as libc::socklen_t,
                )
            } {
                0 => (),
                _ => return Err(io::Error::last_os_error()),
            }
        }
        Ok(())
    }

    /// List joined groups for a socket.
    pub fn list_mcast_membership(&self) -> Result<NetlinkBitArray, io::Error> {
        let mut bit_array = NetlinkBitArray::new(4);
        let mut len = bit_array.len();
        if unsafe {
            libc::getsockopt(
                self.fd,
                libc::SOL_NETLINK,
                libc::NETLINK_LIST_MEMBERSHIPS,
                bit_array.as_mut_slice() as *mut _ as *mut libc::c_void,
                &mut len as *mut _ as *mut libc::socklen_t,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if len > bit_array.len() {
            bit_array.resize(len);
            if unsafe {
                libc::getsockopt(
                    self.fd,
                    libc::SOL_NETLINK,
                    libc::NETLINK_LIST_MEMBERSHIPS,
                    bit_array.as_mut_slice() as *mut _ as *mut libc::c_void,
                    &mut len as *mut _ as *mut libc::socklen_t,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(bit_array)
    }

    /// Send message encoded as byte slice to the netlink ID
    /// specified in the netlink header
    /// [`Nlmsghdr`].
    pub fn send<B>(&self, buf: B, flags: i32) -> Result<libc::size_t, io::Error>
    where
        B: AsRef<[u8]>,
    {
        match unsafe {
            libc::send(
                self.fd,
                buf.as_ref() as *const _ as *const c_void,
                buf.as_ref().len(),
                flags,
            )
        } {
            i if i >= 0 => Ok(i as libc::size_t),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Receive message encoded as byte slice from the netlink socket.
    pub fn recv<B>(&self, mut buf: B, flags: i32) -> Result<libc::size_t, io::Error>
    where
        B: AsMut<[u8]>,
    {
        match unsafe {
            libc::recv(
                self.fd,
                buf.as_mut() as *mut _ as *mut c_void,
                buf.as_mut().len(),
                flags,
            )
        } {
            i if i >= 0 => Ok(i as libc::size_t),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Get the PID for this socket.
    pub fn pid(&self) -> Result<u32, io::Error> {
        let mut sock_len = size_of::<libc::sockaddr_nl>() as u32;
        let mut sock_addr: MaybeUninit<libc::sockaddr_nl> = MaybeUninit::uninit();
        match unsafe {
            libc::getsockname(
                self.fd,
                sock_addr.as_mut_ptr() as *mut _,
                &mut sock_len as *mut _,
            )
        } {
            i if i >= 0 => Ok(unsafe { sock_addr.assume_init() }.nl_pid),
            _ => Err(io::Error::last_os_error()),
        }
    }
}

impl From<NlSocketHandle> for NlSocket {
    fn from(s: NlSocketHandle) -> Self {
        s.socket
    }
}

impl AsRawFd for NlSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl IntoRawFd for NlSocket {
    fn into_raw_fd(self) -> RawFd {
        let fd = self.fd;
        std::mem::forget(self);
        fd
    }
}

impl FromRawFd for NlSocket {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        NlSocket { fd }
    }
}

impl Drop for NlSocket {
    /// Closes underlying file descriptor to avoid file descriptor
    /// leaks.
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// Higher level handle for socket operations.
pub struct NlSocketHandle {
    socket: NlSocket,
    buffer: Vec<u8>,
    position: usize,
    end: usize,
    pub(super) needs_ack: bool,
}

type GenlFamily = Result<
    NlBuffer<GenlId, Genlmsghdr<CtrlCmd, CtrlAttr>>,
    NlError<GenlId, Genlmsghdr<CtrlCmd, CtrlAttr>>,
>;

impl NlSocketHandle {
    /// Wrapper around `socket()` syscall filling in the
    /// netlink-specific information
    pub fn new(proto: NlFamily) -> Result<Self, io::Error> {
        Ok(NlSocketHandle {
            socket: NlSocket::new(proto)?,
            buffer: vec![0; MAX_NL_LENGTH],
            position: 0,
            end: 0,
            needs_ack: false,
        })
    }

    /// Equivalent of `socket` and `bind` calls.
    pub fn connect(proto: NlFamily, pid: Option<u32>, groups: &[u32]) -> Result<Self, io::Error> {
        Ok(NlSocketHandle {
            socket: NlSocket::connect(proto, pid, groups)?,
            buffer: vec![0; MAX_NL_LENGTH],
            position: 0,
            end: 0,
            needs_ack: false,
        })
    }

    /// Set underlying socket file descriptor to be blocking.
    pub fn block(&self) -> Result<(), io::Error> {
        self.socket.block()
    }

    /// Set underlying socket file descriptor to be non blocking.
    pub fn nonblock(&self) -> Result<(), io::Error> {
        self.socket.nonblock()
    }

    /// Determines if underlying file descriptor is blocking.
    pub fn is_blocking(&self) -> Result<bool, io::Error> {
        self.socket.is_blocking()
    }

    /// Use this function to bind to a netlink ID and subscribe to
    /// groups. See netlink(7) man pages for more information on
    /// netlink IDs and groups.
    pub fn bind(&self, pid: Option<u32>, groups: &[u32]) -> Result<(), io::Error> {
        self.socket.bind(pid, groups)
    }

    /// Join multicast groups for a socket.
    pub fn add_mcast_membership(&self, groups: &[u32]) -> Result<(), io::Error> {
        self.socket.add_mcast_membership(groups)
    }

    /// Leave multicast groups for a socket.
    pub fn drop_mcast_membership(&self, groups: &[u32]) -> Result<(), io::Error> {
        self.socket.drop_mcast_membership(groups)
    }

    /// List joined groups for a socket.
    pub fn list_mcast_membership(&self) -> Result<NetlinkBitArray, io::Error> {
        self.socket.list_mcast_membership()
    }

    /// Get the PID for the current socket.
    pub fn pid(&self) -> Result<u32, io::Error> {
        self.socket.pid()
    }

    fn get_genl_family(&mut self, family_name: &str) -> GenlFamily {
        let mut attrs = GenlBuffer::new();
        attrs.push(Nlattr::new(
            false,
            false,
            CtrlAttr::FamilyName,
            family_name,
        )?);
        let genlhdr = Genlmsghdr::new(CtrlCmd::Getfamily, 2, attrs);
        let nlhdr = Nlmsghdr::new(
            None,
            GenlId::Ctrl,
            NlmFFlags::new(&[NlmF::Request, NlmF::Ack]),
            None,
            None,
            NlPayload::Payload(genlhdr),
        );
        self.send(nlhdr)?;

        let mut buffer = NlBuffer::new();
        for msg in self.iter(false) {
            buffer.push(msg?);
        }
        Ok(buffer)
    }

    /// Convenience function for resolving a [`str`] containing the
    /// generic netlink family name to a numeric generic netlink ID.
    pub fn resolve_genl_family(
        &mut self,
        family_name: &str,
    ) -> Result<u16, NlError<GenlId, Genlmsghdr<CtrlCmd, CtrlAttr>>> {
        let mut res = Err(NlError::new(format!(
            "Generic netlink family {} was not found",
            family_name
        )));

        let nlhdrs = self.get_genl_family(family_name)?;
        for nlhdr in nlhdrs.into_iter() {
            if let NlPayload::Payload(p) = nlhdr.nl_payload {
                let handle = p.get_attr_handle();
                if let Ok(u) = handle.get_attr_payload_as::<u16>(CtrlAttr::FamilyId) {
                    res = Ok(u);
                }
            }
        }

        res
    }

    /// Convenience function for resolving a [`str`] containing the
    /// multicast group name to a numeric multicast group ID.
    pub fn resolve_nl_mcast_group(
        &mut self,
        family_name: &str,
        mcast_name: &str,
    ) -> Result<u32, NlError<GenlId, Genlmsghdr<CtrlCmd, CtrlAttr>>> {
        let mut res = Err(NlError::new(format!(
            "Failed to resolve multicast group ID for family name {}, multicast group name {}",
            family_name, mcast_name,
        )));

        let nlhdrs = self.get_genl_family(family_name)?;
        for nlhdr in nlhdrs {
            if let NlPayload::Payload(p) = nlhdr.nl_payload {
                let mut handle = p.get_attr_handle();
                let mcast_groups = handle.get_nested_attributes::<Index>(CtrlAttr::McastGroups)?;
                if let Some(id) = mcast_groups.iter().find_map(|item| {
                    let nested_attrs = item.get_attr_handle::<CtrlAttrMcastGrp>().ok()?;
                    let string = nested_attrs
                        .get_attr_payload_as_with_len::<String>(CtrlAttrMcastGrp::Name)
                        .ok()?;
                    if string.as_str() == mcast_name {
                        nested_attrs
                            .get_attr_payload_as::<u32>(CtrlAttrMcastGrp::Id)
                            .ok()
                    } else {
                        None
                    }
                }) {
                    res = Ok(id);
                }
            }
        }

        res
    }

    /// Look up netlink family and multicast group name by ID.
    pub fn lookup_id(
        &mut self,
        id: u32,
    ) -> Result<(String, String), NlError<GenlId, Genlmsghdr<CtrlCmd, CtrlAttr>>> {
        let mut res = Err(NlError::new("ID does not correspond to a multicast group"));

        let attrs = GenlBuffer::new();
        let genlhdr = Genlmsghdr::<CtrlCmd, CtrlAttr>::new(CtrlCmd::Getfamily, 2, attrs);
        let nlhdr = Nlmsghdr::new(
            None,
            GenlId::Ctrl,
            NlmFFlags::new(&[NlmF::Request, NlmF::Dump]),
            None,
            None,
            NlPayload::Payload(genlhdr),
        );

        self.send(nlhdr)?;
        for res_msg in self.iter::<GenlId, Genlmsghdr<CtrlCmd, CtrlAttr>>(false) {
            let msg = res_msg?;

            if let NlPayload::Payload(p) = msg.nl_payload {
                let mut attributes = p.get_attr_handle();
                let name =
                    attributes.get_attr_payload_as_with_len::<String>(CtrlAttr::FamilyName)?;
                let groups = match attributes.get_nested_attributes::<Index>(CtrlAttr::McastGroups)
                {
                    Ok(grps) => grps,
                    Err(_) => continue,
                };
                for group_by_index in groups.iter() {
                    let attributes = group_by_index.get_attr_handle::<CtrlAttrMcastGrp>()?;
                    if let Ok(mcid) = attributes.get_attr_payload_as::<u32>(CtrlAttrMcastGrp::Id) {
                        if mcid == id {
                            let mcast_name = attributes
                                .get_attr_payload_as_with_len::<String>(CtrlAttrMcastGrp::Name)?;
                            res = Ok((name.clone(), mcast_name));
                        }
                    }
                }
            }
        }

        res
    }

    /// Convenience function to send an [`Nlmsghdr`] struct
    pub fn send<T, P>(&mut self, msg: Nlmsghdr<T, P>) -> Result<(), SerError>
    where
        T: NlType + Debug,
        P: ToBytes + Debug,
    {
        debug!("Message sent:\n{:?}", msg);

        if msg.nl_flags.contains(&NlmF::Ack) && !msg.nl_flags.contains(&NlmF::Dump) {
            self.needs_ack = true;
        }

        let mut buffer = Cursor::new(Vec::new());
        msg.to_bytes(&mut buffer)?;
        self.socket.send(buffer.get_ref(), 0)?;

        Ok(())
    }

    /// Convenience function to read a stream of
    /// [`Nlmsghdr`] structs one by one.
    /// Use [`NlSocketHandle::iter`] instead for easy iteration over
    /// returned packets.
    ///
    /// Returns [`None`] only in non-blocking contexts if no
    /// message can be immediately returned or if the socket
    /// has been closed.
    pub fn recv<'a, T, P>(&'a mut self) -> Result<Option<Nlmsghdr<T, P>>, NlError<T, P>>
    where
        T: NlType + Debug,
        P: FromBytesWithInput<'a, Input = usize> + Debug,
    {
        if self.end == self.position {
            // Read the buffer from the socket and fail if nothing
            // was read.
            let mem_read_res = self.socket.recv(&mut self.buffer, 0);
            if let Err(ref e) = mem_read_res {
                if e.kind() == io::ErrorKind::WouldBlock {
                    return Ok(None);
                }
            }
            let mem_read = mem_read_res?;
            if mem_read == 0 {
                return Ok(None);
            }
            self.position = 0;
            self.end = mem_read;
        }

        let (packet_res, next_packet_len) = {
            let end = self.buffer.len();
            // Get the next packet length at the current position of the
            // buffer for the next read operation.
            if self.position == end {
                return Ok(None);
            }
            let next_packet_len = packet_length_u32(&self.buffer, self.position);
            // If the packet extends past the end of the number of bytes
            // read into the buffer, return an error; something
            // has gone wrong.
            if self.position + next_packet_len > end {
                return Err(NlError::new("Incomplete packet received from socket"));
            }

            // Deserialize the next Nlmsghdr struct.
            let deserialized_packet_result = Nlmsghdr::<T, P>::from_bytes(&mut Cursor::new(
                &self.buffer[self.position..self.position + next_packet_len],
            ));

            (deserialized_packet_result, next_packet_len)
        };

        let packet = match packet_res {
            Ok(packet) => {
                // If successful, forward the position of the buffer
                // for the next read.
                self.position += next_packet_len;

                packet
            }
            Err(e) => return Err(NlError::De(e)),
        };

        debug!("Message received: {:?}", packet);

        if let NlPayload::Err(e) = packet.nl_payload {
            return Err(NlError::<T, P>::from(e));
        } else if let NlPayload::Ack(_) = packet.nl_payload {
            if self.needs_ack {
                self.needs_ack = false;
            } else {
                return Err(NlError::new(
                    "Socket did not expect an ACK but one was received",
                ));
            }
        }

        Ok(Some(packet))
    }

    /// Parse all [`Nlmsghdr`] structs sent in
    /// one network packet and return them all in a list.
    ///
    /// Failure to parse any packet will cause the entire operation
    /// to fail. If an error is detected at the application level,
    /// this method will discard any non-error
    /// [`Nlmsghdr`] structs and only return the
    /// error. This method checks for ACKs. For a more granular
    /// approach, use either [`NlSocketHandle::recv`] or
    /// [`NlSocketHandle::iter`].
    pub fn recv_all<'a, T, P>(&'a mut self) -> Result<NlBuffer<T, P>, NlError>
    where
        T: NlType + Debug,
        P: FromBytesWithInput<'a, Input = usize> + Debug,
    {
        if self.position == self.end {
            let mem_read = self.socket.recv(&mut self.buffer, 0)?;
            if mem_read == 0 {
                return Err(NlError::new("No data could be read from the socket"));
            }
            self.end = mem_read;
        }

        let vec =
            NlBuffer::from_bytes_with_input(&mut Cursor::new(&self.buffer[0..self.end]), self.end)?;

        debug!("Messages received: {:?}", vec);

        self.position = 0;
        self.end = 0;
        Ok(vec)
    }

    /// Return an iterator object
    ///
    /// The argument `iterate_indefinitely` is documented
    /// in more detail in [`NlMessageIter`]
    pub fn iter<'a, T, P>(&'a mut self, iter_indefinitely: bool) -> NlMessageIter<'a, T, P>
    where
        T: NlType + Debug,
        P: FromBytesWithInput<'a, Input = usize> + Debug,
    {
        let behavior = if iter_indefinitely {
            IterationBehavior::IterIndefinitely
        } else {
            IterationBehavior::EndMultiOnDone
        };
        NlMessageIter::new(self, behavior)
    }
}

impl AsRawFd for NlSocketHandle {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

impl IntoRawFd for NlSocketHandle {
    fn into_raw_fd(self) -> RawFd {
        self.socket.into_raw_fd()
    }
}

impl FromRawFd for NlSocketHandle {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        NlSocketHandle {
            socket: NlSocket::from_raw_fd(fd),
            buffer: vec![0; MAX_NL_LENGTH],
            end: 0,
            position: 0,
            needs_ack: false,
        }
    }
}

#[cfg(feature = "async")]
pub mod tokio {
    //! Tokio-specific features for neli
    //!
    //! This module contains a struct that wraps [`NlSocket`] for
    //! async IO.
    use super::*;

    use std::{
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
    };

    use ::tokio::io::{unix::AsyncFd, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

    use crate::{err::DeError, Size};

    macro_rules! ready {
        ($e:expr $(,)?) => {
            match $e {
                ::std::task::Poll::Ready(t) => t,
                ::std::task::Poll::Pending => return ::std::task::Poll::Pending,
            }
        };
    }

    fn poll_read_priv(
        async_fd: &AsyncFd<super::NlSocket>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(async_fd.poll_read_ready(cx))?;
            match guard.try_io(|fd| {
                let bytes_read = fd.get_ref().recv(buf.initialized_mut(), 0)?;
                buf.advance(bytes_read);
                Ok(bytes_read)
            }) {
                Ok(Ok(bytes_read)) => return Poll::Ready(Ok(bytes_read)),
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_) => continue,
            }
        }
    }

    fn poll_write_priv(
        async_fd: &AsyncFd<super::NlSocket>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut guard = ready!(async_fd.poll_write_ready(cx))?;
        guard.clear_ready();
        let socket = async_fd.get_ref();
        Poll::Ready(socket.send(buf, 0))
    }

    /// Tokio-enabled Netlink socket struct
    pub struct NlSocket {
        socket: Arc<AsyncFd<super::NlSocket>>,
    }

    impl NlSocket {
        /// Set up [`NlSocket`][crate::socket::NlSocket] for use
        /// with tokio; set to nonblocking state and wrap in polling
        /// mechanism.
        pub fn new<S>(s: S) -> io::Result<Self>
        where
            S: Into<super::NlSocket>,
        {
            let socket = s.into();
            if socket.is_blocking()? {
                socket.nonblock()?;
            }
            Ok(NlSocket {
                socket: Arc::new(AsyncFd::new(socket)?),
            })
        }

        /// Send a message on the socket asynchronously.
        pub async fn send<T, P>(&mut self, msg: &Nlmsghdr<T, P>) -> Result<(), SerError>
        where
            T: NlType,
            P: Size + ToBytes,
        {
            let mut buffer = Cursor::new(vec![0; msg.padded_size()]);
            msg.to_bytes(&mut buffer)?;
            self.write_all(buffer.get_ref()).await?;
            Ok(())
        }

        /// Receive a message from the socket asynchronously.
        pub async fn recv<'a, T, P>(
            &mut self,
            buffer: &'a mut Vec<u8>,
        ) -> Result<NlBuffer<T, P>, DeError>
        where
            T: NlType,
            P: FromBytesWithInput<'a, Input = usize>,
        {
            if buffer.len() != MAX_NL_LENGTH {
                buffer.resize(MAX_NL_LENGTH, 0);
            }
            let bytes = self.read(buffer.as_mut_slice()).await?;
            buffer.truncate(bytes);
            NlBuffer::from_bytes_with_input(&mut Cursor::new(buffer.as_slice()), bytes)
        }
    }

    impl AsyncRead for NlSocket {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &mut ReadBuf,
        ) -> Poll<io::Result<()>> {
            let _ = ready!(poll_read_priv(&self.socket, cx, buf))?;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for NlSocket {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            poll_write_priv(&self.socket, cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Unpin for NlSocket {}
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::{consts::nl::Nlmsg, test::setup};

    #[test]
    fn multi_msg_iter() {
        setup();

        let mut attrs = GenlBuffer::new();
        attrs.push(Nlattr::new(false, false, CtrlAttr::FamilyId, 5u32).unwrap());
        attrs.push(Nlattr::new(false, false, CtrlAttr::FamilyName, "my_family_name").unwrap());
        let nl1 = Nlmsghdr::new(
            None,
            NlTypeWrapper::Nlmsg(Nlmsg::Noop),
            NlmFFlags::new(&[NlmF::Multi]),
            None,
            None,
            NlPayload::Payload(Genlmsghdr::new(CtrlCmd::Unspec, 2, attrs)),
        );

        let mut attrs = GenlBuffer::new();
        attrs.push(Nlattr::new(false, false, CtrlAttr::FamilyId, 6u32).unwrap());
        attrs
            .push(Nlattr::new(false, false, CtrlAttr::FamilyName, "my_other_family_name").unwrap());
        let nl2 = Nlmsghdr::new(
            None,
            NlTypeWrapper::Nlmsg(Nlmsg::Noop),
            NlmFFlags::new(&[NlmF::Multi]),
            None,
            None,
            NlPayload::Payload(Genlmsghdr::new(CtrlCmd::Unspec, 2, attrs)),
        );
        let mut v = NlBuffer::new();
        v.push(nl1);
        v.push(nl2);
        let mut buffer = Cursor::new(Vec::new());
        let bytes = {
            v.to_bytes(&mut buffer).unwrap();
            buffer.into_inner()
        };

        let bytes_len = bytes.len();
        let mut s = NlSocketHandle {
            socket: unsafe { NlSocket::from_raw_fd(-1) },
            buffer: bytes,
            needs_ack: false,
            position: 0,
            end: bytes_len,
        };
        let mut iter = s.iter(false);
        let nl_next1 = if let Some(Ok(nl_next)) = iter.next() {
            nl_next
        } else {
            panic!("Expected message not found");
        };
        let nl_next2 = if let Some(Ok(nl_next)) = iter.next() {
            nl_next
        } else {
            panic!("Expected message not found");
        };
        let mut nl = NlBuffer::new();
        nl.push(nl_next1);
        nl.push(nl_next2);
        assert_eq!(nl, v);
    }

    #[test]
    fn real_test_mcast_groups() {
        setup();

        let mut sock = NlSocketHandle::new(NlFamily::Generic).unwrap();
        let notify_id_result = sock.resolve_nl_mcast_group("nlctrl", "notify");
        let config_id_result = sock.resolve_nl_mcast_group("devlink", "config");

        let ids = match (notify_id_result, config_id_result) {
            (Ok(ni), Ok(ci)) => {
                sock.add_mcast_membership(&[ni, ci]).unwrap();
                vec![ni, ci]
            }
            (Ok(ni), Err(NlError::Nlmsgerr(_))) => {
                sock.add_mcast_membership(&[ni]).unwrap();
                vec![ni]
            }
            (Err(NlError::Nlmsgerr(_)), Ok(ci)) => {
                sock.add_mcast_membership(&[ci]).unwrap();
                vec![ci]
            }
            (Err(NlError::Nlmsgerr(_)), Err(NlError::Nlmsgerr(_))) => {
                return;
            }
            (Err(e), _) => panic!("Unexpected result from resolve_nl_mcast_group: {:?}", e),
            (_, Err(e)) => panic!("Unexpected result from resolve_nl_mcast_group: {:?}", e),
        };

        let groups = sock.list_mcast_membership().unwrap();
        for id in ids.iter() {
            assert!(groups.is_set(*id as usize));
        }

        sock.drop_mcast_membership(ids.as_slice()).unwrap();
        let groups = sock.list_mcast_membership().unwrap();

        for id in ids.iter() {
            assert!(!groups.is_set(*id as usize));
        }
    }

    #[test]
    fn real_test_pid() {
        setup();

        let s = NlSocket::connect(NlFamily::Generic, Some(5555), &[]).unwrap();
        assert_eq!(s.pid().unwrap(), 5555);
    }
}
