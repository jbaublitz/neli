//! This module provides code that glues all of the other modules together and allows message send
//! and receive operations. This module relies heavily on the `buffering` crate. See `buffering`
//! for more information on the serialization and deserialization implementations.
//!
//! ## Important methods
//! * `send` and `recv` methods are meant to be the most low level calls. They essentially do what
//! the C system calls `send` and `recv` do with very little abstraction.
//! * `send_nl` and `recv_nl` methods are meant to provide an interface that is more idiomatic for
//! the library. The are able to operate on any structure wrapped in an `Nlmsghdr` struct that implements
//! the `Nl` trait.
//! * `iter` provides a loop based iteration through messages that are received in a stream over
//! the socket.
//! * `recv_ack` receives an ACK message and verifies it matches the request.
//!
//! ## Features
//! The `async` feature exposed by `cargo` allows the socket to use Rust's tokio for async IO.
//!
//! ## Additional methods
//!
//! There are methods for blocking and non-blocking, resolving generic netlink multicast group IDs,
//! and other convenience functions so see if your use case is supported. If it isn't, please open
//! a Github issue and submit a feature request.
//!
//! ## Design decisions
//!
//! The buffer allocated in the `NlSocket` structure should
//! be allocated on the heap. This is intentional as a buffer
//! that large could be a problem on the stack. Big thanks to
//! @vorner for the suggestion on how to minimize allocations.

use std::{
    fmt::Debug,
    io,
    mem::{size_of, zeroed},
    os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
};

use libc::{self, c_int, c_void};

#[cfg(feature = "logging")]
use crate::log;
use crate::{
    consts::{
        nl::*, AddrFamily, CtrlAttr, CtrlAttrMcastGrp, CtrlCmd, GenlId, Index, NlAttrType,
        NlFamily, NlType, NlmF, NlmFFlags,
    },
    err::NlError,
    genl::Genlmsghdr,
    iter::{IterationBehavior, NlMessageIter},
    nl::{NlPayload, Nlmsghdr},
    nlattr::Nlattr,
    parse::{packet_length_u32, parse_next},
    types::{
        DeBuffer, GenlBuffer, GenlBufferOps, NlBuffer, NlBufferOps, SerBuffer, SerBufferOps,
        SockBuffer, SockBufferOps,
    },
    utils::U32Bitmask,
    Nl,
};

/// Define the behavior on a netlink packet parsing error
pub enum OnError {
    /// Rewind the position to the beginning of the packet to try again
    Rewind,
    /// Skip to the next packet, discarding the failed packet
    FastForward,
}

/// Low level access to a netlink socket.
pub struct NlSocket {
    fd: c_int,
}

impl NlSocket {
    /// Wrapper around `socket()` syscall filling in the netlink-specific information
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
    pub fn connect(
        proto: NlFamily,
        pid: Option<u32>,
        groups: U32Bitmask,
    ) -> Result<Self, io::Error> {
        let s = NlSocket::new(proto)?;
        s.bind(pid, groups)?;
        Ok(s)
    }

    /// Set underlying socket file descriptor to be blocking
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

    /// Set underlying socket file descriptor to be non blocking
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

    /// Determines if underlying file descriptor is blocking - `Stream` feature will throw an
    /// error if this function returns false
    pub fn is_blocking(&self) -> Result<bool, io::Error> {
        let is_blocking = match unsafe { libc::fcntl(self.fd, libc::F_GETFL, 0) } {
            i if i >= 0 => i & libc::O_NONBLOCK == 0,
            _ => return Err(io::Error::last_os_error()),
        };
        Ok(is_blocking)
    }

    /// Use this function to bind to a netlink ID and subscribe to groups. See netlink(7)
    /// man pages for more information on netlink IDs and groups.
    ///
    /// The pid parameter sets PID checking.
    /// * `None` means checking is off.
    /// * `Some(0)` turns checking on, but takes the PID from the first received message.
    /// * `Some(pid)` uses the given PID.
    pub fn bind(&self, pid: Option<u32>, groups: U32Bitmask) -> Result<(), io::Error> {
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

    /// Join multicast groups for a socket
    pub fn add_mcast_membership(&self, groups: U32Bitmask) -> Result<(), io::Error> {
        match unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_NETLINK,
                libc::NETLINK_ADD_MEMBERSHIP,
                &*groups as *const _ as *const libc::c_void,
                size_of::<u32>() as libc::socklen_t,
            )
        } {
            i if i == 0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Leave multicast groups for a socket
    pub fn drop_mcast_membership(&self, groups: U32Bitmask) -> Result<(), io::Error> {
        match unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_NETLINK,
                libc::NETLINK_DROP_MEMBERSHIP,
                &*groups as *const _ as *const libc::c_void,
                size_of::<u32>() as libc::socklen_t,
            )
        } {
            i if i == 0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// List joined groups for a socket
    pub fn list_mcast_membership(&self) -> Result<U32Bitmask, io::Error> {
        let mut grps = 0u32;
        let mut len = size_of::<u32>() as libc::socklen_t;
        match unsafe {
            libc::getsockopt(
                self.fd,
                libc::SOL_NETLINK,
                libc::NETLINK_LIST_MEMBERSHIPS,
                &mut grps as *mut _ as *mut libc::c_void,
                &mut len as *mut _ as *mut libc::socklen_t,
            )
        } {
            i if i == 0 => Ok(U32Bitmask::from(grps)),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Send message encoded as byte slice to the netlink ID specified in the netlink header
    /// (`neli::nl::Nlmsghdr`)
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
    /// Closes underlying file descriptor to avoid file descriptor leaks.
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// Higher level handle for socket operations.
pub struct NlSocketHandle {
    socket: NlSocket,
    buffer: SockBuffer,
    position: usize,
    end: usize,
    needs_ack: bool,
    expects_ack: bool,
}

impl NlSocketHandle {
    /// Wrapper around `socket()` syscall filling in the netlink-specific information
    pub fn new(proto: NlFamily) -> Result<Self, io::Error> {
        Ok(NlSocketHandle {
            socket: NlSocket::new(proto)?,
            buffer: SockBuffer::new(),
            position: 0,
            end: 0,
            needs_ack: false,
            expects_ack: false,
        })
    }

    /// Equivalent of `socket` and `bind` calls.
    pub fn connect(
        proto: NlFamily,
        pid: Option<u32>,
        groups: U32Bitmask,
    ) -> Result<Self, io::Error> {
        Ok(NlSocketHandle {
            socket: NlSocket::connect(proto, pid, groups)?,
            buffer: SockBuffer::new(),
            position: 0,
            end: 0,
            needs_ack: false,
            expects_ack: false,
        })
    }

    /// Set underlying socket file descriptor to be blocking
    pub fn block(&self) -> Result<(), io::Error> {
        self.socket.block()
    }

    /// Set underlying socket file descriptor to be non blocking
    pub fn nonblock(&self) -> Result<(), io::Error> {
        self.socket.nonblock()
    }

    /// Determines if underlying file descriptor is blocking - `Stream` feature will throw an
    /// error if this function returns false
    pub fn is_blocking(&self) -> Result<bool, io::Error> {
        self.socket.is_blocking()
    }

    /// Use this function to bind to a netlink ID and subscribe to groups. See netlink(7)
    /// man pages for more information on netlink IDs and groups.
    ///
    /// The pid parameter sets PID checking.
    /// * `None` means checking is off.
    /// * `Some(0)` turns checking on, but takes the PID from the first received message.
    /// * `Some(pid)` uses the given PID.
    pub fn bind(&self, pid: Option<u32>, groups: U32Bitmask) -> Result<(), io::Error> {
        self.socket.bind(pid, groups)
    }

    /// Join multicast groups for a socket
    pub fn add_mcast_membership(&self, groups: U32Bitmask) -> Result<(), io::Error> {
        self.socket.add_mcast_membership(groups)
    }

    /// Leave multicast groups for a socket
    pub fn drop_mcast_membership(&self, groups: U32Bitmask) -> Result<(), io::Error> {
        self.socket.drop_mcast_membership(groups)
    }

    /// List joined groups for a socket
    pub fn list_mcast_membership(&self) -> Result<U32Bitmask, io::Error> {
        self.socket.list_mcast_membership()
    }

    fn get_genl_family<T>(
        &mut self,
        family_name: &str,
    ) -> Result<NlBuffer<NlTypeWrapper, Genlmsghdr<CtrlCmd, T>>, NlError>
    where
        T: NlAttrType + Debug,
    {
        let mut attrs = GenlBuffer::new();
        attrs.push(Nlattr::new(
            None,
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

    /// Convenience function for resolving a `&str` containing the multicast group name to a
    /// numeric netlink ID
    pub fn resolve_genl_family(&mut self, family_name: &str) -> Result<u16, NlError> {
        let nlhdrs = self.get_genl_family(family_name)?;
        for nlhdr in nlhdrs.into_iter() {
            let attrs = nlhdr
                .nl_payload
                .get_payload()
                .ok_or_else(|| NlError::new("No attributes were returned in this message."))?;
            let handle = attrs.get_attr_handle();
            if let Ok(u) = handle.get_attr_payload_as::<u16>(CtrlAttr::FamilyId) {
                return Ok(u);
            }
        }
        Err(NlError::new(format!(
            "Generic netlink family {} was not found",
            family_name
        )))
    }

    /// Convenience function for resolving a `&str` containing the multicast group name to a
    /// numeric netlink ID
    pub fn resolve_nl_mcast_group(
        &mut self,
        family_name: &str,
        mcast_name: &str,
    ) -> Result<u32, NlError> {
        let nlhdrs = self.get_genl_family(family_name)?;
        for nlhdr in nlhdrs {
            let attrs = nlhdr
                .nl_payload
                .get_payload()
                .ok_or_else(|| NlError::new("No attributes were returned in this message."))?;
            let mut handle = attrs.get_attr_handle();
            let mcast_groups = handle.get_nested_attributes::<Index>(CtrlAttr::McastGroups)?;
            if let Some(id) = mcast_groups
                .iter()
                .filter_map(|item| {
                    let nested_attrs = item.get_attr_handle::<CtrlAttrMcastGrp>().ok()?;
                    let string = nested_attrs
                        .get_attr_payload_as::<String>(CtrlAttrMcastGrp::Name)
                        .ok()?;
                    if string.as_str() == mcast_name {
                        nested_attrs
                            .get_attr_payload_as::<u32>(CtrlAttrMcastGrp::Id)
                            .ok()
                    } else {
                        None
                    }
                })
                .next()
            {
                return Ok(id);
            }
        }
        Err(NlError::new("Failed to resolve multicast group ID"))
    }

    /// Look up netlink family and multicast group name by ID
    pub fn lookup_id(&mut self, id: u32) -> Result<(String, String), NlError> {
        let attrs = GenlBuffer::new();
        let genlhdr = Genlmsghdr::<CtrlCmd, CtrlAttrMcastGrp>::new(CtrlCmd::Getfamily, 2, attrs);
        let nlhdr = Nlmsghdr::new(
            None,
            GenlId::Ctrl,
            NlmFFlags::new(&[NlmF::Ack, NlmF::Request, NlmF::Dump]),
            None,
            None,
            NlPayload::Payload(genlhdr),
        );

        self.send(nlhdr)?;
        for res_msg in self.iter::<Genlmsghdr<u8, CtrlAttr>>(false) {
            let msg = res_msg?;

            let mut attributes = msg
                .nl_payload
                .get_payload()
                .ok_or_else(|| NlError::new("No attributes returned in this message."))?
                .get_attr_handle();
            let name = attributes.get_attr_payload_as::<String>(CtrlAttr::FamilyName)?;
            let groups = match attributes.get_nested_attributes::<Index>(CtrlAttr::McastGroups) {
                Ok(grps) => grps,
                Err(_) => continue,
            };
            for group_by_index in groups.iter() {
                let attributes = group_by_index.get_attr_handle::<CtrlAttrMcastGrp>()?;
                if let Ok(mcid) = attributes.get_attr_payload_as::<u32>(CtrlAttrMcastGrp::Id) {
                    if mcid == id {
                        let mcast_name =
                            attributes.get_attr_payload_as::<String>(CtrlAttrMcastGrp::Name)?;
                        return Ok((name, mcast_name));
                    }
                }
            }
        }

        Err(NlError::new("ID does not correspond to a multicast group"))
    }

    /// Convenience function to send an `Nlmsghdr` struct
    pub fn send<T, P>(&mut self, msg: Nlmsghdr<T, P>) -> Result<(), NlError>
    where
        T: Nl + NlType + Debug,
        P: Nl + Debug,
    {
        #[cfg(feature = "logging")]
        log!("Message sent:\n{:#?}", msg);

        if msg.nl_flags.contains(&NlmF::Ack) {
            self.needs_ack = true;
        }

        let mut mem = SerBuffer::new(Some(msg.asize()));
        mem = msg.serialize(mem).map_err(NlError::new)?;
        self.socket.send(mem, 0)?;

        Ok(())
    }

    /// Convenience function to begin receiving a stream of `Nlmsghdr` structs
    pub fn recv<T, P>(&mut self, on_error: OnError) -> Result<Option<Nlmsghdr<T, P>>, NlError>
    where
        T: Nl + NlType + Debug,
        P: Nl + Debug,
    {
        if self.end == self.position {
            // Borrow buffer for writing.
            let mut_buffer = self.buffer.get_mut().expect("Caller borrows mutable self");

            // Read the buffer from the socket and fail if nothing
            // was read.
            let mem_read_res = self.socket.recv(mut_buffer, 0);
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

        let packet = match parse_next(
            &self
                .buffer
                .get_ref()
                .expect("Caller borrows mutable self")
                .as_ref()[..self.end],
            self.position,
            self.expects_ack,
        ) {
            Ok((po, pa)) => {
                self.position += po;
                pa
            }
            Err(e) => match on_error {
                OnError::Rewind => return Err(e),
                OnError::FastForward => {
                    let next_packet_pos = packet_length_u32(
                        self.buffer
                            .get_ref()
                            .expect("Caller borrows mutable self")
                            .as_ref(),
                        self.position,
                    );
                    self.position += next_packet_pos;
                    return Err(e);
                }
            },
        };

        #[cfg(feature = "logging")]
        log!("Message received: {:#?}", packet);

        Ok(Some(packet))
    }

    /// Parse all `Nlmsghdr` structs sent in one network packet
    /// and return them all in a list.
    ///
    /// Failure to parse any packet will cause the entire operation
    /// to fail. If an error is detected at the application level,
    /// this method will discard any non-error `Nlmsghdr` structs and only
    /// return the error. This method checks for ACKs. For a more granular
    /// approach, use either `NlSocket::recv_nl` or `NlSocket::iter`.
    pub fn recv_all<T, P>(&mut self) -> Result<NlBuffer<T, P>, NlError>
    where
        T: Nl + NlType + Debug,
        P: Nl + Debug,
    {
        if self.position == self.end {
            let mut_buffer = self.buffer.get_mut().expect("Caller borrows mutable self");
            let mem_read = self.socket.recv(mut_buffer, 0)?;
            if mem_read == 0 {
                return Err(NlError::new("No data could be read from the socket"));
            }
            self.end = mem_read;
        }

        let buffer = self.buffer.get_ref().expect("Caller borrows mutable self");
        let vec = NlBuffer::deserialize(DeBuffer::from(&buffer.as_ref()[0..self.end]))
            .map_err(NlError::new)?;

        #[cfg(feature = "logging")]
        log!("Messages received: {:#?}", vec);

        self.position = 0;
        self.end = 0;
        Ok(vec)
    }

    /// Return an iterator object
    ///
    /// The argument `iterate_indefinitely` is documented
    /// in more detail in [`NlMessageIter`]
    pub fn iter<P>(&mut self, iter_indefinitely: bool) -> NlMessageIter<NlTypeWrapper, P>
    where
        P: Nl + Debug,
    {
        let behavior = match (iter_indefinitely, self.needs_ack) {
            (true, _) => IterationBehavior::IterIndefinitely,
            (false, true) => IterationBehavior::EndMultiOnDoneAndAck,
            (_, _) => IterationBehavior::EndMultiOnDone,
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
            buffer: SockBuffer::new(),
            end: 0,
            position: 0,
            needs_ack: false,
            expects_ack: false,
        }
    }
}

#[cfg(all(feature = "async", not(no_std)))]
pub mod tokio {
    //! Tokio-specific features for neli
    //!
    //! This module contains a struct that wraps `NlSocket` for async IO.
    use super::*;

    use std::{
        cell::{RefCell, RefMut},
        marker::PhantomData,
        pin::Pin,
        task::{Context, Poll},
    };

    use ::tokio::{
        io::{AsyncRead, PollEvented},
        stream::Stream,
    };
    use mio::{self, Evented};

    fn poll_read_priv(
        mut socket: RefMut<PollEvented<super::NlSocket>>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *socket).poll_read(cx, buf)
    }

    /// Tokio-enabled Netlink socket struct
    pub struct NlSocket<T, P> {
        socket: RefCell<PollEvented<super::NlSocket>>,
        buffer: SockBuffer,
        position: usize,
        end: usize,
        type_: PhantomData<T>,
        payload: PhantomData<P>,
    }

    impl<'a, T, P> NlSocket<T, P>
    where
        T: NlType,
    {
        /// Setup NlSocket for use with tokio - set to nonblocking state and wrap in polling mechanism
        pub fn new<S>(s: S) -> io::Result<Self>
        where
            S: Into<super::NlSocket>,
        {
            let socket = s.into();
            if socket.is_blocking()? {
                socket.nonblock()?;
            }
            Ok(NlSocket {
                socket: RefCell::new(PollEvented::new(socket)?),
                buffer: SockBuffer::new(),
                position: 0,
                end: 0,
                type_: PhantomData,
                payload: PhantomData,
            })
        }

        /// Check if underlying received message buffer is empty
        pub fn empty(&self) -> bool {
            self.end == self.position
        }
    }

    impl io::Read for super::NlSocket {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.is_blocking()? {
                self.nonblock()?;
            }
            self.recv(buf, 0).map(|i| i as usize)
        }
    }

    impl io::Write for super::NlSocket {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.is_blocking()? {
                self.nonblock()?;
            }
            self.send(buf, 0)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<T, P> AsyncRead for NlSocket<T, P> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let mut_ref = self.as_mut();
            poll_read_priv(mut_ref.socket.borrow_mut(), cx, buf)
        }
    }

    impl<T, P> Stream for NlSocket<T, P>
    where
        T: NlType,
        P: Nl,
    {
        type Item = Result<Nlmsghdr<T, P>, NlError>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
            let optional_end = if self.empty() {
                let immut_ref = self.as_ref();
                let mut mem = immut_ref
                    .buffer
                    .get_mut()
                    .expect("Caller borrows mutable self");
                let bytes_read = match poll_read_priv(self.socket.borrow_mut(), cx, mem.as_mut()) {
                    Poll::Ready(Ok(0)) => return Poll::Ready(None),
                    Poll::Ready(Ok(i)) => i,
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(NlError::from(e)))),
                };
                Some(bytes_read)
            } else {
                None
            };

            if let Some(bytes_read) = optional_end {
                let mut mut_ref = self.as_mut();
                mut_ref.position = 0;
                mut_ref.end = bytes_read;
            }

            let (packet_res, packet_len) = {
                let immut_ref = self.as_ref();
                let buffer = &immut_ref
                    .buffer
                    .get_ref()
                    .expect("Caller borrows mutable self");
                (
                    parse_next(&buffer.as_ref()[..immut_ref.end], immut_ref.position, false),
                    packet_length_u32(buffer.as_ref(), immut_ref.position),
                )
            };

            let mut mut_ref = self.as_mut();
            mut_ref.position += packet_len;

            let packet = match packet_res {
                Ok((_, packet)) => packet,
                Err(e) => return Poll::Ready(Some(Err(e))),
            };

            Poll::Ready(Some(Ok(packet)))
        }
    }

    impl<T, P> Unpin for NlSocket<T, P> {}

    impl Evented for super::NlSocket {
        fn register(
            &self,
            poll: &mio::Poll,
            token: mio::Token,
            interest: mio::Ready,
            opts: mio::PollOpt,
        ) -> io::Result<()> {
            poll.register(
                &mio::unix::EventedFd(&self.as_raw_fd()),
                token,
                interest,
                opts,
            )
        }

        fn reregister(
            &self,
            poll: &mio::Poll,
            token: mio::Token,
            interest: mio::Ready,
            opts: mio::PollOpt,
        ) -> io::Result<()> {
            poll.reregister(
                &mio::unix::EventedFd(&self.as_raw_fd()),
                token,
                interest,
                opts,
            )
        }

        fn deregister(&self, poll: &mio::Poll) -> io::Result<()> {
            poll.deregister(&mio::unix::EventedFd(&self.as_raw_fd()))
        }
    }

    impl Evented for &mut super::NlSocket {
        fn register(
            &self,
            poll: &mio::Poll,
            token: mio::Token,
            interest: mio::Ready,
            opts: mio::PollOpt,
        ) -> io::Result<()> {
            <super::NlSocket as Evented>::register(self, poll, token, interest, opts)
        }

        fn reregister(
            &self,
            poll: &mio::Poll,
            token: mio::Token,
            interest: mio::Ready,
            opts: mio::PollOpt,
        ) -> io::Result<()> {
            <super::NlSocket as Evented>::reregister(self, poll, token, interest, opts)
        }

        fn deregister(&self, poll: &mio::Poll) -> io::Result<()> {
            <super::NlSocket as Evented>::deregister(self, poll)
        }
    }

    #[cfg(test)]
    mod test {
        use std::io::Read;

        use ::tokio::runtime::Runtime;
        use futures_util::{future::ready, stream::StreamExt};

        use super::*;
        use crate::{
            nl::NlEmpty,
            socket::{self, tokio::NlSocket},
        };

        #[test]
        fn test_socket_nonblock() {
            let mut s =
                socket::NlSocket::connect(NlFamily::Generic, None, U32Bitmask::empty()).unwrap();
            s.nonblock().unwrap();
            assert_eq!(s.is_blocking().unwrap(), false);
            let buf = &mut [0; 4];
            match s.read(buf) {
                Err(e) => {
                    if e.kind() != io::ErrorKind::WouldBlock {
                        panic!("Error: {}", e);
                    }
                }
                Ok(_) => {
                    panic!("Should not return data");
                }
            }
        }

        #[test]
        fn test_socket_send() {
            let s =
                socket::NlSocket::connect(NlFamily::Generic, None, U32Bitmask::empty()).unwrap();
            let mut runtime = Runtime::new().unwrap();
            runtime
                .block_on(async {
                    let async_s = NlSocket::<NlTypeWrapper, NlEmpty>::new(s).unwrap();
                    ::tokio::task::spawn(async {
                        async_s
                            .take(0)
                            .for_each(|res| {
                                println!("{:?}", res);
                                ready(())
                            })
                            .await;
                    })
                    .await
                })
                .unwrap();
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::consts::Nlmsg;

    #[test]
    fn multi_msg_iter() {
        let mut attrs = GenlBuffer::new();
        attrs.push(Nlattr::new(None, false, false, CtrlAttr::FamilyId, 5u32).unwrap());
        attrs
            .push(Nlattr::new(None, false, false, CtrlAttr::FamilyName, "my_family_name").unwrap());
        let nl1 = Nlmsghdr::new(
            None,
            NlTypeWrapper::Nlmsg(Nlmsg::Noop),
            NlmFFlags::new(&[NlmF::Multi]),
            None,
            None,
            NlPayload::Payload(Genlmsghdr::new(CtrlCmd::Unspec, 2, attrs)),
        );

        let mut attrs = GenlBuffer::new();
        attrs.push(Nlattr::new(None, false, false, CtrlAttr::FamilyId, 6u32).unwrap());
        attrs.push(
            Nlattr::new(
                None,
                false,
                false,
                CtrlAttr::FamilyName,
                "my_other_family_name",
            )
            .unwrap(),
        );
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
        let mut bytes = SerBuffer::new(Some(v.asize()));
        bytes = v.serialize(bytes).unwrap();

        let bytes_len = bytes.len();
        let mut s = NlSocketHandle {
            socket: unsafe { NlSocket::from_raw_fd(-1) },
            buffer: SockBuffer::from(bytes.as_ref()),
            expects_ack: false,
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
}
