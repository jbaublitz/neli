use std::{
    io,
    mem::{size_of, zeroed, MaybeUninit},
    os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
};

use libc::{c_int, c_void, sockaddr, sockaddr_nl};

#[cfg(feature = "async")]
use crate::socket::asynchronous;
#[cfg(feature = "sync")]
use crate::socket::synchronous;
use crate::{
    consts::socket::*,
    utils::{Groups, NetlinkBitArray},
};

/// Low level access to a netlink socket.
pub struct NlSocket {
    fd: c_int,
}

impl NlSocket {
    /// Wrapper around `socket()` syscall filling in the
    /// netlink-specific information.
    pub fn new(proto: NlFamily) -> Result<Self, io::Error> {
        let fd = match unsafe {
            libc::socket(
                AddrFamily::Netlink.into(),
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                proto.into(),
            )
        } {
            i if i >= 0 => Ok(i),
            _ => Err(io::Error::last_os_error()),
        }?;
        Ok(NlSocket { fd })
    }

    /// Equivalent of `socket` and `bind` calls.
    pub fn connect(proto: NlFamily, pid: Option<u32>, groups: Groups) -> Result<Self, io::Error> {
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
    pub fn bind(&self, pid: Option<u32>, groups: Groups) -> Result<(), io::Error> {
        let mut nladdr = unsafe { zeroed::<libc::sockaddr_nl>() };
        nladdr.nl_family = c_int::from(AddrFamily::Netlink) as u16;
        nladdr.nl_pid = pid.unwrap_or(0);
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
        self.add_mcast_membership(groups)?;
        Ok(())
    }

    /// Join multicast groups for a socket.
    pub fn add_mcast_membership(&self, groups: Groups) -> Result<(), io::Error> {
        for group in groups.as_groups() {
            match unsafe {
                libc::setsockopt(
                    self.fd,
                    libc::SOL_NETLINK,
                    libc::NETLINK_ADD_MEMBERSHIP,
                    &group as *const _ as *const libc::c_void,
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
    pub fn drop_mcast_membership(&self, groups: Groups) -> Result<(), io::Error> {
        for group in groups.as_groups() {
            match unsafe {
                libc::setsockopt(
                    self.fd,
                    libc::SOL_NETLINK,
                    libc::NETLINK_DROP_MEMBERSHIP,
                    &group as *const _ as *const libc::c_void,
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
    /// [`Nlmsghdr`][crate::nl::Nlmsghdr]
    pub fn send<B>(&self, buf: B, flags: Msg) -> Result<libc::size_t, io::Error>
    where
        B: AsRef<[u8]>,
    {
        match unsafe {
            libc::send(
                self.fd,
                buf.as_ref() as *const _ as *const c_void,
                buf.as_ref().len(),
                flags.bits() as i32,
            )
        } {
            i if i >= 0 => Ok(i as libc::size_t),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Receive message encoded as byte slice from the netlink socket.
    pub fn recv<B>(&self, mut buf: B, flags: Msg) -> Result<(libc::size_t, Groups), io::Error>
    where
        B: AsMut<[u8]>,
    {
        let mut addr = unsafe { std::mem::zeroed::<sockaddr_nl>() };
        let mut size: u32 = size_of::<sockaddr_nl>().try_into().unwrap_or(0);
        match unsafe {
            libc::recvfrom(
                self.fd,
                buf.as_mut() as *mut _ as *mut c_void,
                buf.as_mut().len(),
                flags.bits() as i32,
                &mut addr as *mut _ as *mut sockaddr,
                &mut size,
            )
        } {
            i if i >= 0 => Ok((i as libc::size_t, Groups::new_bitmask(addr.nl_groups))),
            i if i == -libc::EWOULDBLOCK as isize => {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }
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

    /// If [`true`] is passed in, enable extended ACKs for this socket. If [`false`]
    /// is passed in, disable extended ACKs for this socket.
    pub fn enable_ext_ack(&self, enable: bool) -> Result<(), io::Error> {
        match unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_NETLINK,
                libc::NETLINK_EXT_ACK,
                &c_int::from(enable) as *const _ as *const libc::c_void,
                size_of::<i32>() as libc::socklen_t,
            )
        } {
            0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Return [`true`] if an extended ACK is enabled for this socket.
    pub fn get_ext_ack_enabled(&self) -> Result<bool, io::Error> {
        let mut sock_len = size_of::<libc::c_int>() as libc::socklen_t;
        let mut sock_val: MaybeUninit<libc::c_int> = MaybeUninit::uninit();
        match unsafe {
            libc::getsockopt(
                self.fd,
                libc::SOL_NETLINK,
                libc::NETLINK_EXT_ACK,
                &mut sock_val as *mut _ as *mut libc::c_void,
                &mut sock_len as *mut _ as *mut libc::socklen_t,
            )
        } {
            0 => Ok(unsafe { sock_val.assume_init() } != 0),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// If [`true`] is passed in, enable strict checking for this socket. If [`false`]
    /// is passed in, disable strict checking for for this socket.
    /// Only supported by `NlFamily::Route` sockets.
    /// Requires Linux >= 4.20.
    pub fn enable_strict_checking(&self, enable: bool) -> Result<(), io::Error> {
        match unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_NETLINK,
                libc::NETLINK_GET_STRICT_CHK,
                &libc::c_int::from(enable) as *const _ as *const libc::c_void,
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        } {
            0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Return [`true`] if strict checking is enabled for this socket.
    /// Only supported by `NlFamily::Route` sockets.
    /// Requires Linux >= 4.20.
    pub fn get_strict_checking_enabled(&self) -> Result<bool, io::Error> {
        let mut sock_len = size_of::<libc::c_int>() as libc::socklen_t;
        let mut sock_val: MaybeUninit<libc::c_int> = MaybeUninit::uninit();
        match unsafe {
            libc::getsockopt(
                self.fd,
                libc::SOL_NETLINK,
                libc::NETLINK_GET_STRICT_CHK,
                &mut sock_val as *mut _ as *mut libc::c_void,
                &mut sock_len as *mut _ as *mut libc::socklen_t,
            )
        } {
            0 => Ok(unsafe { sock_val.assume_init() } != 0),
            _ => Err(io::Error::last_os_error()),
        }
    }
}

#[cfg(feature = "sync")]
impl From<synchronous::NlSocketHandle> for NlSocket {
    fn from(s: synchronous::NlSocketHandle) -> Self {
        s.socket
    }
}

#[cfg(feature = "async")]
impl From<asynchronous::NlSocketHandle> for NlSocket {
    fn from(s: asynchronous::NlSocketHandle) -> Self {
        s.socket.into_inner()
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

#[cfg(test)]
mod test {
    use super::*;

    use crate::test::setup;

    #[test]
    fn real_test_pid() {
        setup();

        let s = NlSocket::connect(NlFamily::Generic, Some(5555), Groups::empty()).unwrap();
        assert_eq!(s.pid().unwrap(), 5555);
    }

    #[test]
    fn real_ext_ack() {
        setup();

        let s = NlSocket::connect(NlFamily::Generic, None, Groups::empty()).unwrap();
        assert!(!s.get_ext_ack_enabled().unwrap());
        s.enable_ext_ack(true).unwrap();
        assert!(s.get_ext_ack_enabled().unwrap());
    }

    #[test]
    fn real_strict_checking() {
        setup();

        let s = NlSocket::connect(NlFamily::Route, None, Groups::empty()).unwrap();
        assert!(!s.get_strict_checking_enabled().unwrap());
        s.enable_strict_checking(true).unwrap();
        assert!(s.get_strict_checking_enabled().unwrap());
    }
}
