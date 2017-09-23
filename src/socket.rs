use std::io;
use std::mem::{zeroed,size_of};

use libc::{self,c_int,c_void};

use ffi::NlFamily;

pub struct NlSocket {
    fd: c_int,
}

impl NlSocket {
    pub fn new(proto: NlFamily) -> Result<Self, io::Error> {
        let proto_u32: u32 = proto.into();
        let fd = match unsafe {
            libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, proto_u32 as libc::c_int)
        } {
            i if i >= 0 => Ok(i),
            _ => Err(io::Error::last_os_error()),
        };
        Ok(NlSocket { fd: try!(fd) })
    }

    pub fn bind(&mut self, groups: u32) -> Result<(), io::Error> {
        let mut nladdr = unsafe { zeroed::<libc::sockaddr_nl>() };
        nladdr.nl_family = libc::AF_NETLINK as u16;
        nladdr.nl_pid = 0;
        nladdr.nl_groups = groups;
        match unsafe {
            libc::bind(self.fd, &nladdr as *const _ as *const libc::sockaddr,
                       size_of::<libc::sockaddr_nl>() as u32)
        } {
            i if i >= 0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    pub fn send(&mut self, buf: &[u8], flags: i32) -> Result<isize, io::Error> {
        match unsafe {
            libc::send(self.fd, buf as *const _ as *const c_void, buf.len(), flags)
        } {
            i if i >= 0 => Ok(i),
            _ => Err(io::Error::last_os_error()),
        }
    }

    pub fn recv(&mut self, len: usize, flags: i32) -> Result<Vec<u8>, io::Error> {
        let mut v = Vec::with_capacity(len); 
        match unsafe {
            libc::recv(self.fd, v.as_mut_slice() as *mut _ as *mut c_void, v.len(), flags)
        } {
            i if i >= 0 => Ok(v),
            _ => Err(io::Error::last_os_error()),
        }
    }

    // Higher level API
    pub fn connect(proto: NlFamily, groups: u32) -> Result<Self, io::Error> {
        let mut s = try!(NlSocket::new(proto));
        try!(s.bind(groups));
        Ok(s)
    }
}

impl Drop for NlSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd); }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_socket_creation() {
        match NlSocket::connect(NlFamily::NlGeneric, 0) {
            Err(_) => panic!(),
            _ => (),
        }
    }
}
