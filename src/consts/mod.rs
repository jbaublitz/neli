//! # High level notes
//!
//! The contents of this module are generated mostly by macros, which
//! implement the appropriate traits necessary to both be
//! serialized/deserialized and also provide an additional level of
//! type safety when constructing netlink packets. Some of the traits
//! generated in this module allow netlink structures to implement
//! trait bounds assuring that only compatible constant-based enums
//! are allowed to be passed in as parameters.  The macros are
//! exported; you can use them too! See [`impl_trait`][crate::impl_trait]
//! and [`impl_flags`][crate::impl_flags] for more details.
//!
//! Note that most of these constants come from the Linux kernel
//! headers, which can be found in `/usr/include/linux` on many
//! distros. You can also see `man 3 netlink`, `man 7 netlink`,
//! and `man 7 rtnetlink` for more information.
//!
//! # Design decisions
//!
//! * Macros are exported so that these conventions are extensible and
//!   usable for data types implemented by the user in the case of new
//!   netlink families (which is supported by the protocol). In this
//!   case, there is no way in which I can support every custom netlink
//!   family but my aim is to make this library as flexible as possible
//!   so that it is painless to hook your custom netlink data type into
//!   the existing library support.
//! * Enums are used so that:
//!   * Values can be checked based on a finite number of inputs as
//!     opposed to the range of whatever integer data type C defines as
//!     the struct member type. This makes it easier to catch garbage
//!     responses and corruption when an invalid netlink message is sent
//!     to the kernel.
//!   * Only the enum or an enum implementing a marker trait in the
//!     case of type parameters can be used in the appropriate places
//!     when constructing netlink messages. This takes guess work out of
//!     which constants can be used where. Netlink documentation is not
//!     always complete and sometimes takes a bit of trial and error
//!     sending messages to the kernel to figure out if you are using
//!     the correct constants. This setup should let you know at compile
//!     time if you are doing something you should not be doing.
//! * `UnrecognizedVariant` is included in each enum because
//!   completeness cannot be guaranteed for every constant for every
//!   protocol. This allows you to inspect the integer value returned
//!   and if you are sure that it is correct, you can use it. If it is
//!   a garbage value, this can also be useful for error reporting.

#[macro_use]
mod macros;

/// Constants related to netlink connector interface
pub mod connector;
/// Constants related to generic netlink
pub mod genl;
/// Constants related to mac80211_hwsim virtual WiFi driver
pub mod mac80211_hwsim;
/// Constants related to netfilter netlink integration
pub mod netfilter;
/// Constants related to generic netlink top level headers
pub mod nl;
/// Constants related to rtnetlink
pub mod rtnl;
/// Constants related to netlink socket operations
pub mod socket;

/// Reimplementation of alignto macro in C
pub fn alignto(len: usize) -> usize {
    (len + libc::NLA_ALIGNTO as usize - 1) & !(libc::NLA_ALIGNTO as usize - 1)
}

/// Max supported message length for netlink messages supported by
/// the kernel.
pub const MAX_NL_LENGTH: usize = 32768;

#[cfg(test)]
mod test {
    use super::genl::*;

    #[test]
    fn test_generated_enum_into_from() {
        let unspec: u8 = CtrlCmd::Unspec.into();
        assert_eq!(unspec, libc::CTRL_CMD_UNSPEC as u8);

        let unspec_variant = CtrlCmd::from(libc::CTRL_CMD_UNSPEC as u8);
        assert_eq!(unspec_variant, CtrlCmd::Unspec);
    }
}
