# Changelog

## 0.7.1
### Features
* Support `FromBytes` and `ToBytes` for statically sized arrays
* Allow setting recv buffer size in socket
* Support for the connector protocol

### Maintenance
* Clippy fixes
* Update to Rust 2024 edition

## 0.7.0
### Breaking changes
* `FromBytes` and `FromBytesWithInput` have had the lifetime parameter removed. This
removes the ability to borrow data from the buffer written to by the `recv()` syscall.
This is intentional as it provides more ergonomic support for `NlRouter` to send
messages across threads. A new trait, `FromBytesWithInputBorrowed`, has been added to
support the use case of borrowing payloads from attributes as `&str` or `&[u8]`.
* The `async` feature API has been completely redesigned to more closely resemble
it's corresponding synchronous API.
* All `new()` methods and public fields on data structures used to construct packets
have been replaced by the builder pattern.
* The IO error variant is now the full IO error wrapped in an `Arc`.

### New Cargo features
* `sync` has been added as a Cargo feature. If a user is only interested in asynchronous
functionality, `sync` can be disabled to disable the higher level synchronous API
and reduce the number of required dependencies. 

### Features
* Extended ACK support. Sockets now support parsing and enabling entended ACKs for more
information in error cases.
* New router infrastructure allowing ACK handling, seq management, and PID validation
for requests sent in parallel.
* Builder pattern defined for all data structures used to construct netlink packets.

## Bug fixes
* Fixed a mismatch between `libc::socklen_t` and `usize` in the list memberships call.
This was causing failures on s390x in the tests.

### Dependency version updates
* syn
* libc

### Migration guide
* If you were previously using `new()` methods defined on structs representing packet 
data, all packet data structures have been migrated over to a builder pattern.
* Flags in packets have been migrated from a custom data structure to
[`bitflags`](https://docs.rs/bitflags). For example `&[Nlm::Request, Nlm::Ack]` is now `NlmF::REQUEST | NlmF::ACK`.
* Because of previous errors around multicast groups, there is a new data structure
to handle group management that allows either converting from group numbers or a
bitmask. If you previously passed in 0 for groups, you will now use `Groups::empty()`.
* If you were previously using convenience methods like `NlSocketHandle::iter()` or
`NlSocketHandle::resolve_genl_family`, this functionality has been migrated to the
new `NlRouter` functionality. `NlSocketHandle` has been repurposed for a slightly
lower level API providing iteration over all messages in a single `recv()` buffer.
`NlRouter` provides a safer, parallelization-capable version of the functionality
previously provided by `NlSocketHandle`. See the documentation in the `neli::router`
module for a more detailed explanation of the problem this was meant to solve.
* If you were previously using `Attr::get_payload_as_with_len()` with a `&[u8]` or
`&str` type, you should change this to `Attr::get_payload_as_with_len_borrowed()`.
* `NlError` has been removed and replaced by `SocketError` for `NlSocketHandle`
operations and `RouterError` for `NlRouter` operations. The appropriate conversions
between errors using `From` should be implemented.
* `Genlmsghdr::get_attr_handle()` has been removed in favor of
`genl.attrs().get_attr_handle()`.

## 0.6.4
### Bug fixes
* Fixed bug in error intepretation for Nlmsgerr.

### Features
* Add `FromBytes`/`ToBytes` implementations for `u128`.

Thanks to the upstream contributors who provided the code for this release!

## 0.6.3
### Bug fixes
* Fixed memory bug in `NlSocket::drop_mcast_membership()` unsafe code found using
valgrind

### Clean up
* CI and clippy maintenance

## 0.6.2
### Enhancements
* Added support for option user header in netlink protocol for generic netlink 
* Added method to get socket PID
* Added support for converting to a `FlagBuffer` from a bitmask

### Bug fixes
* Fixed up `examples` directory to compile successfully with `cargo build --examples`

### Clean up
* Removed unnecessary features and dependencies
(PR from [MaxVerevkin](https://github.com/MaxVerevkin))
* CI and clippy maintenance

## 0.6.1
### Bug fixes
* Bug fix for `RtBuffer` and `GenlBuffer` size calculation
* Bug fix for `Rtattr` size calculation
* Bug fixes in tokio usage
* Bug fix where padding at the end of an empty netlink packet caused errors

### Improvements
* Better debug logging

See all pull requests and issues that went into this release [here!](https://github.com/jbaublitz/neli/milestone/12?closed=1)

## 0.6.0
### Bug fixes
* Fixed problem where `Tcmsg` could not be created due to padding.
* Fixed problem with listing multicast groups.

### Additions
* Addition of `neli-proc-macros` crate to handle most of trait
generation.
* More testing!

### Breaking changes
* Changed the core traits from `Nl` to a number of different, more
granular traits.
* Consolidated `iter()` and `iter2()`.
* Major changes to async module.
* Changes to how bit flag sets are handled.

## 0.5.3
### Bug fixes
* Bug fix for `Ifinfomsg.ifi_change` being serialized twice.
* Bug fix for `Ndmsg` where it could not be constructed due to
  private padding fields.
* Bug fix for `Ifinfomsg.ifi_change`. This should be of type
 `IffFlags`, not `Iff`.
* Fixed assumption in `NlSocketHandle::recv()` where this method
  never expected an ACK to be returned with no data.
  * The behavior of `NlSocketHandle::recv()` has changed slightly.
    It will now return ACKs and only returns `None` when nonblocking.
    Use `NlSocketHandle::iter()` for handling of streams of messages.
* Fixed bug for deserialization of errors returned at the
  application level.
* Fixed bug in subscription to multicast groups.
  * The API has been changed and `U32Bitmask` has been replaced by
    `NetlinkBitArray`.

### Additions
* More constants in `Arphrd`.
* More constants in `Ifla`.
* Addition of `NlSocketHandle::iter2()` that does not restrict
  users to the `NlWrapperType` type for packet parsing.
* Addition of convenience methods on `RtBuffer` and `GenlBuffer`
  types to make parsing nested attributes easier.

### Dependency updates
* Update to tokio 1.0.

## 0.5.2
### Bug fixes
* Fixed bug in `Ifaddrmsg` serialization and deserialization.
  Thanks, [`@joshtriplett`](https://github.com/joshtriplett)!

## 0.5.1
### Bug fixes
* Fixed bug in ACK handling.
  * This change makes `NlSocketHandle` exclusively responsible
    for handling ACKs.

## 0.5.0
### Breaking changes
* Change from `buffering` structs for serialization to regular slices
  to allow buffer size tracking for each layer of serialization
  and deserialization and easy slicing into smaller, sized pieces.
* Change `stream` feature to `async` for clarity with higher level
  API.
* Remove `seq` and `pid` tracking. This will eventually be added to
  higher level APIs.
* Make `NlSocket::send`/`::recv` take an immutable reference due to
  the case made for message vs. stream based sockets.
* Remove universal exports of constants from the `consts` module.
* Update to tokio 0.3.
* Split lower level and higher level synchronous netlink socket calls
  across two structs, `NlSocket` and `NlSocketHandle`.
* Factor out parsing code so that it can be used across multiple
  socket types.
* Add nested netlink attribute parsing for routing netlink attributes. 
* Changes to the `Nlmsg` struct to support handling application
  errors returned by the kernel. Previously, there was no easy way
  to handle application errors returned inside of an `Nlmsg` packet.
* Added the ability to define the visibility for constants defined by
  the `consts` macros.

### Additions
* Add genetlink ID to family name/multicast group name lookup.
* Add `Index` type for nested attributes returned as a numbered list.
* `NlSocket` functions to leave/list multicast groups.
* Macro infrastructure for generating `serialize` and `deserialize`
  methods safely.
* `attr` module for shared attribute code.
* Debug logging enabled through the `logging` feature.

### Deprecations
* `Nlattr.get_nested_attributes()` in favor of `.get_attr_handle()`
* `NlSocket.set_mcast_groups()` in favor of `.add_multicast_membership()`

### Bug fixes
* Bug fixes for rtnetlink

### Documentation
* Updates to the documentation.
* More examples.
* Links to the referenced data structures.

## 0.5.0-rc1
### Additions
* Feature flagged NFLOG support, in the `netfilter` module.

### Resolved issues
* Resolved issue relating to allowing documentation annotations in
  macros for enum variants representing netlink constants.

## 0.4.3
### Breaking changes
* Change `Nlattr.add_nested_attribute()` to take a reference

### Additions
* Support `RTM_*` constants in `consts.rs`
* Fix length calculation errors
* Add methods to Nl trait with default implementations - does not break API
* Additional tests for padding
* Add design decision documentation for new padding handling

### Deprecations
* Deprecate `.size()` usage for `Vec<Nlattr>` - use `.asize()` instead

### Structure changes
* `consts.rs` is now `consts/` with a corresponding submodule for each category of constant -
not a breaking change
* Start enforcing rustfmt in CI and use cargo fmt to switch over to new formatting

### Fixes
* Merge PR fixing rtnetlink support

## 0.4.2
### Dependencies
* Update buffering to 0.3.4 minimum to force stable channel support for neli

## 0.4.1
### Breaking changes
* Revert to builder pattern for creating/parsing generic netlink messages with attributes
  * Particular notable changes for nested attribute handling

## 0.4.0
### Breaking changes
* Rework API in a number of places:
  * Tokio support for sockets
  * Many socket functions
  * Generic netlink

### Additions
* Support for rtnetlink
* Iterative message parsing from `NlSocket`

### Bug fixes
* Support parsing multiple netlink messages returned in the same socket read buffer
* Missing documentation added
* Fix alignment bugs when serializing netlink attributes

## 0.3.1
### Breaking changes
* Migration to buffering crate for buffer operations - _this does change the API_

# NOTE:
For record keeping it should be noted that semantic versioning was misused here. 0.3.0-r1 and
0.3.0-r2 should have been 0.3.1 and 0.3.2 respectively.

## 0.3.0-r2
### Bug fixes
* Fix documentation bug

## 0.3.0-r1
### Bug fixes
* After looking at tokio's `File` implementation, the file descriptor should block for
the `Stream` implementation

## 0.3.0
### Breaking changes
* Type signature of `bind` and `connect` calls' `groups` parameter was changed to be a `Vec<u32>`
which will allow specifying a list of IDs and the group bitmask will be calculated for the user.
* `poll` implementation of for `NlSocket` for `tokio::prelude::Stream` trait will now return
`io::ErrorKind::InvalidData` if the socket file descriptor is not set to non-blocking
before polling. This is intentional as Tokio docs rely on polls being non-blocking and my
implementation requires a read that either returns an `io::ErrorKind::WouldBlock` value or
the desired data.
* There is now an `nlattr` module to group together all of the netlink attribute code.

### Additions
* A function `block` was added to allow reversing `nonblock` function on `NlSocket`.
* `is_blocking` was added and returns a `bool` indicating whether reads will block on this socket.

### Deprecations
* `get_payload_as` was deprecated in favor of `get_payload_with`.

### Removed
None

## Versions prior to 0.3.0 are not included in the CHANGELOG
