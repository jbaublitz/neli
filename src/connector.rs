//! Connector module for Linux Netlink connector messages.
//!
//! This module provides support for the Linux Netlink connector subsystem,
//! which creates a communication channel between userspace programs and the kernel.
//! It allows applications to receive notifications about various kernel events.
//!
//! This module currently provides full support for the Linux proc connector protocol,
//! enabling the reception and handling of process lifecycle events such as creation,
//! termination, exec, UID/GID/sid changes, tracing, name changes, and core dumps.
//!
//! ## Supported protocols
//! At this time, only the proc connector (`PROC_CN`) protocol is fully implemented.
//!
//! ## Extensibility
//! The implementation can be extended in two ways:
//! 1. By defining additional types and logic in your own crate and using them with this module.
//! 2. By using a `Vec<u8>` as a payload and manually parsing protocol messages to suit other connector protocols.
//!
//! This design allows both high-level ergonomic handling of proc events and low-level manual parsing for custom needs.

use std::{io::Cursor, io::Read};

use derive_builder::{Builder, UninitializedFieldError};
use getset::Getters;
use log::trace;

use crate::{
    self as neli,
    consts::connector::{CnMsgIdx, CnMsgVal, ProcEventType},
    err::{DeError, MsgError, SerError},
    FromBytes, FromBytesWithInput, Header, Size, ToBytes,
};

/// Netlink connector message header and payload.
#[derive(
    Builder, Getters, Clone, Debug, PartialEq, Eq, Size, ToBytes, FromBytesWithInput, Header,
)]
#[neli(from_bytes_bound = "P: Size + FromBytesWithInput<Input = usize>")]
#[builder(pattern = "owned")]
pub struct CnMsg<P: Size> {
    /// Index of the connector (idx)
    #[getset(get = "pub")]
    idx: CnMsgIdx,
    /// Value (val)
    #[getset(get = "pub")]
    val: CnMsgVal,
    /// Sequence number
    #[builder(default)]
    #[getset(get = "pub")]
    seq: u32,
    /// Acknowledgement number
    #[builder(default)]
    #[getset(get = "pub")]
    ack: u32,
    /// Length of the payload
    #[builder(
        setter(skip),
        default = "self.payload.as_ref().ok_or_else(|| UninitializedFieldError::new(\"payload\"))?.unpadded_size() as _"
    )]
    #[getset(get = "pub")]
    len: u16,
    /// Flags
    #[builder(default)]
    #[getset(get = "pub")]
    flags: u16,
    /// Payload of the netlink message
    ///
    /// You can either use predefined types like `ProcCnMcastOp` or `ProcEventHeader`,
    /// a custom type defined by you or `Vec<u8>` for raw payload.
    #[neli(size = "len as usize")]
    #[neli(input = "input - Self::header_size()")]
    #[getset(get = "pub")]
    pub(crate) payload: P,
}

// -- proc connector structs --

/// Header for process event messages.
#[derive(Debug, Size)]
pub struct ProcEventHeader {
    /// The CPU on which the event occurred.
    pub cpu: u32,
    /// Nanosecond timestamp of the event.
    pub timestamp_ns: u64,
    /// The process event data.
    pub event: ProcEvent,
}

/// Ergonomic enum for process event data.
#[derive(Debug, Size, Copy, Clone)]
pub enum ProcEvent {
    /// Acknowledgement event, typically for PROC_EVENT_NONE.
    Ack {
        /// Error code (0 for success).
        err: u32,
    },
    /// Fork event, triggered when a process forks.
    Fork {
        /// Parent process PID.
        parent_pid: i32,
        /// Parent process TGID (thread group ID).
        parent_tgid: i32,
        /// Child process PID.
        child_pid: i32,
        /// Child process TGID.
        child_tgid: i32,
    },
    /// Exec event, triggered when a process calls exec().
    Exec {
        /// Process PID.
        process_pid: i32,
        /// Process TGID.
        process_tgid: i32,
    },
    /// UID change event, triggered when a process changes its UID.
    Uid {
        /// Process PID.
        process_pid: i32,
        /// Process TGID.
        process_tgid: i32,
        /// Real UID.
        ruid: u32,
        /// Effective UID.
        euid: u32,
    },
    /// GID change event, triggered when a process changes its GID.
    Gid {
        /// Process PID.
        process_pid: i32,
        /// Process TGID.
        process_tgid: i32,
        /// Real GID.
        rgid: u32,
        /// Effective GID.
        egid: u32,
    },
    /// SID change event, triggered when a process changes its session ID.
    Sid {
        /// Process PID.
        process_pid: i32,
        /// Process TGID.
        process_tgid: i32,
    },
    /// Ptrace event, triggered when a process is traced.
    Ptrace {
        /// Process PID.
        process_pid: i32,
        /// Process TGID.
        process_tgid: i32,
        /// Tracer process PID.
        tracer_pid: i32,
        /// Tracer process TGID.
        tracer_tgid: i32,
    },
    /// Comm event, triggered when a process changes its command name.
    Comm {
        /// Process PID.
        process_pid: i32,
        /// Process TGID.
        process_tgid: i32,
        /// Command name (null-terminated, max 16 bytes).
        comm: [u8; 16],
    },
    /// Coredump event, triggered when a process dumps core.
    Coredump {
        /// Process PID.
        process_pid: i32,
        /// Process TGID.
        process_tgid: i32,
        /// Parent process PID.
        parent_pid: i32,
        /// Parent process TGID.
        parent_tgid: i32,
    },
    /// Exit event, triggered when a process exits.
    Exit {
        /// Process PID.
        process_pid: i32,
        /// Process TGID.
        process_tgid: i32,
        /// Exit code.
        exit_code: u32,
        /// Exit signal.
        exit_signal: u32,
        /// Parent process PID.
        parent_pid: i32,
        /// Parent process TGID.
        parent_tgid: i32,
    },
}

impl From<&ProcEvent> for ProcEventType {
    fn from(ev: &ProcEvent) -> Self {
        match ev {
            ProcEvent::Ack { .. } => ProcEventType::None,
            ProcEvent::Fork { .. } => ProcEventType::Fork,
            ProcEvent::Exec { .. } => ProcEventType::Exec,
            ProcEvent::Uid { .. } => ProcEventType::Uid,
            ProcEvent::Gid { .. } => ProcEventType::Gid,
            ProcEvent::Sid { .. } => ProcEventType::Sid,
            ProcEvent::Ptrace { .. } => ProcEventType::Ptrace,
            ProcEvent::Comm { .. } => ProcEventType::Comm,
            ProcEvent::Coredump { .. } => ProcEventType::Coredump,
            ProcEvent::Exit { exit_code, .. } => {
                if *exit_code == 0 {
                    ProcEventType::Exit
                } else {
                    ProcEventType::NonzeroExit
                }
            }
        }
    }
}

impl ToBytes for ProcEventHeader {
    fn to_bytes(&self, buffer: &mut Cursor<Vec<u8>>) -> Result<(), SerError> {
        ProcEventType::from(&self.event).to_bytes(buffer)?;
        self.cpu.to_bytes(buffer)?;
        self.timestamp_ns.to_bytes(buffer)?;

        match self.event {
            ProcEvent::Ack { err } => {
                err.to_bytes(buffer)?;
            }
            ProcEvent::Fork {
                parent_pid,
                parent_tgid,
                child_pid,
                child_tgid,
            } => {
                parent_pid.to_bytes(buffer)?;
                parent_tgid.to_bytes(buffer)?;
                child_pid.to_bytes(buffer)?;
                child_tgid.to_bytes(buffer)?;
            }
            ProcEvent::Exec {
                process_pid,
                process_tgid,
            } => {
                process_pid.to_bytes(buffer)?;
                process_tgid.to_bytes(buffer)?;
            }
            ProcEvent::Uid {
                process_pid,
                process_tgid,
                ruid,
                euid,
            } => {
                process_pid.to_bytes(buffer)?;
                process_tgid.to_bytes(buffer)?;
                ruid.to_bytes(buffer)?;
                euid.to_bytes(buffer)?;
            }
            ProcEvent::Gid {
                process_pid,
                process_tgid,
                rgid,
                egid,
            } => {
                process_pid.to_bytes(buffer)?;
                process_tgid.to_bytes(buffer)?;
                rgid.to_bytes(buffer)?;
                egid.to_bytes(buffer)?;
            }
            ProcEvent::Sid {
                process_pid,
                process_tgid,
            } => {
                process_pid.to_bytes(buffer)?;
                process_tgid.to_bytes(buffer)?;
            }
            ProcEvent::Ptrace {
                process_pid,
                process_tgid,
                tracer_pid,
                tracer_tgid,
            } => {
                process_pid.to_bytes(buffer)?;
                process_tgid.to_bytes(buffer)?;
                tracer_pid.to_bytes(buffer)?;
                tracer_tgid.to_bytes(buffer)?;
            }
            ProcEvent::Comm {
                process_pid,
                process_tgid,
                comm,
            } => {
                process_pid.to_bytes(buffer)?;
                process_tgid.to_bytes(buffer)?;
                comm.to_bytes(buffer)?;
            }
            ProcEvent::Coredump {
                process_pid,
                process_tgid,
                parent_pid,
                parent_tgid,
            } => {
                process_pid.to_bytes(buffer)?;
                process_tgid.to_bytes(buffer)?;
                parent_pid.to_bytes(buffer)?;
                parent_tgid.to_bytes(buffer)?;
            }
            ProcEvent::Exit {
                process_pid,
                process_tgid,
                exit_code,
                exit_signal,
                parent_pid,
                parent_tgid,
            } => {
                process_pid.to_bytes(buffer)?;
                process_tgid.to_bytes(buffer)?;
                exit_code.to_bytes(buffer)?;
                exit_signal.to_bytes(buffer)?;
                parent_pid.to_bytes(buffer)?;
                parent_tgid.to_bytes(buffer)?;
            }
        };

        Ok(())
    }
}

impl FromBytesWithInput for ProcEventHeader {
    type Input = usize;

    fn from_bytes_with_input(
        buffer: &mut Cursor<impl AsRef<[u8]>>,
        input: Self::Input,
    ) -> Result<Self, DeError> {
        let start = buffer.position();

        trace!("Parsing ProcEventHeader at position {start} with input size {input}");

        // Minimum size for header (16) + smallest event (ack: 4) is 20.
        if input < 16 || buffer.position() as usize + input > buffer.get_ref().as_ref().len() {
            return Err(DeError::InvalidInput(input));
        }

        // Read header fields: what (u32), cpu (u32), timestamp_ns (u64)
        fn parse(buffer: &mut Cursor<impl AsRef<[u8]>>) -> Result<ProcEventHeader, DeError> {
            let what_val = u32::from_bytes(buffer)?;
            let what = ProcEventType::from(what_val);
            let cpu = u32::from_bytes(buffer)?;
            let timestamp_ns = u64::from_bytes(buffer)?;

            let event = match what {
                ProcEventType::None => ProcEvent::Ack {
                    err: u32::from_bytes(buffer)?,
                },
                ProcEventType::Fork => ProcEvent::Fork {
                    parent_pid: i32::from_bytes(buffer)?,
                    parent_tgid: i32::from_bytes(buffer)?,
                    child_pid: i32::from_bytes(buffer)?,
                    child_tgid: i32::from_bytes(buffer)?,
                },
                ProcEventType::Exec => ProcEvent::Exec {
                    process_pid: i32::from_bytes(buffer)?,
                    process_tgid: i32::from_bytes(buffer)?,
                },
                ProcEventType::Uid => ProcEvent::Uid {
                    process_pid: i32::from_bytes(buffer)?,
                    process_tgid: i32::from_bytes(buffer)?,
                    ruid: u32::from_bytes(buffer)?,
                    euid: u32::from_bytes(buffer)?,
                },
                ProcEventType::Gid => ProcEvent::Gid {
                    process_pid: i32::from_bytes(buffer)?,
                    process_tgid: i32::from_bytes(buffer)?,
                    rgid: u32::from_bytes(buffer)?,
                    egid: u32::from_bytes(buffer)?,
                },
                ProcEventType::Sid => ProcEvent::Sid {
                    process_pid: i32::from_bytes(buffer)?,
                    process_tgid: i32::from_bytes(buffer)?,
                },
                ProcEventType::Ptrace => ProcEvent::Ptrace {
                    process_pid: i32::from_bytes(buffer)?,
                    process_tgid: i32::from_bytes(buffer)?,
                    tracer_pid: i32::from_bytes(buffer)?,
                    tracer_tgid: i32::from_bytes(buffer)?,
                },
                ProcEventType::Comm => {
                    let process_pid = i32::from_bytes(buffer)?;
                    let process_tgid = i32::from_bytes(buffer)?;
                    let mut comm = [0u8; 16];
                    buffer.read_exact(&mut comm)?;
                    ProcEvent::Comm {
                        process_pid,
                        process_tgid,
                        comm,
                    }
                }
                ProcEventType::Coredump => ProcEvent::Coredump {
                    process_pid: i32::from_bytes(buffer)?,
                    process_tgid: i32::from_bytes(buffer)?,
                    parent_pid: i32::from_bytes(buffer)?,
                    parent_tgid: i32::from_bytes(buffer)?,
                },
                ProcEventType::Exit | ProcEventType::NonzeroExit => ProcEvent::Exit {
                    process_pid: i32::from_bytes(buffer)?,
                    process_tgid: i32::from_bytes(buffer)?,
                    exit_code: u32::from_bytes(buffer)?,
                    exit_signal: u32::from_bytes(buffer)?,
                    parent_pid: i32::from_bytes(buffer)?,
                    parent_tgid: i32::from_bytes(buffer)?,
                },
                ProcEventType::UnrecognizedConst(i) => {
                    return Err(DeError::Msg(MsgError::new(format!(
                        "Unrecognized Proc event type: {i} (raw value: {what_val})"
                    ))));
                }
            };
            Ok(ProcEventHeader {
                cpu,
                timestamp_ns,
                event,
            })
        }

        let event = match parse(buffer) {
            Ok(ev) => ev,
            Err(e) => {
                buffer.set_position(start);
                return Err(e);
            }
        };

        buffer.set_position(start + input as u64);

        // consume the entire len, because the kernel can pad the event data with zeros

        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_endian_agnostic_response() -> Vec<u8> {
        let mut cursor = Cursor::new(vec![]);
        let msg = CnMsg {
            idx: CnMsgIdx::Proc,
            val: CnMsgVal::Proc,
            seq: 643,
            ack: 0,
            len: 40,
            flags: 0,
            payload: ProcEventHeader {
                cpu: 1,
                timestamp_ns: 2504390882488,
                event: ProcEvent::Exec {
                    process_pid: 5759,
                    process_tgid: 5759,
                },
            },
        };
        msg.to_bytes(&mut cursor).unwrap();
        cursor.into_inner()
    }

    #[test]
    fn parse_static_proc_header() {
        let mut cursor = Cursor::new(build_endian_agnostic_response());

        let len = cursor.get_ref().len();
        let msg: CnMsg<ProcEventHeader> = CnMsg::from_bytes_with_input(&mut cursor, len).unwrap();

        assert_eq!(msg.idx(), &CnMsgIdx::Proc);
        assert_eq!(msg.val(), &CnMsgVal::Proc);
        assert_eq!(msg.payload.cpu, 1);
        assert_eq!(msg.payload.timestamp_ns, 2504390882488);
        match &msg.payload.event {
            ProcEvent::Exec {
                process_pid,
                process_tgid,
            } => {
                assert_eq!(*process_pid, 5759);
                assert_eq!(*process_tgid, 5759);
            }
            _ => panic!("Expected Exec event"),
        }
    }

    #[test]
    fn parse_static_raw_data() {
        let mut cursor = Cursor::new(build_endian_agnostic_response());

        let len = cursor.get_ref().len();
        let msg: CnMsg<Vec<u8>> = CnMsg::from_bytes_with_input(&mut cursor, len).unwrap();

        assert_eq!(msg.idx(), &CnMsgIdx::Proc);
        assert_eq!(msg.val(), &CnMsgVal::Proc);
    }
}
