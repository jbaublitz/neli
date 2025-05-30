//! Connector module for netlink messages.

use crate::{
    self as neli,
    consts::connector::{CnMsgIdx, CnMsgVal, ProcCnMcastOp, ProcEventType},
    err::{DeError, MsgError},
    FromBytesWithInput, Header, Size, ToBytes,
};
use byteorder::{NativeEndian, ReadBytesExt};
use derive_builder::Builder;
use getset::Getters;
use log::trace;
use std::{io::Cursor, io::Read};

/// A trait for types that can be used as payloads in netlink connector messages.
pub trait CnMsgPayload {}

impl CnMsgPayload for ProcCnMcastOp {}
impl CnMsgPayload for ProcEventHeader {}

/// Netlink connector message header and payload.
#[derive(
    Builder, Getters, Clone, Debug, PartialEq, Eq, Size, ToBytes, FromBytesWithInput, Header,
)]
#[neli(from_bytes_bound = "P: Size + FromBytesWithInput<Input = usize> + CnMsgPayload")]
#[builder(pattern = "owned")]
pub struct CnMsg<P: CnMsgPayload + Size> {
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
    #[builder(setter(skip), default = "self.payload.as_ref().unwrap().unpadded_size() as _")]
    #[getset(get = "pub")]
    len: u16,
    /// Flags
    #[builder(default)]
    #[getset(get = "pub")]
    flags: u16,
    /// Payload of the netlink message
    #[neli(size = "len as usize")]
    #[neli(input = "(len as usize)")]
    #[getset(get = "pub")]
    pub(crate) payload: P,
}

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

impl FromBytesWithInput for ProcEventHeader {
    type Input = usize;

    fn from_bytes_with_input(
        buffer: &mut Cursor<impl AsRef<[u8]>>,
        input: Self::Input,
    ) -> Result<Self, DeError> {
        let start = buffer.position() as usize;
        let bytes = buffer.get_ref().as_ref();

        trace!(
            "Parsing ProcEventHeader at position {} with input size {}",
            start,
            input
        );

        // Minimum size for header (16) + smallest event (ack: 4) is 20.
        if input < 16 || bytes.len() < start + input {
            return Err(DeError::InvalidInput(input));
        }

        // Read header fields: what (u32), cpu (u32), timestamp_ns (u64)
        let what_val = buffer.read_u32::<NativeEndian>()?;
        let what = ProcEventType::from(what_val);
        let cpu = buffer.read_u32::<NativeEndian>()?;
        let timestamp_ns = buffer.read_u64::<NativeEndian>()?;

        let event = match what {
            ProcEventType::None => {
                ProcEvent::Ack { err: buffer.read_u32::<NativeEndian>()? }
            }
            ProcEventType::Fork => {
                ProcEvent::Fork {
                    parent_pid: buffer.read_i32::<NativeEndian>()?,
                    parent_tgid: buffer.read_i32::<NativeEndian>()?,
                    child_pid: buffer.read_i32::<NativeEndian>()?,
                    child_tgid: buffer.read_i32::<NativeEndian>()?,
                }
            }
            ProcEventType::Exec => {
                ProcEvent::Exec {
                    process_pid: buffer.read_i32::<NativeEndian>()?,
                    process_tgid: buffer.read_i32::<NativeEndian>()?,
                }
            }
            ProcEventType::Uid => {
                ProcEvent::Uid {
                    process_pid: buffer.read_i32::<NativeEndian>()?,
                    process_tgid: buffer.read_i32::<NativeEndian>()?,
                    ruid: buffer.read_u32::<NativeEndian>()?,
                    euid: buffer.read_u32::<NativeEndian>()?,
                }
            }
            ProcEventType::Gid => {
                ProcEvent::Gid {
                    process_pid: buffer.read_i32::<NativeEndian>()?,
                    process_tgid: buffer.read_i32::<NativeEndian>()?,
                    rgid: buffer.read_u32::<NativeEndian>()?,
                    egid: buffer.read_u32::<NativeEndian>()?,
                }
            }
            ProcEventType::Sid => {
                ProcEvent::Sid {
                    process_pid: buffer.read_i32::<NativeEndian>()?,
                    process_tgid: buffer.read_i32::<NativeEndian>()?,
                }
            }
            ProcEventType::Ptrace => {
                ProcEvent::Ptrace {
                    process_pid: buffer.read_i32::<NativeEndian>()?,
                    process_tgid: buffer.read_i32::<NativeEndian>()?,
                    tracer_pid: buffer.read_i32::<NativeEndian>()?,
                    tracer_tgid: buffer.read_i32::<NativeEndian>()?,
                }
            }
            ProcEventType::Comm => {
                let process_pid = buffer.read_i32::<NativeEndian>()?;
                let process_tgid = buffer.read_i32::<NativeEndian>()?;
                let mut comm = [0u8; 16];
                buffer.read_exact(&mut comm)?;
                ProcEvent::Comm {
                    process_pid,
                    process_tgid,
                    comm,
                }
            }
            ProcEventType::Coredump => {
                ProcEvent::Coredump {
                    process_pid: buffer.read_i32::<NativeEndian>()?,
                    process_tgid: buffer.read_i32::<NativeEndian>()?,
                    parent_pid: buffer.read_i32::<NativeEndian>()?,
                    parent_tgid: buffer.read_i32::<NativeEndian>()?,
                }
            }
            ProcEventType::Exit | ProcEventType::NonzeroExit => {
                ProcEvent::Exit {
                    process_pid: buffer.read_i32::<NativeEndian>()?,
                    process_tgid: buffer.read_i32::<NativeEndian>()?,
                    exit_code: buffer.read_u32::<NativeEndian>()?,
                    exit_signal: buffer.read_u32::<NativeEndian>()?,
                    parent_pid: buffer.read_i32::<NativeEndian>()?,
                    parent_tgid: buffer.read_i32::<NativeEndian>()?,
                }
            }
            ProcEventType::UnrecognizedConst(i) => {
                return Err(DeError::Msg(MsgError::new(format!(
                    "Unrecognized Proc event type: {i} (raw value: {what_val})"
                ))));
            }
        };
        
        // consume the entire len, because the kernel can pad the event data with zeros
        buffer.set_position(start as u64 + input as u64);

        Ok(ProcEventHeader {
            cpu,
            timestamp_ns,
            event,
        })
    }
}
