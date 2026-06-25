// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! Virtio-vsock 44-byte packet header codec.
//!
//! This module is pure: it only encodes/decodes the fixed header and carries
//! the payload as a `Vec<u8>`. Walking guest descriptor chains (reading the
//! header + payload off the TX queue, writing them onto the RX queue) lives in
//! `lib.rs` against the in-process `VirtioMemory` / `DescriptorChain` API.

/// Size of the vsock packet header in bytes.
pub(crate) const VSOCK_HEADER_LEN: usize = 44;

// Vsock operations.

/// Connection request (guest initiates).
pub(crate) const VSOCK_OP_REQUEST: u16 = 1;
/// Connection response (host accepts).
pub(crate) const VSOCK_OP_RESPONSE: u16 = 2;
/// Connection reset.
pub(crate) const VSOCK_OP_RST: u16 = 3;
/// Graceful shutdown (with direction flags).
pub(crate) const VSOCK_OP_SHUTDOWN: u16 = 4;
/// Data read/write.
pub(crate) const VSOCK_OP_RW: u16 = 5;
/// Proactive credit update from peer.
pub(crate) const VSOCK_OP_CREDIT_UPDATE: u16 = 6;
/// Credit request: asks peer to send a credit update.
pub(crate) const VSOCK_OP_CREDIT_REQUEST: u16 = 7;

/// Stream socket type (the only type defined for vsock).
pub(crate) const VSOCK_TYPE_STREAM: u16 = 1;

/// Shutdown flag: peer requests receive direction shutdown.
pub(crate) const VSOCK_FLAGS_SHUTDOWN_RCV: u32 = 1;
/// Shutdown flag: peer requests send direction shutdown.
pub(crate) const VSOCK_FLAGS_SHUTDOWN_SEND: u32 = 2;

/// Well-known host CID.
pub(crate) const VSOCK_HOST_CID: u64 = 2;

/// A vsock packet: fixed header fields plus an optional data payload.
#[derive(Debug, Clone)]
pub(crate) struct VsockPacket {
    /// Source context identifier (CID).
    pub(crate) src_cid: u64,
    /// Destination context identifier (CID).
    pub(crate) dst_cid: u64,
    /// Source port number.
    pub(crate) src_port: u32,
    /// Destination port number.
    pub(crate) dst_port: u32,
    /// Payload length in bytes (from the header; may differ from `data.len()`).
    pub(crate) len: u32,
    /// Socket type (always [`VSOCK_TYPE_STREAM`]).
    pub(crate) type_: u16,
    /// Operation code (one of the `VSOCK_OP_*` constants).
    pub(crate) op: u16,
    /// Flags (e.g., shutdown direction flags).
    pub(crate) flags: u32,
    /// Sender's advertised buffer allocation for credit-based flow control.
    pub(crate) buf_alloc: u32,
    /// Sender's forwarded byte count for credit-based flow control.
    pub(crate) fwd_cnt: u32,
    /// Payload data bytes (empty for control packets).
    pub(crate) data: Vec<u8>,
}

impl VsockPacket {
    /// Decode the 44-byte header. The payload is left empty; callers append
    /// payload bytes read from the descriptor chain.
    pub(crate) fn parse_header(hdr: &[u8; VSOCK_HEADER_LEN]) -> Self {
        Self {
            src_cid: u64::from_le_bytes(hdr[0..8].try_into().unwrap()),
            dst_cid: u64::from_le_bytes(hdr[8..16].try_into().unwrap()),
            src_port: u32::from_le_bytes(hdr[16..20].try_into().unwrap()),
            dst_port: u32::from_le_bytes(hdr[20..24].try_into().unwrap()),
            len: u32::from_le_bytes(hdr[24..28].try_into().unwrap()),
            type_: u16::from_le_bytes(hdr[28..30].try_into().unwrap()),
            op: u16::from_le_bytes(hdr[30..32].try_into().unwrap()),
            flags: u32::from_le_bytes(hdr[32..36].try_into().unwrap()),
            buf_alloc: u32::from_le_bytes(hdr[36..40].try_into().unwrap()),
            fwd_cnt: u32::from_le_bytes(hdr[40..44].try_into().unwrap()),
            data: Vec::new(),
        }
    }

    /// Encode the 44-byte header. The `len` field reflects `data.len()` so the
    /// guest sees a header consistent with the payload actually delivered.
    pub(crate) fn header_bytes(&self) -> [u8; VSOCK_HEADER_LEN] {
        let mut hdr = [0u8; VSOCK_HEADER_LEN];
        hdr[0..8].copy_from_slice(&self.src_cid.to_le_bytes());
        hdr[8..16].copy_from_slice(&self.dst_cid.to_le_bytes());
        hdr[16..20].copy_from_slice(&self.src_port.to_le_bytes());
        hdr[20..24].copy_from_slice(&self.dst_port.to_le_bytes());
        hdr[24..28].copy_from_slice(&(self.data.len() as u32).to_le_bytes());
        hdr[28..30].copy_from_slice(&self.type_.to_le_bytes());
        hdr[30..32].copy_from_slice(&self.op.to_le_bytes());
        hdr[32..36].copy_from_slice(&self.flags.to_le_bytes());
        hdr[36..40].copy_from_slice(&self.buf_alloc.to_le_bytes());
        hdr[40..44].copy_from_slice(&self.fwd_cnt.to_le_bytes());
        hdr
    }

    /// Create a reply packet with the given operation and no data.
    pub(crate) fn new_reply(
        op: u16,
        src_cid: u64,
        dst_cid: u64,
        src_port: u32,
        dst_port: u32,
    ) -> Self {
        Self {
            src_cid,
            dst_cid,
            src_port,
            dst_port,
            len: 0,
            type_: VSOCK_TYPE_STREAM,
            op,
            flags: 0,
            buf_alloc: 0,
            fwd_cnt: 0,
            data: Vec::new(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trips_through_bytes() {
        let pkt = VsockPacket {
            src_cid: 3,
            dst_cid: VSOCK_HOST_CID,
            src_port: 1234,
            dst_port: 5678,
            len: 0,
            type_: VSOCK_TYPE_STREAM,
            op: VSOCK_OP_REQUEST,
            flags: 0,
            buf_alloc: 65536,
            fwd_cnt: 100,
            data: Vec::new(),
        };
        let parsed = VsockPacket::parse_header(&pkt.header_bytes());
        assert_eq!(parsed.src_cid, 3);
        assert_eq!(parsed.dst_cid, VSOCK_HOST_CID);
        assert_eq!(parsed.src_port, 1234);
        assert_eq!(parsed.dst_port, 5678);
        assert_eq!(parsed.op, VSOCK_OP_REQUEST);
        assert_eq!(parsed.buf_alloc, 65536);
        assert_eq!(parsed.fwd_cnt, 100);
        assert!(parsed.data.is_empty());
    }

    #[test]
    fn header_bytes_len_field_tracks_payload() {
        let mut pkt = VsockPacket::new_reply(VSOCK_OP_RW, VSOCK_HOST_CID, 3, 5678, 1234);
        pkt.data = b"hello".to_vec();
        let hdr = pkt.header_bytes();
        // len field at offset 24..28 reflects the 5-byte payload.
        assert_eq!(u32::from_le_bytes(hdr[24..28].try_into().unwrap()), 5);
        let op = u16::from_le_bytes(hdr[30..32].try_into().unwrap());
        assert_eq!(op, VSOCK_OP_RW);
    }

    #[test]
    fn new_reply_creates_control_packet() {
        let pkt = VsockPacket::new_reply(VSOCK_OP_RESPONSE, VSOCK_HOST_CID, 3, 5678, 1234);
        assert_eq!(pkt.op, VSOCK_OP_RESPONSE);
        assert_eq!(pkt.src_cid, VSOCK_HOST_CID);
        assert_eq!(pkt.dst_cid, 3);
        assert_eq!(pkt.type_, VSOCK_TYPE_STREAM);
        assert!(pkt.data.is_empty());
    }
}
