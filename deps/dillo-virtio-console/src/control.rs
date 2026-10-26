// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The MULTIPORT control plane: `virtio_console_control` codec plus the
//! device-side state machine that announces ports to the guest.
//!
//! Wire format (virtio 1.x §5.3.6.X), little-endian:
//!
//! ```text
//! struct virtio_console_control { le32 id; le16 event; le16 value; }
//! ```
//!
//! `PORT_NAME` appends the name bytes **plus a NUL terminator** — Linux's
//! `virtio_console` copies the payload straight into a string buffer and
//! relies on that terminator.
//!
//! Ordering floor (consensus S5/S16): nothing is announced until the guest
//! says `DEVICE_READY`. Then every port — including the unnamed port 0, which
//! under MULTIPORT only exists if the control plane creates it — gets
//! `PORT_ADD`; once the guest acknowledges with `PORT_READY`, the device sends
//! `CONSOLE_PORT` (port 0 only), `PORT_NAME` (named ports only), and
//! `PORT_OPEN`.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;

/// `struct virtio_console_control` header length.
pub(crate) const CONTROL_HEADER_LEN: usize = 8;

/// Control events (virtio 1.x §5.3.6.X).
pub(crate) mod event {
    /// Guest → device: the driver is ready for port announcements.
    pub(crate) const DEVICE_READY: u16 = 0;
    /// Device → guest: a port exists.
    pub(crate) const PORT_ADD: u16 = 1;
    /// Device → guest: a port is gone.
    #[allow(dead_code)]
    pub(crate) const PORT_REMOVE: u16 = 2;
    /// Guest → device: the driver finished setting a port up.
    pub(crate) const PORT_READY: u16 = 3;
    /// Device → guest: this port is a console (port 0).
    pub(crate) const CONSOLE_PORT: u16 = 4;
    /// Device → guest / guest → device: terminal resize. Unused.
    #[allow(dead_code)]
    pub(crate) const RESIZE: u16 = 5;
    /// Either direction: the far side opened (1) or closed (0) the port.
    pub(crate) const PORT_OPEN: u16 = 6;
    /// Device → guest: the port's name, NUL-terminated.
    pub(crate) const PORT_NAME: u16 = 7;
}

/// One `virtio_console_control` message, with any trailing payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ControlMessage {
    pub(crate) id: u32,
    pub(crate) event: u16,
    pub(crate) value: u16,
    pub(crate) payload: Vec<u8>,
}

impl ControlMessage {
    pub(crate) fn new(id: u32, event: u16, value: u16) -> Self {
        Self {
            id,
            event,
            value,
            payload: Vec::new(),
        }
    }

    /// `PORT_NAME` for `id`: header + name bytes + NUL.
    pub(crate) fn port_name(id: u32, name: &str) -> Self {
        let mut payload = Vec::with_capacity(name.len() + 1);
        payload.extend_from_slice(name.as_bytes());
        payload.push(0);
        Self {
            id,
            event: event::PORT_NAME,
            value: 0,
            payload,
        }
    }

    /// Serialize for the control receiveq.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CONTROL_HEADER_LEN + self.payload.len());
        out.extend_from_slice(&self.id.to_le_bytes());
        out.extend_from_slice(&self.event.to_le_bytes());
        out.extend_from_slice(&self.value.to_le_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parse a guest-sent control message. Short buffers are ignored.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < CONTROL_HEADER_LEN {
            return None;
        }
        Some(Self {
            id: u32::from_le_bytes(bytes[0..4].try_into().ok()?),
            event: u16::from_le_bytes(bytes[4..6].try_into().ok()?),
            value: u16::from_le_bytes(bytes[6..8].try_into().ok()?),
            payload: bytes[CONTROL_HEADER_LEN..].to_vec(),
        })
    }
}

/// What a port needs announced once the guest acknowledges it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PortKind {
    /// Port 0: the unnamed stdio console. Gets `CONSOLE_PORT`, never a name.
    Console,
    /// A named MULTIPORT port. Gets `PORT_NAME`.
    Named(String),
}

/// Device-side control state machine, plus the queue of messages waiting for
/// guest-provided control receiveq buffers.
///
/// Shared by the control worker (which drains `outbound`) and the per-port
/// data workers (which report a host-side disconnect).
#[derive(Debug)]
pub(crate) struct ControlPlane {
    ports: Vec<PortKind>,
    /// Per-port: has a guest process opened it? Host → guest data is held
    /// until this is set, because Linux drops inbound buffers for a port
    /// nobody has opened.
    guest_open: Vec<AtomicBool>,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    /// Set once the guest sends `DEVICE_READY`; nothing is announced before.
    device_ready: bool,
    outbound: VecDeque<ControlMessage>,
}

impl ControlPlane {
    /// `ports[i]` describes port id `i`, so index 0 is always the console.
    pub(crate) fn new(ports: Vec<PortKind>) -> Self {
        Self {
            guest_open: ports.iter().map(|_| AtomicBool::new(false)).collect(),
            ports,
            state: Mutex::new(State::default()),
        }
    }

    /// Has a guest process opened port `id`? Host → guest data must wait for
    /// this, or Linux will silently drop it.
    pub(crate) fn guest_has_opened(&self, id: u32) -> bool {
        self.guest_open
            .get(id as usize)
            .is_some_and(|f| f.load(std::sync::atomic::Ordering::Acquire))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .expect("virtio-console control plane mutex")
    }

    /// Handle one guest → device control message.
    pub(crate) fn handle(&self, msg: &ControlMessage) {
        match msg.event {
            event::DEVICE_READY => {
                if msg.value == 0 {
                    log::warn!("virtio-console: guest reported DEVICE_READY failure");
                    return;
                }
                let mut state = self.lock();
                if state.device_ready {
                    return;
                }
                state.device_ready = true;
                // Port 0 is announced like any other: once MULTIPORT is
                // negotiated Linux creates ports only from control messages.
                for id in 0..self.ports.len() as u32 {
                    state
                        .outbound
                        .push_back(ControlMessage::new(id, event::PORT_ADD, 1));
                }
                log::debug!(
                    "virtio-console: guest DEVICE_READY, announcing {} port(s)",
                    self.ports.len()
                );
            }
            event::PORT_READY => {
                let Some(kind) = self.ports.get(msg.id as usize).cloned() else {
                    log::warn!("virtio-console: PORT_READY for unknown port {}", msg.id);
                    return;
                };
                if msg.value == 0 {
                    log::warn!("virtio-console: guest failed to add port {}", msg.id);
                    return;
                }
                let mut state = self.lock();
                match kind {
                    PortKind::Console => state.outbound.push_back(ControlMessage::new(
                        msg.id,
                        event::CONSOLE_PORT,
                        1,
                    )),
                    PortKind::Named(name) => state
                        .outbound
                        .push_back(ControlMessage::port_name(msg.id, &name)),
                }
                state
                    .outbound
                    .push_back(ControlMessage::new(msg.id, event::PORT_OPEN, 1));
            }
            event::PORT_OPEN => {
                // Linux discards inbound data for a port no guest process has
                // opened yet (`virtio_console`'s `in_intr` drops buffers while
                // `guest_connected` is false), so RX must wait for this.
                let open = msg.value != 0;
                if let Some(flag) = self.guest_open.get(msg.id as usize) {
                    flag.store(open, std::sync::atomic::Ordering::Release);
                }
                log::debug!(
                    "virtio-console: guest {} port {}",
                    if open { "opened" } else { "closed" },
                    msg.id
                );
            }
            other => {
                log::debug!(
                    "virtio-console: ignoring guest control event {other} for port {}",
                    msg.id
                );
            }
        }
    }

    /// Tell the guest the host side of `id` is gone — every open direction of
    /// that port has hit EOF / EPIPE. The guest sees a clean close on its
    /// `/dev/vport*` instead of a port that merely stops producing.
    pub(crate) fn port_disconnected(&self, id: u32) {
        self.lock()
            .outbound
            .push_back(ControlMessage::new(id, event::PORT_OPEN, 0));
    }

    /// Take the next message owed to the guest, if any.
    pub(crate) fn pop_outbound(&self) -> Option<ControlMessage> {
        self.lock().outbound.pop_front()
    }

    /// Put a message back when no guest buffer was available for it.
    pub(crate) fn requeue(&self, msg: ControlMessage) {
        self.lock().outbound.push_front(msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plane() -> ControlPlane {
        ControlPlane::new(vec![
            PortKind::Console,
            PortKind::Named("build".into()),
            PortKind::Named("log".into()),
        ])
    }

    fn drain(plane: &ControlPlane) -> Vec<ControlMessage> {
        std::iter::from_fn(|| plane.pop_outbound()).collect()
    }

    #[test]
    fn nothing_is_announced_before_device_ready() {
        let plane = plane();
        // A stray PORT_READY before DEVICE_READY still must not jump the gun
        // on the announcements DEVICE_READY owns.
        plane.handle(&ControlMessage::new(0, event::PORT_READY, 1));
        let msgs = drain(&plane);
        assert!(
            msgs.iter().all(|m| m.event != event::PORT_ADD),
            "PORT_ADD before DEVICE_READY: {msgs:?}"
        );
    }

    #[test]
    fn device_ready_adds_every_port_including_port_zero() {
        let plane = plane();
        plane.handle(&ControlMessage::new(0, event::DEVICE_READY, 1));
        let msgs = drain(&plane);
        assert_eq!(msgs.len(), 3);
        for (id, msg) in msgs.iter().enumerate() {
            assert_eq!(msg.event, event::PORT_ADD);
            assert_eq!(msg.id, id as u32);
        }
    }

    #[test]
    fn device_ready_is_idempotent() {
        let plane = plane();
        plane.handle(&ControlMessage::new(0, event::DEVICE_READY, 1));
        let _ = drain(&plane);
        plane.handle(&ControlMessage::new(0, event::DEVICE_READY, 1));
        assert!(drain(&plane).is_empty(), "ports announced twice");
    }

    #[test]
    fn port_zero_gets_console_port_and_open_but_no_name() {
        let plane = plane();
        plane.handle(&ControlMessage::new(0, event::DEVICE_READY, 1));
        let _ = drain(&plane);

        plane.handle(&ControlMessage::new(0, event::PORT_READY, 1));
        let msgs = drain(&plane);
        assert_eq!(
            msgs,
            vec![
                ControlMessage::new(0, event::CONSOLE_PORT, 1),
                ControlMessage::new(0, event::PORT_OPEN, 1),
            ]
        );
    }

    #[test]
    fn named_port_gets_nul_terminated_name_then_open() {
        let plane = plane();
        plane.handle(&ControlMessage::new(0, event::DEVICE_READY, 1));
        let _ = drain(&plane);

        plane.handle(&ControlMessage::new(1, event::PORT_READY, 1));
        let msgs = drain(&plane);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].event, event::PORT_NAME);
        assert_eq!(msgs[0].id, 1);
        assert_eq!(msgs[0].payload, b"build\0");
        assert_eq!(msgs[1], ControlMessage::new(1, event::PORT_OPEN, 1));
        // No CONSOLE_PORT for a named port.
        assert!(msgs.iter().all(|m| m.event != event::CONSOLE_PORT));
    }

    #[test]
    fn port_ready_for_unknown_port_is_ignored() {
        let plane = plane();
        plane.handle(&ControlMessage::new(0, event::DEVICE_READY, 1));
        let _ = drain(&plane);
        plane.handle(&ControlMessage::new(9, event::PORT_READY, 1));
        assert!(drain(&plane).is_empty());
    }

    #[test]
    fn a_port_is_not_guest_open_until_the_guest_opens_it() {
        let plane = plane();
        assert!(
            !plane.guest_has_opened(1),
            "a port must start closed — Linux drops inbound data for a port \
             no guest process has opened"
        );

        plane.handle(&ControlMessage::new(1, event::PORT_OPEN, 1));
        assert!(plane.guest_has_opened(1));
        assert!(!plane.guest_has_opened(2), "only the named port opened");

        plane.handle(&ControlMessage::new(1, event::PORT_OPEN, 0));
        assert!(!plane.guest_has_opened(1), "the guest closed it again");
    }

    #[test]
    fn guest_open_of_an_unknown_port_is_ignored() {
        let plane = plane();
        plane.handle(&ControlMessage::new(9, event::PORT_OPEN, 1));
        assert!(!plane.guest_has_opened(9));
    }

    #[test]
    fn host_disconnect_closes_the_port() {
        let plane = plane();
        plane.port_disconnected(2);
        assert_eq!(
            drain(&plane),
            vec![ControlMessage::new(2, event::PORT_OPEN, 0)]
        );
    }

    #[test]
    fn control_message_round_trips() {
        let msg = ControlMessage::port_name(3, "dev.pichi.build");
        let bytes = msg.encode();
        assert_eq!(&bytes[..4], &3u32.to_le_bytes());
        assert_eq!(&bytes[4..6], &event::PORT_NAME.to_le_bytes());
        assert_eq!(
            *bytes.last().expect("payload"),
            0,
            "name must be NUL-terminated"
        );
        assert_eq!(ControlMessage::decode(&bytes).expect("decode"), msg);
    }

    #[test]
    fn short_control_buffers_are_rejected() {
        assert!(ControlMessage::decode(&[]).is_none());
        assert!(ControlMessage::decode(&[0; CONTROL_HEADER_LEN - 1]).is_none());
        assert!(ControlMessage::decode(&[0; CONTROL_HEADER_LEN]).is_some());
    }

    #[test]
    fn requeued_message_is_sent_first() {
        let plane = plane();
        plane.port_disconnected(1);
        let first = plane.pop_outbound().expect("message");
        plane.requeue(first.clone());
        assert_eq!(plane.pop_outbound(), Some(first));
    }
}
