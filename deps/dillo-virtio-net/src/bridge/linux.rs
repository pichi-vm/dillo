// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! Linux bridge backend: create a tap and enslave it to an existing bridge.
//!
//! dillo creates a fresh `IFF_TAP | IFF_NO_PI` interface (kernel-assigned name),
//! enslaves it to the operator's bridge with `SIOCBRADDIF`, brings it up, and
//! exchanges raw Ethernet frames with it. The guest then shares the bridge's L2
//! segment — the "traditional TAP/bridging" path, now behind `backend=bridge`.
//!
//! The operator owns the bridge out of band, e.g.:
//!
//! ```text
//! ip link add br0 type bridge
//! ip link set br0 up
//! ip link set eth0 master br0     # to reach the physical LAN
//! ```
//!
//! Then: `--net backend=bridge,iface=br0`. Creating/enslaving a tap needs
//! `CAP_NET_ADMIN`; [`BridgeBackend::open`] surfaces `EPERM`/`ENOENT` cleanly.

use std::ffi::CString;
use std::fs::OpenOptions;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;

use crate::backend::NetBackend;
use crate::linux_fd::FrameFd;

/// `TUNSETIFF` ioctl: `_IOW('T', 202, int)`. Stable kernel ABI.
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
/// `IFF_TAP`: layer-2 (Ethernet frame) tap device.
const IFF_TAP: u16 = 0x0002;
/// `IFF_NO_PI`: no 4-byte packet-info prefix — deliver bare Ethernet frames.
const IFF_NO_PI: u16 = 0x1000;
/// `SIOCBRADDIF`: add an interface (by ifindex) to a bridge.
const SIOCBRADDIF: libc::c_ulong = 0x89a2;
/// `SIOCGIFFLAGS` / `SIOCSIFFLAGS`: get/set interface flags.
const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
const SIOCSIFFLAGS: libc::c_ulong = 0x8914;
/// `IFF_UP` / `IFF_RUNNING` interface-flag bits.
const IFF_UP: i16 = 0x1;
const IFF_RUNNING: i16 = 0x40;
/// `IFNAMSIZ`: max interface-name length including the NUL terminator.
const IFNAMSIZ: usize = 16;
/// Size of `struct ifreq` on Linux (name[16] + the largest union member).
const IFREQ_LEN: usize = 40;
/// Byte offset of the `ifreq` union (where `ifr_flags`/`ifr_ifindex` live).
const IFREQ_UNION_OFF: usize = IFNAMSIZ;

/// A bridge-enslaved tap backing a virtio-net device.
#[derive(Debug)]
pub struct BridgeBackend {
    fd: FrameFd,
    tap_name: String,
    bridge: String,
}

impl BridgeBackend {
    /// Create a tap, enslave it to `bridge`, and bring it up.
    pub fn open(bridge: &str) -> io::Result<Self> {
        if bridge.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bridge backend requires iface=<bridge-name>",
            ));
        }
        if bridge.len() >= IFNAMSIZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("bridge name {bridge:?} exceeds {} bytes", IFNAMSIZ - 1),
            ));
        }

        // 1. Create the tap (kernel assigns the name).
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open("/dev/net/tun")?;
        let mut ifr = ifreq_with_name("");
        let flags = IFF_TAP | IFF_NO_PI;
        ifr[IFREQ_UNION_OFF..IFREQ_UNION_OFF + 2].copy_from_slice(&flags.to_le_bytes());
        // SAFETY: `ifr` is a correctly sized, initialized `ifreq` buffer; the
        // kernel reads ifr_name + ifr_flags and writes back the resolved name.
        #[allow(unsafe_code)]
        let rc = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, ifr.as_mut_ptr()) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        let tap_name = read_ifr_name(&ifr);

        // 2. Resolve the tap's ifindex.
        let tap_c = CString::new(tap_name.clone())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        // SAFETY: `tap_c` is a valid NUL-terminated C string.
        #[allow(unsafe_code)]
        let ifindex = unsafe { libc::if_nametoindex(tap_c.as_ptr()) };
        if ifindex == 0 {
            return Err(io::Error::last_os_error());
        }

        // 3. A control socket for the bridge/flags ioctls.
        // SAFETY: a standard `socket(2)` call; the returned fd is wrapped in an
        // `OwnedFd` so it is closed on drop.
        #[allow(unsafe_code)]
        let ctrl = unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            OwnedFd::from_raw_fd(fd)
        };

        // 4. Enslave the tap to the bridge.
        let mut braddif = build_braddif_ifreq(bridge, ifindex.cast_signed());
        // SAFETY: `braddif` is a correctly sized `ifreq` carrying ifr_name +
        // ifr_ifindex; the kernel only reads it.
        #[allow(unsafe_code)]
        let rc = unsafe { libc::ioctl(ctrl.as_raw_fd(), SIOCBRADDIF, braddif.as_mut_ptr()) };
        if rc < 0 {
            return Err(io::Error::new(
                io::Error::last_os_error().kind(),
                format!(
                    "enslaving tap {tap_name:?} to bridge {bridge:?} (SIOCBRADDIF): {}",
                    io::Error::last_os_error()
                ),
            ));
        }

        // 5. Bring the tap up (read-modify-write its flags).
        set_iface_up(&ctrl, &tap_name)?;

        log::info!("virtio-net: tap {tap_name:?} enslaved to bridge {bridge:?} and up");
        Ok(Self {
            fd: FrameFd::new(file),
            tap_name,
            bridge: bridge.to_owned(),
        })
    }

    /// The kernel-assigned tap interface name (e.g. `"tap0"`).
    pub fn tap_name(&self) -> &str {
        &self.tap_name
    }

    /// The bridge this tap was enslaved to.
    pub fn bridge(&self) -> &str {
        &self.bridge
    }
}

impl NetBackend for BridgeBackend {
    fn send(&self, frame: &[u8]) -> io::Result<()> {
        self.fd.send(frame)
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        self.fd.recv(buf)
    }
}

/// Read-modify-write an interface's flags to add `IFF_UP | IFF_RUNNING`.
fn set_iface_up(ctrl: &OwnedFd, name: &str) -> io::Result<()> {
    let mut ifr = ifreq_with_name(name);
    // SAFETY: `ifr` carries a valid ifr_name; SIOCGIFFLAGS writes ifr_flags.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::ioctl(ctrl.as_raw_fd(), SIOCGIFFLAGS, ifr.as_mut_ptr()) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut flags = i16::from_le_bytes([ifr[IFREQ_UNION_OFF], ifr[IFREQ_UNION_OFF + 1]]);
    flags |= IFF_UP | IFF_RUNNING;
    ifr[IFREQ_UNION_OFF..IFREQ_UNION_OFF + 2].copy_from_slice(&flags.to_le_bytes());
    // SAFETY: same buffer, now with the desired ifr_flags; the kernel reads it.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::ioctl(ctrl.as_raw_fd(), SIOCSIFFLAGS, ifr.as_mut_ptr()) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// A zeroed `ifreq` with `ifr_name` set to `name` (truncated to fit).
fn ifreq_with_name(name: &str) -> [u8; IFREQ_LEN] {
    let mut ifr = [0u8; IFREQ_LEN];
    let nb = name.as_bytes();
    let n = nb.len().min(IFNAMSIZ - 1);
    ifr[..n].copy_from_slice(&nb[..n]);
    ifr
}

/// Build the `ifreq` for `SIOCBRADDIF`: `ifr_name = bridge`, `ifr_ifindex` (a
/// `c_int`) in the union at [`IFREQ_UNION_OFF`].
fn build_braddif_ifreq(bridge: &str, ifindex: libc::c_int) -> [u8; IFREQ_LEN] {
    let mut ifr = ifreq_with_name(bridge);
    let bytes = ifindex.to_ne_bytes();
    ifr[IFREQ_UNION_OFF..IFREQ_UNION_OFF + bytes.len()].copy_from_slice(&bytes);
    ifr
}

/// Extract the NUL-terminated `ifr_name` from an `ifreq` buffer.
fn read_ifr_name(ifr: &[u8; IFREQ_LEN]) -> String {
    let end = ifr[..IFNAMSIZ]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(IFNAMSIZ);
    String::from_utf8_lossy(&ifr[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn braddif_ifreq_layout() {
        let ifr = build_braddif_ifreq("br0", 7);
        assert_eq!(&ifr[..3], b"br0", "ifr_name must hold the bridge name");
        assert_eq!(ifr[3], 0, "ifr_name must be NUL-terminated");
        let idx = libc::c_int::from_ne_bytes([
            ifr[IFREQ_UNION_OFF],
            ifr[IFREQ_UNION_OFF + 1],
            ifr[IFREQ_UNION_OFF + 2],
            ifr[IFREQ_UNION_OFF + 3],
        ]);
        assert_eq!(idx, 7, "ifr_ifindex must carry the tap index");
    }

    #[test]
    fn ifr_name_round_trips() {
        let ifr = ifreq_with_name("tap42");
        assert_eq!(read_ifr_name(&ifr), "tap42");
    }

    #[test]
    fn empty_bridge_name_rejected() {
        let err = BridgeBackend::open("").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn overlong_bridge_name_rejected() {
        let err = BridgeBackend::open("this-bridge-name-too-long").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    /// Enslaving needs CAP_NET_ADMIN and a real bridge; in an unprivileged
    /// sandbox this fails cleanly rather than panicking. A success (privileged
    /// box with a `br0`) yields a usable tap name.
    #[test]
    fn open_is_clean_without_privilege() {
        match BridgeBackend::open("br0") {
            Ok(b) => assert!(!b.tap_name().is_empty(), "kernel must assign a tap name"),
            Err(e) => eprintln!("bridge open unavailable in this environment: {e}"),
        }
    }

    /// Layer-3 integration: actually create and enslave a tap on a real bridge.
    /// Opt-in and never run in CI (needs root + an existing bridge). See the
    /// crate README for the setup recipe.
    ///
    /// Run with:
    /// ```text
    /// sudo DILLO_NET_BRIDGE_TEST=br0 \
    ///   cargo test -p dillo-virtio-net --  --ignored bridge_enslaves_tap
    /// ```
    #[test]
    #[ignore = "needs root + an existing bridge; set DILLO_NET_BRIDGE_TEST=<bridge>"]
    fn bridge_enslaves_tap_when_privileged() {
        let bridge = match std::env::var("DILLO_NET_BRIDGE_TEST") {
            Ok(b) if !b.is_empty() => b,
            _ => {
                eprintln!("set DILLO_NET_BRIDGE_TEST=<bridge> (and run as root) to exercise this");
                return;
            }
        };

        let backend = BridgeBackend::open(&bridge)
            .expect("open bridge backend (needs root + an existing bridge)");
        let tap = backend.tap_name();
        assert_eq!(backend.bridge(), bridge);

        // Enslavement proof: /sys/class/net/<tap>/master links to the bridge.
        let master = std::fs::read_link(format!("/sys/class/net/{tap}/master"))
            .expect("enslaved tap must expose a master link");
        let master_name = master
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        assert_eq!(master_name, bridge, "tap enslaved to the wrong bridge");

        // And the tap was brought up (IFF_UP is bit 0 of the sysfs flags hex).
        let flags =
            std::fs::read_to_string(format!("/sys/class/net/{tap}/flags")).unwrap_or_default();
        let flags_val = u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16).unwrap_or(0);
        assert_ne!(flags_val & 0x1, 0, "tap {tap} should be IFF_UP");
        eprintln!("tap {tap} enslaved to {bridge} and up (flags {flags:?})");
    }
}
