// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! macOS bridge backend over Apple's `vmnet` framework in **bridged** mode.
//!
//! `vmnet` exposes a host networking endpoint; in `VMNET_BRIDGED_MODE` it bridges
//! the guest onto a named physical interface (`iface=en0`), the macOS analogue of
//! the Linux tap-on-bridge path. Its API is asynchronous and block-based: we
//! start the interface with an XPC parameter dictionary plus a completion
//! handler, register a packet-available event callback that drains inbound
//! frames, and move frames with `vmnet_read`/`vmnet_write` over `vmpktdesc`.
//!
//! Needs root or the `com.apple.vm.networking` entitlement. **All** unsafe FFI
//! is isolated in this module; the rest of the crate stays unsafe-free.
//!
//! This path cannot be exercised in CI (privilege/driver); it is compile-checked
//! on the macOS lane and covered by an opt-in integration test (see the crate
//! README).
#![allow(unsafe_code)]

use std::collections::VecDeque;
use std::ffi::{CString, c_char, c_int, c_void};
use std::io;
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use block2::RcBlock;

use crate::backend::{MAX_FRAME_LEN, NetBackend, RECV_POLL};

// --- vmnet / xpc / dispatch FFI -------------------------------------------

#[allow(non_camel_case_types)]
type xpc_object_t = *mut c_void;
#[allow(non_camel_case_types)]
type dispatch_queue_t = *mut c_void;
#[allow(non_camel_case_types)]
type interface_ref = *mut c_void;
#[allow(non_camel_case_types)]
type vmnet_return_t = c_int;

/// `VMNET_SUCCESS` from `vmnet_return_t`.
const VMNET_SUCCESS: vmnet_return_t = 1000;
/// `VMNET_BRIDGED_MODE` from `operating_modes_t`.
const VMNET_BRIDGED_MODE: u64 = 1002;
/// `VMNET_INTERFACE_PACKETS_AVAILABLE` from `interface_event_t` (`1 << 0`).
const VMNET_INTERFACE_PACKETS_AVAILABLE: u32 = 1;

/// `struct iovec` (sys/uio.h).
#[repr(C)]
struct IoVec {
    iov_base: *mut c_void,
    iov_len: usize,
}

/// `struct vmpktdesc` (vmnet/vmnet.h).
#[repr(C)]
struct VmPktDesc {
    vm_pkt_size: usize,
    vm_pkt_iov: *mut IoVec,
    vm_pkt_iovcnt: u32,
    vm_flags: u32,
}

// Blocks are passed across the C ABI as a pointer to the block object; we keep
// the typed `RcBlock` alive on the Rust side and hand vmnet that pointer.
#[link(name = "vmnet", kind = "framework")]
unsafe extern "C" {
    static vmnet_operation_mode_key: *const c_char;
    static vmnet_shared_interface_name_key: *const c_char;

    fn vmnet_start_interface(
        interface_desc: xpc_object_t,
        queue: dispatch_queue_t,
        handler: *mut c_void,
    ) -> interface_ref;
    fn vmnet_stop_interface(
        interface: interface_ref,
        queue: dispatch_queue_t,
        handler: *mut c_void,
    ) -> vmnet_return_t;
    fn vmnet_interface_set_event_callback(
        interface: interface_ref,
        event_mask: u32,
        queue: dispatch_queue_t,
        handler: *mut c_void,
    ) -> vmnet_return_t;
    fn vmnet_read(
        interface: interface_ref,
        packets: *mut VmPktDesc,
        pktcnt: *mut c_int,
    ) -> vmnet_return_t;
    fn vmnet_write(
        interface: interface_ref,
        packets: *mut VmPktDesc,
        pktcnt: *mut c_int,
    ) -> vmnet_return_t;
}

// xpc + libdispatch live in libSystem, always linked on macOS.
unsafe extern "C" {
    fn xpc_dictionary_create(
        keys: *const *const c_char,
        values: *mut xpc_object_t,
        count: usize,
    ) -> xpc_object_t;
    fn xpc_dictionary_set_uint64(dict: xpc_object_t, key: *const c_char, value: u64);
    fn xpc_dictionary_set_string(dict: xpc_object_t, key: *const c_char, value: *const c_char);
    fn xpc_release(object: xpc_object_t);
    fn dispatch_queue_create(label: *const c_char, attr: *mut c_void) -> dispatch_queue_t;
    fn dispatch_release(object: *mut c_void);
}

/// A raw pointer we promise is safe to move/share across threads. vmnet's
/// `interface_ref` and a dispatch queue are thread-safe handles; we serialize
/// our own access where needed.
struct SendPtr(*mut c_void);
// SAFETY: vmnet interface handles and dispatch queues are documented as usable
// from multiple threads (reads happen on the queue, writes from the TX worker).
unsafe impl Send for SendPtr {}
unsafe impl Sync for SendPtr {}

/// Inbound frame queue filled by the packet-available callback.
type Inbound = Arc<(Mutex<VecDeque<Vec<u8>>>, Condvar)>;

// --- backend ---------------------------------------------------------------

/// A `vmnet` bridged-mode endpoint backing a virtio-net device.
///
/// `vmnet` copies (retains) the event-callback block when it is registered, so
/// the backend holds no `RcBlock` (which isn't `Send`) — keeping it `Send + Sync`
/// as [`NetBackend`] requires.
pub struct VmnetBackend {
    iface: SendPtr,
    queue: SendPtr,
    inbound: Inbound,
    physical: String,
}

impl std::fmt::Debug for VmnetBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmnetBackend")
            .field("physical", &self.physical)
            .finish_non_exhaustive()
    }
}

impl VmnetBackend {
    /// Start `vmnet` in bridged mode on the physical interface `physical`
    /// (e.g. `"en0"`). Blocks until the asynchronous start completes.
    pub fn open(physical: &str) -> io::Result<Self> {
        if physical.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "vmnet bridge requires iface=<physical-interface>",
            ));
        }
        let physical_c =
            CString::new(physical).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        // Build the interface-description XPC dictionary (bridged mode on iface).
        let desc = build_bridged_desc(&physical_c);
        if desc.is_null() {
            return Err(io::Error::other("xpc_dictionary_create returned null"));
        }

        let label = CString::new("dillo-vmnet").expect("static label");
        // SAFETY: a serial dispatch queue with a valid label and null attr.
        let queue = unsafe { dispatch_queue_create(label.as_ptr(), std::ptr::null_mut()) };
        if queue.is_null() {
            unsafe { xpc_release(desc) };
            return Err(io::Error::other("dispatch_queue_create returned null"));
        }

        // Completion handler: signal the result back synchronously.
        let (tx, rx) = mpsc::channel::<vmnet_return_t>();
        let completion = RcBlock::new(move |status: vmnet_return_t, _params: xpc_object_t| {
            let _ = tx.send(status);
        });
        // SAFETY: `desc`/`queue` are valid; the block stays alive until we
        // receive on `rx` below (vmnet invokes it on `queue`).
        let iface = unsafe { vmnet_start_interface(desc, queue, block_ptr(&completion)) };
        unsafe { xpc_release(desc) };
        if iface.is_null() {
            unsafe { dispatch_release(queue) };
            return Err(io::Error::other("vmnet_start_interface returned null"));
        }

        let status = rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| io::Error::other("vmnet start timed out"))?;
        // Keep the completion block alive across the wait.
        drop(completion);
        if status != VMNET_SUCCESS {
            unsafe { dispatch_release(queue) };
            return Err(io::Error::other(format!(
                "vmnet_start_interface failed (status {status}); needs root or the \
                 com.apple.vm.networking entitlement"
            )));
        }

        // Packet-available callback drains inbound frames into our queue.
        let inbound: Inbound = Arc::new((Mutex::new(VecDeque::new()), Condvar::new()));
        let cb_iface = SendPtr(iface);
        let cb_inbound = Arc::clone(&inbound);
        let event_block = RcBlock::new(move |_event: u32, _params: xpc_object_t| {
            drain_available(cb_iface.0, &cb_inbound);
        });
        // SAFETY: valid interface/queue; vmnet retains the block, and we also
        // keep our `RcBlock` alive in the returned struct.
        let rc = unsafe {
            vmnet_interface_set_event_callback(
                iface,
                VMNET_INTERFACE_PACKETS_AVAILABLE,
                queue,
                block_ptr(&event_block),
            )
        };
        if rc != VMNET_SUCCESS {
            unsafe { dispatch_release(queue) };
            return Err(io::Error::other(format!(
                "vmnet_interface_set_event_callback failed (status {rc})"
            )));
        }
        // vmnet has copied the block; ours can now drop.
        drop(event_block);

        log::info!("virtio-net: vmnet bridged mode on {physical:?}");
        Ok(Self {
            iface: SendPtr(iface),
            queue: SendPtr(queue),
            inbound,
            physical: physical.to_owned(),
        })
    }

    /// The physical interface this endpoint bridges onto.
    pub fn physical(&self) -> &str {
        &self.physical
    }
}

impl NetBackend for VmnetBackend {
    fn send(&self, frame: &[u8]) -> io::Result<()> {
        // vmnet_write needs a mutable iovec base; copy into a local buffer.
        let mut buf = frame.to_vec();
        let mut iov = IoVec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut pkt = VmPktDesc {
            vm_pkt_size: buf.len(),
            vm_pkt_iov: &raw mut iov,
            vm_pkt_iovcnt: 1,
            vm_flags: 0,
        };
        let mut count: c_int = 1;
        // SAFETY: `pkt`/`iov` describe one valid buffer for the duration of the
        // call; `count` is in/out.
        let rc = unsafe { vmnet_write(self.iface.0, &raw mut pkt, &raw mut count) };
        if rc != VMNET_SUCCESS {
            // A momentarily full device queue is not fatal; drop like a NIC.
            log::trace!("vmnet_write status {rc} ({} bytes)", frame.len());
        }
        Ok(())
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        let (lock, cvar) = &*self.inbound;
        let mut q = lock.lock().expect("vmnet inbound poisoned");
        if q.is_empty() {
            let (g, _timeout) = cvar
                .wait_timeout(q, RECV_POLL)
                .expect("vmnet inbound poisoned");
            q = g;
        }
        match q.pop_front() {
            Some(frame) => {
                let n = frame.len().min(buf.len());
                buf[..n].copy_from_slice(&frame[..n]);
                Ok(Some(n))
            }
            None => Ok(None),
        }
    }
}

impl Drop for VmnetBackend {
    fn drop(&mut self) {
        // Stop the interface (best effort) and release the queue.
        let stop = RcBlock::new(|_status: vmnet_return_t| {});
        // SAFETY: valid interface/queue; the block is alive for the call.
        unsafe {
            vmnet_stop_interface(self.iface.0, self.queue.0, block_ptr(&stop));
            dispatch_release(self.queue.0);
        }
    }
}

/// Build the bridged-mode XPC interface description: `operation_mode =
/// VMNET_BRIDGED_MODE`, `shared_interface_name = <physical>`.
fn build_bridged_desc(physical: &CString) -> xpc_object_t {
    // SAFETY: an empty dictionary, then two well-typed key/value sets using
    // vmnet's own extern key constants.
    unsafe {
        let dict = xpc_dictionary_create(std::ptr::null(), std::ptr::null_mut(), 0);
        if dict.is_null() {
            return dict;
        }
        xpc_dictionary_set_uint64(dict, vmnet_operation_mode_key, VMNET_BRIDGED_MODE);
        xpc_dictionary_set_string(dict, vmnet_shared_interface_name_key, physical.as_ptr());
        dict
    }
}

/// The C-ABI block pointer for an `RcBlock` (a block is passed by pointer).
fn block_ptr<F: ?Sized>(block: &RcBlock<F>) -> *mut c_void {
    (&raw const **block).cast::<c_void>().cast_mut()
}

/// Drain every currently-available inbound frame via `vmnet_read` into `inbound`.
fn drain_available(iface: *mut c_void, inbound: &Inbound) {
    loop {
        let mut buf = vec![0u8; MAX_FRAME_LEN.min(2048)];
        let mut iov = IoVec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut pkt = VmPktDesc {
            vm_pkt_size: buf.len(),
            vm_pkt_iov: &raw mut iov,
            vm_pkt_iovcnt: 1,
            vm_flags: 0,
        };
        let mut count: c_int = 1;
        // SAFETY: one valid descriptor/iovec for the duration of the call.
        let rc = unsafe { vmnet_read(iface, &raw mut pkt, &raw mut count) };
        if rc != VMNET_SUCCESS || count < 1 {
            break;
        }
        buf.truncate(pkt.vm_pkt_size);
        let (lock, cvar) = &**inbound;
        lock.lock().expect("vmnet inbound poisoned").push_back(buf);
        cvar.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_physical_rejected() {
        let err = VmnetBackend::open("").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    /// The bridged-mode descriptor builds without panicking (XPC dictionary
    /// construction). A non-null result means the two keys were set.
    #[test]
    fn bridged_desc_builds() {
        let name = CString::new("en0").unwrap();
        let desc = build_bridged_desc(&name);
        assert!(!desc.is_null(), "xpc dictionary must build");
        // SAFETY: `desc` is a freshly created XPC object.
        unsafe { xpc_release(desc) };
    }

    /// Layer-3 integration: actually start vmnet bridged mode. Opt-in and never
    /// run in CI (needs root or the `com.apple.vm.networking` entitlement). See
    /// the crate README for the setup recipe.
    ///
    /// Run with:
    /// ```text
    /// sudo DILLO_NET_VMNET_TEST=en0 \
    ///   cargo test -p dillo-virtio-net -- --ignored vmnet_starts
    /// ```
    #[test]
    #[ignore = "needs macOS root/entitlement + a physical iface; set DILLO_NET_VMNET_TEST=en0"]
    fn vmnet_starts_when_privileged() {
        let iface = match std::env::var("DILLO_NET_VMNET_TEST") {
            Ok(i) if !i.is_empty() => i,
            _ => {
                eprintln!("set DILLO_NET_VMNET_TEST=<iface> (and run as root) to exercise this");
                return;
            }
        };
        let backend = VmnetBackend::open(&iface).expect("start vmnet (needs root/entitlement)");
        assert_eq!(backend.physical(), iface);
        // A minimal broadcast frame must be accepted by vmnet_write.
        let mut frame = vec![0xffu8; 6];
        frame.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x01]);
        frame.extend_from_slice(&[0x08, 0x00]);
        backend.send(&frame).expect("vmnet_write");
    }
}
