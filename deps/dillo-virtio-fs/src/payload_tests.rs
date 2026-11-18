// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use dillo_machine::memory::{MappedSharedMemory, SharedAccess};
use dillo_virtio::{SharedQueueMemory, SharedVirtioMemory};
use std::sync::atomic::{AtomicUsize, Ordering};
use vm_memory::{Bytes, GuestMemoryMmap};

const TAIL: u64 = 0x001f_0000;
const REPLY: u64 = 0x4000;

fn request(opcode: u32, unique: u64, node: u64, args: &[u8]) -> Vec<u8> {
    let mut input = vec![0; 40];
    input[..4].copy_from_slice(&((40 + args.len()) as u32).to_le_bytes());
    input[4..8].copy_from_slice(&opcode.to_le_bytes());
    input[8..16].copy_from_slice(&unique.to_le_bytes());
    input[16..24].copy_from_slice(&node.to_le_bytes());
    input.extend_from_slice(args);
    input
}

fn mkdir() -> Vec<u8> {
    request(9, 73, 1, &[0xed, 1, 0, 0, 0, 0, 0, 0, b'x', 0])
}

struct Backend {
    fs: MapFs,
    mutations: AtomicUsize,
    failure: Option<std::io::ErrorKind>,
}

impl Backend {
    fn new() -> Self {
        Self {
            fs: MapFs::new().with_file("file", "data"),
            mutations: AtomicUsize::new(0),
            failure: None,
        }
    }
}

impl FsBackend for Backend {
    fn stat(&self, path: &std::path::Path) -> std::io::Result<Attr> {
        self.fs.stat(path)
    }
    fn readdir(&self, path: &std::path::Path) -> std::io::Result<Vec<DirEntry>> {
        self.fs.readdir(path)
    }
    fn read(&self, path: &std::path::Path, offset: u64, size: u32) -> std::io::Result<Vec<u8>> {
        self.fs.read(path, offset, size)
    }
    fn readlink(&self, path: &std::path::Path) -> std::io::Result<Vec<u8>> {
        self.fs.readlink(path)
    }
    fn mkdir(&self, _: &std::path::Path, _: u32) -> std::io::Result<Attr> {
        self.mutations.fetch_add(1, Ordering::Relaxed);
        if let Some(error) = self.failure {
            return Err(error.into());
        }
        self.fs.stat(std::path::Path::new(""))
    }
}

#[derive(Clone, Copy)]
enum Fault {
    Short,
    RefusedAfterCopy,
    Backing,
    Unsupported,
    OversizedCount,
    HeaderOnly(usize),
}

struct PayloadMemory {
    inner: Arc<dyn VirtioMemory>,
    address: u64,
    fault: Fault,
    reads: Mutex<Vec<usize>>,
}

impl VirtioMemory for PayloadMemory {
    fn read(&self, address: GuestAddress, data: &mut [u8]) -> Result<usize, VirtioMemoryError> {
        if address.0 != self.address {
            return self.inner.read(address, data);
        }
        self.reads.lock().unwrap().push(data.len());
        match self.fault {
            Fault::HeaderOnly(limit) if data.len() <= limit => self.inner.read(address, data),
            Fault::HeaderOnly(_) => {
                Err(SharedMemoryError::Backing("irrelevant body read".into()).into())
            }
            Fault::Short => {
                let n = data.len() - 1;
                self.inner.read(address, &mut data[..n])
            }
            Fault::RefusedAfterCopy => {
                self.inner.read(address, data)?;
                Err(SharedMemoryError::AccessDenied.into())
            }
            Fault::Backing => Err(SharedMemoryError::Backing("lost payload backing".into()).into()),
            Fault::Unsupported => Err(SharedMemoryError::Unsupported.into()),
            Fault::OversizedCount => Ok(data.len() + 1),
        }
    }
    fn write(&self, address: GuestAddress, data: &[u8]) -> Result<usize, VirtioMemoryError> {
        self.inner.write(address, data)
    }
}

struct Fixture {
    mem: GuestMemoryMmap,
    queue: Arc<Mutex<Queue>>,
    metadata: Arc<dyn QueueMemory>,
    payload: Arc<dyn VirtioMemory>,
    state: Arc<Mutex<FsState>>,
    backend: Backend,
    posted: u16,
    notifications: Arc<AtomicUsize>,
    interrupt: Interrupt,
}

impl Fixture {
    fn new() -> Self {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x0020_0000)]).unwrap();
        let shared = Arc::new(MappedSharedMemory::for_guest_memory(
            mem.clone(),
            SharedAccess::ReadWrite,
        ));
        let metadata = Arc::new(SharedQueueMemory::new(vec![shared.clone()]));
        let payload = Arc::new(SharedVirtioMemory::new(vec![shared]));
        let mut queue = Queue::new(16);
        queue.ready = true;
        queue.desc_table = GuestAddress(0x100);
        queue.avail_ring = GuestAddress(0x1000);
        queue.used_ring = GuestAddress(0x2000);
        let notifications = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&notifications);
        Self {
            mem,
            queue: Arc::new(Mutex::new(queue)),
            metadata,
            payload,
            state: Arc::new(Mutex::new(FsState::new(false))),
            backend: Backend::new(),
            posted: 0,
            notifications,
            interrupt: Interrupt::from_fn(move || {
                count.fetch_add(1, Ordering::Relaxed);
            }),
        }
    }
    fn post(&mut self, input: &[u8], tail: Option<(u64, u32)>, reply_len: u32) {
        let head = self.posted * 3;
        let input_addr = 0x5000 + u64::from(self.posted) * 0x100;
        self.mem
            .write_slice(input, GuestAddress(input_addr))
            .unwrap();
        self.mem
            .write_slice(
                &[0xa5; 16],
                GuestAddress(REPLY + u64::from(self.posted) * 0x100),
            )
            .unwrap();
        tests::write_desc(
            &self.mem,
            GuestAddress(0x100),
            u64::from(head),
            input_addr,
            input.len() as u32,
            1,
            head + 1,
        );
        let reply = if let Some((address, length)) = tail {
            tests::write_desc(
                &self.mem,
                GuestAddress(0x100),
                u64::from(head + 1),
                address,
                length,
                1,
                head + 2,
            );
            head + 2
        } else {
            head + 1
        };
        tests::write_desc(
            &self.mem,
            GuestAddress(0x100),
            u64::from(reply),
            REPLY + u64::from(self.posted) * 0x100,
            reply_len,
            2,
            0,
        );
        self.mem
            .write_obj(head, GuestAddress(0x1004 + 2 * u64::from(self.posted)))
            .unwrap();
        self.posted += 1;
        self.mem
            .write_obj(self.posted, GuestAddress(0x1002))
            .unwrap();
    }
    fn fault(&mut self, address: u64, fault: Fault) -> Arc<PayloadMemory> {
        let memory = Arc::new(PayloadMemory {
            inner: self.payload.clone(),
            address,
            fault,
            reads: Mutex::new(Vec::new()),
        });
        self.payload = memory.clone();
        memory
    }
    fn drain(&self) -> Result<(), QueueError> {
        drain_requests(
            &self.metadata,
            &self.payload,
            &self.queue,
            Some(&self.interrupt),
            &self.state,
            &self.backend,
        )
    }
    fn used_len(&self, index: u64) -> u32 {
        self.mem.read_obj(GuestAddress(0x2008 + 8 * index)).unwrap()
    }
    fn errno(&self, index: u64) -> i32 {
        self.mem
            .read_obj(GuestAddress(REPLY + index * 0x100 + 4))
            .unwrap()
    }
    fn assert_no_mutation(&self) {
        assert_eq!(self.backend.mutations.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn actionable_prefix_is_rejected_after_unmapped_or_short_payload() {
    for short in [false, true] {
        let mut fixture = Fixture::new();
        let mut input = mkdir();
        let declared = input.len() as u32 + 8;
        input[..4].copy_from_slice(&declared.to_le_bytes());
        fixture.post(
            &input,
            Some((if short { TAIL } else { 0x0020_0000 }, 8)),
            16,
        );
        if short {
            fixture.fault(TAIL, Fault::Short);
        }
        fixture.drain().unwrap();
        fixture.assert_no_mutation();
        assert_eq!(fixture.errno(0), -5);
        assert_eq!(fixture.used_len(0), 16);
        assert_eq!(
            fixture
                .mem
                .read_obj::<u64>(GuestAddress(REPLY + 8))
                .unwrap(),
            73
        );
        assert_eq!(fixture.queue.lock().unwrap().next_used.0, 1);
        assert_eq!(fixture.notifications.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn failed_read_bytes_and_incomplete_split_headers_cannot_supply_reply_identity() {
    for split in [false, true] {
        let mut fixture = Fixture::new();
        let input = mkdir();
        if split {
            fixture.post(
                &input[..20],
                Some((0x0020_0000, (input.len() - 20) as u32)),
                16,
            );
        } else {
            fixture.post(&input, None, 16);
            fixture.fault(0x5000, Fault::RefusedAfterCopy);
        }
        fixture.drain().unwrap();
        fixture.assert_no_mutation();
        assert_eq!(fixture.used_len(0), 0);
        assert_eq!(
            fixture.mem.read_obj::<u64>(GuestAddress(REPLY)).unwrap(),
            0xa5a5_a5a5_a5a5_a5a5
        );
    }
}

#[test]
fn cap_rejection_and_frame_length_rejection_never_dispatch_the_prefix() {
    for length in [MAX_REQUEST, MAX_REQUEST + 1] {
        let mut fixture = Fixture::new();
        let mut input = mkdir();
        input.resize(length, 0);
        input[..4].copy_from_slice(&(length as u32).to_le_bytes());
        fixture.post(&input, None, 256);
        fixture.drain().unwrap();
        assert_eq!(
            fixture.backend.mutations.load(Ordering::Relaxed),
            usize::from(length == MAX_REQUEST)
        );
        assert_eq!(
            fixture.errno(0),
            if length == MAX_REQUEST { 0 } else { -22 }
        );
    }
    for delta in [-1, 1] {
        let mut fixture = Fixture::new();
        let mut input = mkdir();
        let declared = u32::try_from(i32::try_from(input.len()).unwrap() + delta).unwrap();
        input[..4].copy_from_slice(&declared.to_le_bytes());
        fixture.post(&input, None, 16);
        fixture.drain().unwrap();
        fixture.assert_no_mutation();
        assert_eq!(fixture.errno(0), -22);
    }
}

#[test]
fn failed_replyless_gather_preserves_nodes_without_synthesizing_a_reply() {
    for opcode in [2, 42, 36] {
        let mut fixture = Fixture::new();
        let lookup = fuse::dispatch(
            &mut fixture.state.lock().unwrap(),
            &fixture.backend,
            &request(1, 1, 1, b"file\0"),
        )
        .unwrap();
        let node = u64::from_le_bytes(lookup[16..24].try_into().unwrap());
        let args = if opcode == 42 {
            let mut batch = vec![0; 8];
            batch[..4].copy_from_slice(&1u32.to_le_bytes());
            batch.extend_from_slice(&node.to_le_bytes());
            batch.extend_from_slice(&1u64.to_le_bytes());
            batch
        } else {
            1u64.to_le_bytes().to_vec()
        };
        let mut input = request(opcode, 73, node, &args);
        let declared = input.len() as u32 + 1;
        input[..4].copy_from_slice(&declared.to_le_bytes());
        fixture.post(&input, Some((0x0020_0000, 1)), 16);
        fixture.drain().unwrap();
        assert_eq!(fixture.used_len(0), 0);
        let attr = fuse::dispatch(
            &mut fixture.state.lock().unwrap(),
            &fixture.backend,
            &request(3, 2, node, &[]),
        )
        .unwrap();
        assert_eq!(i32::from_le_bytes(attr[4..8].try_into().unwrap()), 0);
    }
}

#[test]
fn unexpected_provider_errors_preserve_earlier_completion_and_stop_the_batch() {
    for fault in [Fault::Backing, Fault::Unsupported, Fault::OversizedCount] {
        let mut fixture = Fixture::new();
        fixture.post(&mkdir(), None, 256);
        fixture.post(&mkdir(), Some((TAIL, 8)), 16);
        fixture.post(&mkdir(), None, 256);
        fixture.fault(TAIL, fault);
        let error = fixture.drain().unwrap_err();
        assert!(!error.is_published());
        match fault {
            Fault::OversizedCount => assert!(matches!(
                error,
                QueueError::ReadCount {
                    address: TAIL,
                    requested: 8,
                    returned: 9
                }
            )),
            _ => assert!(matches!(
                error,
                QueueError::Payload {
                    address: TAIL,
                    length: 8,
                    ..
                }
            )),
        }
        assert_eq!(fixture.backend.mutations.load(Ordering::Relaxed), 1);
        assert_eq!(fixture.queue.lock().unwrap().next_avail.0, 2);
        assert_eq!(fixture.queue.lock().unwrap().next_used.0, 1);
        assert_eq!(fixture.notifications.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn rejection_publication_failure_never_dispatches_or_replays() {
    for fail in 0..4 {
        let mut fixture = Fixture::new();
        fixture.queue.lock().unwrap().uses_notif_suppression = true;
        fixture.post(&mkdir(), Some((0x0020_0000, 1)), 16);
        fixture.post(&mkdir(), None, 256);
        fixture.metadata = Arc::new(dillo_virtio::test_support::FaultQueueMemory::new(
            fixture.metadata.clone(),
            fail,
        ));
        let error = fixture.drain().unwrap_err();
        assert!(matches!(error, QueueError::Publication(_)));
        assert_eq!(error.is_published(), fail == 3);
        fixture.assert_no_mutation();
        assert_eq!(fixture.errno(0), -5);
        assert_eq!(fixture.queue.lock().unwrap().next_avail.0, 1);
        assert_eq!(
            fixture.notifications.load(Ordering::Relaxed),
            usize::from(fail == 3)
        );
    }
}

#[test]
fn short_reply_capacity_only_reports_the_bytes_actually_written() {
    for capacity in [0, 8] {
        let mut fixture = Fixture::new();
        fixture.post(&mkdir(), Some((0x0020_0000, 1)), capacity);
        fixture.drain().unwrap();
        fixture.assert_no_mutation();
        assert_eq!(fixture.used_len(0), capacity);
        assert_eq!(fixture.queue.lock().unwrap().next_used.0, 1);
    }
}

#[test]
fn expected_backend_errno_is_a_request_result() {
    for (kind, errno) in [
        (std::io::ErrorKind::NotFound, -2),
        (std::io::ErrorKind::Other, -5),
        (std::io::ErrorKind::ReadOnlyFilesystem, -30),
    ] {
        let mut fixture = Fixture::new();
        fixture.backend.failure = Some(kind);
        fixture.post(&mkdir(), None, 16);
        fixture.drain().unwrap();
        assert_eq!(fixture.backend.mutations.load(Ordering::Relaxed), 1);
        assert_eq!(fixture.errno(0), errno);
        assert_eq!(fixture.used_len(0), 16);
    }
}

#[test]
fn a_complete_request_can_span_a_header_boundary() {
    let mut fixture = Fixture::new();
    let input = mkdir();
    fixture
        .mem
        .write_slice(&input[20..], GuestAddress(TAIL))
        .unwrap();
    fixture.post(&input[..20], Some((TAIL, (input.len() - 20) as u32)), 256);
    fixture.drain().unwrap();
    assert_eq!(fixture.backend.mutations.load(Ordering::Relaxed), 1);
    assert_eq!(fixture.errno(0), 0);
}

#[test]
fn payload_address_overflow_is_a_guest_refusal_without_access_or_dispatch() {
    let mut fixture = Fixture::new();
    fixture.post(&mkdir(), Some((u64::MAX, 2)), 16);
    // Any actual access at the overflowing address would become a fatal
    // provider error, so the successful EIO completion proves early refusal.
    fixture.fault(u64::MAX, Fault::Backing);
    fixture.drain().unwrap();
    fixture.assert_no_mutation();
    assert_eq!(fixture.errno(0), -5);
    assert_eq!(fixture.used_len(0), 16);
}

#[test]
fn oversized_requests_read_only_missing_reply_identity() {
    for prefix in [0, 20, 40] {
        let mut fixture = Fixture::new();
        let input = mkdir();
        let observed = if prefix == 0 {
            fixture.post(&input, None, 16);
            // The supplied allocation only needs its header; reading the
            // advertised oversized body would fail the provider contract.
            fixture
                .mem
                .write_obj((MAX_REQUEST + 1) as u32, GuestAddress(0x108))
                .unwrap();
            fixture.fault(0x5000, Fault::HeaderOnly(40))
        } else {
            fixture
                .mem
                .write_slice(&input[prefix..], GuestAddress(TAIL))
                .unwrap();
            fixture.post(&input[..prefix], Some((TAIL, (MAX_REQUEST + 1) as u32)), 16);
            fixture.fault(TAIL, Fault::HeaderOnly(40 - prefix))
        };
        fixture.drain().unwrap();
        fixture.assert_no_mutation();
        assert_eq!(fixture.errno(0), -22);
        assert_eq!(fixture.used_len(0), 16);
        let expected = if prefix == 40 {
            vec![]
        } else {
            vec![40 - prefix]
        };
        assert_eq!(*observed.reads.lock().unwrap(), expected);
    }
}

#[test]
fn necessary_header_read_failure_is_not_hidden_by_known_oversize() {
    let mut fixture = Fixture::new();
    fixture.post(&mkdir()[..20], Some((TAIL, (MAX_REQUEST + 1) as u32)), 16);
    let observed = fixture.fault(TAIL, Fault::Backing);
    assert!(matches!(
        fixture.drain(),
        Err(QueueError::Payload {
            address: TAIL,
            length: 20,
            source: VirtioMemoryError::Shared(SharedMemoryError::Backing(_)),
        })
    ));
    fixture.assert_no_mutation();
    assert_eq!(*observed.reads.lock().unwrap(), vec![20]);
    assert_eq!(fixture.queue.lock().unwrap().next_used.0, 0);
}
