// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// SPDX-License-Identifier: Apache-2.0

//! A minimal DNS responder for the gateway's DNS alias ([`DNS_IP`]).
//!
//! smoltcp's DNS socket is a *client* resolver, so it can't answer the guest's
//! queries. Instead we parse the guest's query enough to extract the name and
//! record type, resolve it through the **host's own resolver** via
//! [`std::net::ToSocketAddrs`] (no FFI, no privilege, identical on every OS —
//! the slirp model), and synthesize a response. This covers `A`/`AAAA` (the
//! dominant case for a VM reaching the internet); other record types return an
//! empty `NOERROR` (documented scope — no `MX`/`TXT`/`SRV`).
//!
//! `ToSocketAddrs` blocks, and the stack runs on a single thread, so resolution
//! is offloaded to a small worker pool. Workers push finished responses onto a
//! result queue and nudge the stack thread via its mio [`Waker`], which drains
//! and sends them on the next loop iteration. The untrusted *parse* stays on the
//! stack thread (it is the fuzzed surface); only the blocking lookup is offloaded.
//!
//! [`DNS_IP`]: super::DNS_IP

use std::collections::VecDeque;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use mio::Waker;
use smoltcp::wire::IpEndpoint;

/// DNS record type for an IPv4 address.
const QTYPE_A: u16 = 1;
/// DNS record type for an IPv6 address.
const QTYPE_AAAA: u16 = 28;
/// DNS class "Internet".
const QCLASS_IN: u16 = 1;
/// Fixed TTL (seconds) on synthesized answers. Short: the host resolver is the
/// real source of truth and the guest shouldn't cache our synthesized view long.
const ANSWER_TTL: u32 = 30;
/// RCODE: no error.
const RCODE_NOERROR: u8 = 0;
/// RCODE: name does not exist.
const RCODE_NXDOMAIN: u8 = 3;
/// Number of blocking-resolver worker threads.
const WORKERS: usize = 4;
/// Cap on a query's encoded name, so a hostile guest can't make us build an
/// unbounded `String` (DNS names are ≤255 bytes on the wire anyway).
const MAX_NAME_WIRE: usize = 255;

/// A parsed guest DNS query: just what we need to resolve and to echo the
/// question back in the response.
#[derive(Debug, Clone)]
pub(super) struct DnsQuery {
    /// Transaction id, echoed in the response.
    id: u16,
    /// Recursion-desired bit from the query flags (echoed for politeness).
    rd: bool,
    /// The decoded hostname (dotted, no trailing dot), for `ToSocketAddrs`.
    name: String,
    /// QTYPE (A / AAAA / other).
    qtype: u16,
    /// The raw question section (qname + qtype + qclass) to copy verbatim into
    /// the response, avoiding a re-encode.
    question: Vec<u8>,
}

/// Parse a guest DNS query. Returns `None` for anything we won't answer (not a
/// single-question standard query, malformed, compressed qname, oversized).
/// Panic-free and bounds-checked: this runs on guest-controlled bytes.
pub(super) fn parse_query(payload: &[u8]) -> Option<DnsQuery> {
    if payload.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([payload[0], payload[1]]);
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    // QR must be 0 (a query), opcode 0 (standard query).
    if flags & 0x8000 != 0 || (flags >> 11) & 0xF != 0 {
        return None;
    }
    let rd = flags & 0x0100 != 0;
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount != 1 {
        return None;
    }

    // Walk the qname labels starting at offset 12.
    let mut pos = 12;
    let mut name = String::new();
    loop {
        let len = *payload.get(pos)? as usize;
        // Compression pointers (top two bits set) are not expected in a query
        // question; reject rather than chase them.
        if len & 0xC0 != 0 {
            return None;
        }
        pos += 1;
        if len == 0 {
            break; // root label: end of name
        }
        let end = pos.checked_add(len)?;
        let label = payload.get(pos..end)?;
        if !name.is_empty() {
            name.push('.');
        }
        // DNS labels are bytes; keep ASCII, reject anything that isn't a sane
        // hostname character to avoid feeding junk to the resolver.
        for &b in label {
            if !(b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.') {
                return None;
            }
            name.push(b as char);
        }
        pos = end;
        if pos > 12 + MAX_NAME_WIRE {
            return None;
        }
    }
    // QTYPE + QCLASS follow the name.
    let qtype = u16::from_be_bytes([*payload.get(pos)?, *payload.get(pos + 1)?]);
    let qclass = u16::from_be_bytes([*payload.get(pos + 2)?, *payload.get(pos + 3)?]);
    if qclass != QCLASS_IN {
        return None;
    }
    let question = payload.get(12..pos + 4)?.to_vec();
    if name.is_empty() {
        return None;
    }
    Some(DnsQuery {
        id,
        rd,
        name,
        qtype,
        question,
    })
}

/// Build a DNS response: echo the question, append one answer per address whose
/// family matches the QTYPE. `rcode` carries the resolution outcome.
fn synthesize(query: &DnsQuery, addrs: &[IpAddr], rcode: u8) -> Vec<u8> {
    let answers: Vec<&IpAddr> = addrs
        .iter()
        .filter(|a| match query.qtype {
            QTYPE_A => a.is_ipv4(),
            QTYPE_AAAA => a.is_ipv6(),
            _ => false,
        })
        .collect();

    let mut out = Vec::with_capacity(12 + query.question.len() + answers.len() * 16);
    // Header.
    out.extend_from_slice(&query.id.to_be_bytes());
    // Flags: QR=1, RD echoed, RA=1, rcode.
    let mut flags: u16 = 0x8000 | 0x0080;
    if query.rd {
        flags |= 0x0100;
    }
    flags |= rcode as u16 & 0x000F;
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // ancount
    out.extend_from_slice(&0u16.to_be_bytes()); // nscount
    out.extend_from_slice(&0u16.to_be_bytes()); // arcount
    // Question, verbatim.
    out.extend_from_slice(&query.question);
    // Answers. Name is a compression pointer to the question at offset 12.
    for addr in answers {
        out.extend_from_slice(&[0xC0, 0x0C]);
        match addr {
            IpAddr::V4(v4) => {
                out.extend_from_slice(&QTYPE_A.to_be_bytes());
                out.extend_from_slice(&QCLASS_IN.to_be_bytes());
                out.extend_from_slice(&ANSWER_TTL.to_be_bytes());
                out.extend_from_slice(&4u16.to_be_bytes());
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.extend_from_slice(&QTYPE_AAAA.to_be_bytes());
                out.extend_from_slice(&QCLASS_IN.to_be_bytes());
                out.extend_from_slice(&ANSWER_TTL.to_be_bytes());
                out.extend_from_slice(&16u16.to_be_bytes());
                out.extend_from_slice(&v6.octets());
            }
        }
    }
    out
}

/// A job handed to a resolver worker.
struct Job {
    query: DnsQuery,
    client: IpEndpoint,
}

/// A finished response ready to send back to the guest.
pub(super) struct DnsResult {
    pub(super) client: IpEndpoint,
    pub(super) response: Vec<u8>,
}

/// Off-thread DNS resolver: a worker pool that turns parsed queries into
/// response datagrams, handing them back to the stack thread via the [`Waker`].
pub(super) struct Resolver {
    tx: Sender<Job>,
    results: Arc<Mutex<VecDeque<DnsResult>>>,
    _workers: Vec<JoinHandle<()>>,
}

impl Resolver {
    pub(super) fn new(waker: Arc<Waker>) -> Self {
        let (tx, rx) = channel::<Job>();
        let rx = Arc::new(Mutex::new(rx));
        let results = Arc::new(Mutex::new(VecDeque::new()));
        let mut workers = Vec::with_capacity(WORKERS);
        for _ in 0..WORKERS {
            let rx = Arc::clone(&rx);
            let results = Arc::clone(&results);
            let waker = Arc::clone(&waker);
            workers.push(std::thread::spawn(move || {
                loop {
                    // Lock only to dequeue; release before the blocking resolve.
                    let job = {
                        let guard = rx.lock().expect("dns worker rx poisoned");
                        guard.recv()
                    };
                    let Ok(job) = job else {
                        break; // sender dropped: shut down
                    };
                    let response = resolve(&job.query);
                    results
                        .lock()
                        .expect("dns results poisoned")
                        .push_back(DnsResult {
                            client: job.client,
                            response,
                        });
                    let _ = waker.wake();
                }
            }));
        }
        Self {
            tx,
            results,
            _workers: workers,
        }
    }

    /// Submit a parsed query for off-thread resolution.
    pub(super) fn submit(&self, query: DnsQuery, client: IpEndpoint) {
        let _ = self.tx.send(Job { query, client });
    }

    /// Take all responses resolved since the last drain.
    pub(super) fn drain(&self) -> Vec<DnsResult> {
        self.results
            .lock()
            .expect("dns results poisoned")
            .drain(..)
            .collect()
    }
}

/// Resolve one query to a response datagram (runs on a worker thread).
fn resolve(query: &DnsQuery) -> Vec<u8> {
    // Only A/AAAA are answerable via ToSocketAddrs; other types → empty NOERROR.
    if query.qtype != QTYPE_A && query.qtype != QTYPE_AAAA {
        return synthesize(query, &[], RCODE_NOERROR);
    }
    // Port is irrelevant; ToSocketAddrs needs one. Keep only the addresses.
    // `synthesize` filters to the requested family, so a name that resolves but
    // not in the requested family yields an empty NOERROR (the name exists).
    match (query.name.as_str(), 0u16).to_socket_addrs() {
        Ok(addrs) => {
            let ips: Vec<IpAddr> = addrs.map(|s| s.ip()).collect();
            synthesize(query, &ips, RCODE_NOERROR)
        }
        // A failed lookup → NXDOMAIN so the guest gets a definitive answer.
        // (Platforms report this as NotFound/Other/Uncategorized inconsistently,
        // so we don't branch on the kind.)
        Err(_) => synthesize(query, &[], RCODE_NXDOMAIN),
    }
}

/// Fuzz entry point for the untrusted DNS query parser. Must never panic.
#[doc(hidden)]
pub fn fuzz_parse_dns_query(payload: &[u8]) {
    let _ = parse_query(payload);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// A well-formed `A example.com` query (mirrors the harness's hand-rolled
    /// query constant), used to exercise parse + synthesize without a network.
    const QUERY_EXAMPLE_COM: &[u8] = &[
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];

    #[test]
    fn parses_a_query() {
        let q = parse_query(QUERY_EXAMPLE_COM).expect("valid query");
        assert_eq!(q.id, 0x1234);
        assert_eq!(q.name, "example.com");
        assert_eq!(q.qtype, QTYPE_A);
        assert!(q.rd);
    }

    #[test]
    fn synthesize_echoes_id_and_sets_qr() {
        let q = parse_query(QUERY_EXAMPLE_COM).unwrap();
        let resp = synthesize(
            &q,
            &[IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            RCODE_NOERROR,
        );
        assert_eq!(&resp[0..2], &[0x12, 0x34], "id echoed");
        assert_eq!(resp[2] & 0x80, 0x80, "QR set");
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1, "one answer");
        // Answer rdata is the A address at the tail.
        assert_eq!(&resp[resp.len() - 4..], &[93, 184, 216, 34]);
    }

    #[test]
    fn nxdomain_has_no_answers() {
        let q = parse_query(QUERY_EXAMPLE_COM).unwrap();
        let resp = synthesize(&q, &[], RCODE_NXDOMAIN);
        assert_eq!(resp[3] & 0x0F, RCODE_NXDOMAIN, "rcode NXDOMAIN");
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0, "no answers");
    }

    #[test]
    fn rejects_compression_pointer_in_query() {
        // A qname that starts with a compression pointer (0xC0) must be rejected.
        let mut bad = QUERY_EXAMPLE_COM.to_vec();
        bad[12] = 0xC0;
        bad[13] = 0x00;
        assert!(parse_query(&bad).is_none());
    }

    #[test]
    fn never_panics_on_truncation() {
        for len in 0..=QUERY_EXAMPLE_COM.len() {
            fuzz_parse_dns_query(&QUERY_EXAMPLE_COM[..len]);
        }
    }

    #[test]
    fn never_panics_on_garbage() {
        for len in 0..160usize {
            fuzz_parse_dns_query(&vec![0u8; len]);
            fuzz_parse_dns_query(&vec![0xffu8; len]);
            let ramp: Vec<u8> = (0..len).map(|i| (i.wrapping_mul(31) ^ len) as u8).collect();
            fuzz_parse_dns_query(&ramp);
        }
    }
}
