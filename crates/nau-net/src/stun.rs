//! A real [STUN] (RFC 5389) client: message codec plus reflexive-address
//! discovery over UDP.
//!
//! # What upstream v2.5.6 got wrong
//!
//! Upstream `gsn-core/src/nat/mod.rs` was a stand-in, and its release notes said
//! so. The three functions an ICE-style implementation actually depends on
//! returned constants:
//!
//! ```text
//! gather_candidates(&mut self) -> Vec<IceCandidate> { self.local_candidates.clone() } // always empty
//! detect_nat_type(&mut self)   -> NatType          { NatType::PortRestrictedCone }    // constant
//! connect(&mut self, ..)       -> ConnectionState  { ConnectionState::Connected }     // unconditional
//! ```
//!
//! `MeshNode::topology()` then published those constants as *measurements*, and
//! the module's own unit tests asserted the constants, so the suite locked the
//! simulation in. The module was also `#[allow(dead_code)]` with no callers.
//!
//! // upstream v2.5.6 fix: `detect_nat_type` no longer returns a constant. The
//! // value published here comes from the mapped transport address that a real
//! // STUN server reports back (see [`crate::nat`]), and every failure path is a
//! // typed error instead of a fabricated success.
//!
//! # What is real here, and what is not
//!
//! **(a) Real and tested locally.** [`BindingRequest`] and [`BindingResponse`]
//! implement the RFC 5389 wire format: the 20-byte header (14-bit message type,
//! 16-bit length, magic cookie `0x2112A442`, 96-bit transaction id), TLV
//! attributes with 4-byte padding on encode *and* decode, `XOR-MAPPED-ADDRESS`
//! (0x0020) with the IPv4 XOR against the cookie and the IPv6 XOR against
//! cookie閳ユ潰ransaction-id, the legacy `MAPPED-ADDRESS` (0x0001) fallback, and
//! `CHANGE-REQUEST` (0x0003). Every malformed input is a typed [`StunError`],
//! never a panic and never an out-of-bounds index. [`binding_request`] sends a
//! Binding Request over a real UDP socket, with a deadline and a bounded number
//! of attempts, and returns the mapped address the server reported. The test
//! suite runs a real UDP server on `127.0.0.1:0` that speaks this codec.
//!
//! **(b) Not claimed.** Classifying the NAT in front of *this* host requires
//! reaching real STUN servers on the public internet, and it requires at least
//! two servers whose behaviour is trusted. This environment may have no such
//! reachability, so nothing in this crate claims a real-world NAT type: with no
//! reachable server the classifier returns
//! [`MappingBehavior::Unknown`](crate::nat::MappingBehavior::Unknown) /
//! [`FilteringBehavior::Unknown`](crate::nat::FilteringBehavior::Unknown) rather
//! than a guess.
//!
//! **(c) Direction of the change.** This replaces a hard-coded constant with an
//! actual measurement over the wire 閳?it is not a simulation with a nicer name.
//! A caller that cannot reach a STUN server gets `Unknown`/`Err`, never
//! `PortRestrictedCone`/`Connected`.
//!
//! [STUN]: https://www.rfc-editor.org/rfc/rfc5389

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use rand::RngCore;
use tokio::net::UdpSocket;

/// The 32-bit STUN magic cookie fixed by RFC 5389 section 6.
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

/// Length of the fixed STUN header, in bytes (RFC 5389 section 6).
pub const HEADER_BYTES: usize = 20;

/// Length of a STUN transaction id, in bytes (96 bits).
pub const TRANSACTION_ID_BYTES: usize = 12;

/// Attribute type: `MAPPED-ADDRESS` (RFC 5389 section 5.1, legacy).
pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;

/// Attribute type: `CHANGE-REQUEST` (RFC 3489 section 1.2.2, obsoleted by 5389 but
/// still the way to run the filtering tests).
pub const ATTR_CHANGE_REQUEST: u16 = 0x0003;

/// Attribute type: `XOR-MAPPED-ADDRESS` (RFC 5389 section 5.2).
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// Message class `request`, encoded in bits 8 and 4 of the type field.
const CLASS_REQUEST: u16 = 0b00;

/// Message class `success response`.
const CLASS_SUCCESS_RESPONSE: u16 = 0b10;

/// Message class `error response`.
const CLASS_ERROR_RESPONSE: u16 = 0b11;

/// Method `Binding`, encoded in bits 13 and 3-0 of the type field.
const METHOD_BINDING: u16 = 0x001;

/// Address family value `IPv4` (RFC 5389 section 5.2).
const FAMILY_IPV4: u8 = 0x01;

/// Address family value `IPv6`.
const FAMILY_IPV6: u8 = 0x02;

/// How many Binding Requests one [`binding_request`] call may send.
///
/// UDP loses datagrams silently, so a single lost packet would otherwise be
/// reported as "server unreachable". The cap keeps the cost bounded: at most
/// three datagrams leave the host, and the whole call still finishes inside the
/// caller's deadline.
pub const BINDING_REQUEST_ATTEMPTS: u32 = 3;

/// Largest number of value bytes an attribute may declare.
///
/// Guards the decoder against a 16-bit length that would otherwise be used to
/// index far past the buffer.
const MAX_ATTR_VALUE_BYTES: usize = u16::MAX as usize;

/// Largest attribute of a message this decoder will look at. A STUN message
/// that is far larger than this is not something a Binding Request/Response
/// needs, so it is rejected before any traversal.
const MAX_MESSAGE_BYTES: usize = 65_535;

/// Everything that can go wrong while speaking STUN.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StunError {
    /// The buffer ended before the structure it declared.
    #[error("truncated STUN message: {0}")]
    Truncated(&'static str),

    /// The 32-bit magic cookie was not [`MAGIC_COOKIE`].
    #[error("bad STUN magic cookie: {found:#010x}, expected {MAGIC_COOKIE:#010x}")]
    BadMagicCookie {
        /// The cookie actually found in the header.
        found: u32,
    },

    /// The header's declared body length does not fit in the buffer.
    #[error("STUN length field declares {declared} bytes but only {available} are present")]
    LengthOverflow {
        /// The value of the 16-bit length field.
        declared: usize,
        /// Bytes actually available after the header.
        available: usize,
    },

    /// The `XOR-MAPPED-ADDRESS`/`MAPPED-ADDRESS` family byte was neither 1 nor 2.
    #[error("unknown STUN address family: {family}")]
    UnknownAddressFamily {
        /// The family byte as it appeared on the wire.
        family: u8,
    },

    /// An attribute declared a length that does not fit in the message.
    #[error("STUN attribute {attr:#06x} declares {declared} bytes but only {available} remain")]
    BadAttributeLength {
        /// The attribute type that failed to fit.
        attr: u16,
        /// The declared value length.
        declared: usize,
        /// Bytes remaining in the message body.
        available: usize,
    },

    /// The message was well-formed but was not a Binding Success/Error Response.
    #[error("unexpected STUN message type {0:#06x} (expected a Binding Response)")]
    UnexpectedMessageType(u16),

    /// The response's transaction id did not echo the request's.
    ///
    /// This is the anti-spoofing property: an off-path attacker who cannot see
    /// the request cannot guess the 96-bit id, so its datagram is dropped.
    #[error("STUN response transaction id does not match the request; datagram discarded")]
    TransactionIdMismatch,

    /// A well-formed response carried no address attribute.
    #[error("STUN response carries no MAPPED-ADDRESS or XOR-MAPPED-ADDRESS attribute")]
    MissingAddress,

    /// A Binding Response with the `error` class. The code arrives in
    /// `ERROR-CODE` (0x0009), which this module does not decode further.
    #[error("STUN server returned an error response")]
    ErrorResponse,

    /// No datagram arrived within the deadline, after the bounded retries.
    #[error("STUN request to {server} timed out after {budget:?} ({attempts} attempts)")]
    Timeout {
        /// Where the requests were sent.
        server: SocketAddr,
        /// The deadline the whole call was given.
        budget: Duration,
        /// How many datagrams were actually sent.
        attempts: u32,
    },

    /// The UDP socket failed.
    #[error("STUN socket error: {0}")]
    Io(#[from] std::io::Error),
}

/// A 96-bit STUN transaction id.
///
/// Generated from OS entropy by [`TransactionId::generate`]. Two ids colliding
/// would let one server's response be accepted for another server's request, so
/// this must not come from a weak PRNG or a counter.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransactionId(pub [u8; TRANSACTION_ID_BYTES]);

impl TransactionId {
    /// Draw 96 bits from the operating system's entropy source.
    ///
    /// // upstream v2.5.6 fix: upstream had no transaction id at all, so nothing
    /// // tied a response to a request and any datagram counted.
    pub fn generate() -> Self {
        let mut bytes = [0u8; TRANSACTION_ID_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        TransactionId(bytes)
    }

    /// The raw 12 bytes, in wire order.
    pub fn as_bytes(&self) -> &[u8; TRANSACTION_ID_BYTES] {
        &self.0
    }
}

impl std::fmt::Debug for TransactionId {
    /// Rendered as hex; a transaction id is not a secret, but it is easier to
    /// diff two of them when they print as bytes rather than a decimal list.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A STUN address attribute: the transport address a server observed for us.
///
/// Carries the address family, the transport port and the IP address exactly as
/// decoded from `XOR-MAPPED-ADDRESS`, with the XOR already undone.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct XorMappedAddress {
    /// The address family: 1 for IPv4, 2 for IPv6, as it appeared on the wire.
    pub family: u8,
    /// The transport port, after the XOR was removed.
    pub port: u16,
    /// The IP address, after the XOR was removed.
    pub address: IpAddr,
    /// The transaction id this attribute was decoded with (needed because the
    /// IPv6 mask is cookie閳ユ潰ransaction-id).
    pub transaction_id: TransactionId,
}

impl XorMappedAddress {
    /// Build an IPv4 `XOR-MAPPED-ADDRESS` for `addr` and `transaction_id`.
    pub fn ipv4(addr: SocketAddr, transaction_id: TransactionId) -> Result<Self, StunError> {
        match addr {
            SocketAddr::V4(v4) => Ok(Self {
                family: FAMILY_IPV4,
                port: v4.port(),
                address: IpAddr::V4(*v4.ip()),
                transaction_id,
            }),
            SocketAddr::V6(_) => Err(StunError::UnknownAddressFamily { family: 0 }),
        }
    }

    /// Build an IPv6 `XOR-MAPPED-ADDRESS` for `addr` and `transaction_id`.
    pub fn ipv6(addr: SocketAddr, transaction_id: TransactionId) -> Result<Self, StunError> {
        match addr {
            SocketAddr::V6(v6) => Ok(Self {
                family: FAMILY_IPV6,
                port: v6.port(),
                address: IpAddr::V6(*v6.ip()),
                transaction_id,
            }),
            SocketAddr::V4(_) => Err(StunError::UnknownAddressFamily { family: 0 }),
        }
    }

    /// The address as a [`SocketAddr`].
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.address, self.port)
    }

    /// The 22-byte XOR mask for one address family.
    ///
    /// IPv4 uses the magic cookie followed by zeroes; IPv6 uses the cookie
    /// followed by the 12 transaction-id bytes (RFC 5389 section 15.2). Indexed
    /// from the start of the *address*: index `0..2` masks the port, `2..6` the
    /// IPv4 address, and `4..20` the IPv6 address, so the array has to be at
    /// least 20 bytes and is padded to keep the offsets visibly consistent.
    ///
    /// Takes the family and the transaction id explicitly rather than reading
    /// them from `self`: a decoder must be able to build the mask for the family
    /// it is *about to* read, and `self.family` is not set until it has.
    fn mask_for(family: u8, transaction_id: TransactionId) -> [u8; 22] {
        let mut mask = [0u8; 22];
        mask[2..6].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        if family == FAMILY_IPV6 {
            mask[6..18].copy_from_slice(&transaction_id.0);
        }
        mask
    }

    /// The XOR mask for this address's own family.
    fn mask(&self) -> [u8; 22] {
        Self::mask_for(self.family, self.transaction_id)
    }

    /// Number of value bytes this attribute occupies.
    pub fn value_len(&self) -> usize {
        if self.family == FAMILY_IPV6 {
            20
        } else {
            8
        }
    }

    /// Encode the attribute value (the bytes after the type and length).
    ///
    /// The mask is indexed from the start of the *address*, not from the start
    /// of the attribute value: the wire layout is `[reserved, family, port(2),
    /// address(N)]`, so the port XORs against [`Self::mask`] bytes `2..4` and the
    /// address against bytes `2..` (IPv4) or `4..` (IPv6, because the cookie and
    /// the transaction id cover six bytes before the address begins).
    pub fn encode_value(&self) -> Result<Vec<u8>, StunError> {
        let mask = self.mask();
        let mut out = Vec::with_capacity(self.value_len());
        out.push(0);
        out.push(self.family);
        out.extend_from_slice(&(self.port ^ u16::from_be_bytes([mask[2], mask[3]])).to_be_bytes());
        match self.address {
            IpAddr::V4(ip) => {
                let octets = ip.octets();
                for (index, byte) in octets.iter().enumerate() {
                    out.push(byte ^ mask[index + 2]);
                }
            }
            IpAddr::V6(ip) => {
                let octets = ip.octets();
                for (index, byte) in octets.iter().enumerate() {
                    out.push(byte ^ mask[index + 4]);
                }
            }
        }
        Ok(out)
    }

    /// Decode an attribute value with the XOR applied.
    ///
    /// `value` is the raw attribute body; `transaction_id` is the id of the
    /// message that carried it.
    pub fn decode_value(value: &[u8], transaction_id: TransactionId) -> Result<Self, StunError> {
        let family = match value.get(1) {
            Some(byte) => *byte,
            None => {
                return Err(StunError::Truncated(
                    "address attribute is shorter than 2 bytes",
                ))
            }
        };
        let mask = Self::mask_for(family, transaction_id);
        let port_bytes = value.get(2..4).ok_or(StunError::Truncated(
            "address attribute is shorter than 4 bytes",
        ))?;
        let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]])
            ^ u16::from_be_bytes([mask[2], mask[3]]);
        match family {
            FAMILY_IPV4 => {
                let octets = value.get(4..8).ok_or(StunError::Truncated(
                    "IPv4 address attribute is shorter than 8 bytes",
                ))?;
                let mut ip = [0u8; 4];
                for (index, byte) in octets.iter().enumerate() {
                    ip[index] = byte ^ mask[index + 2];
                }
                Ok(Self {
                    family: FAMILY_IPV4,
                    port,
                    address: IpAddr::V4(Ipv4Addr::from(ip)),
                    transaction_id,
                })
            }
            FAMILY_IPV6 => {
                let octets = value.get(4..20).ok_or(StunError::Truncated(
                    "IPv6 address attribute is shorter than 20 bytes",
                ))?;
                let mut ip = [0u8; 16];
                for (index, byte) in octets.iter().enumerate() {
                    ip[index] = byte ^ mask[index + 4];
                }
                Ok(Self {
                    family: FAMILY_IPV6,
                    port,
                    address: IpAddr::V6(Ipv6Addr::from(ip)),
                    transaction_id,
                })
            }
            other => Err(StunError::UnknownAddressFamily { family: other }),
        }
    }
}

impl std::fmt::Debug for XorMappedAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XorMappedAddress")
            .field("family", &self.family)
            .field("addr", &self.socket_addr())
            .finish()
    }
}

/// Assemble the three flag bits of `CHANGE-REQUEST` (RFC 3489 section 1.2.2).
///
/// Both flags are off by default, which produces no attribute at all: an empty
/// `CHANGE-REQUEST` and an absent one mean the same thing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChangeRequest {
    /// Ask the server to answer from a different IP address.
    pub change_ip: bool,
    /// Ask the server to answer from a different port.
    pub change_port: bool,
}

impl ChangeRequest {
    /// The flags that ask for nothing: the server answers from the address the
    /// request was sent to.
    pub const NONE: Self = Self {
        change_ip: false,
        change_port: false,
    };

    /// The flags `0b0000_0110`: answer from a different IP *and* port.
    pub const CHANGE_IP_AND_PORT: Self = Self {
        change_ip: true,
        change_port: true,
    };

    /// The flags `0b0000_0100`: answer from a different IP, same port.
    pub const CHANGE_IP: Self = Self {
        change_ip: true,
        change_port: false,
    };

    /// The flags `0b0000_0010`: answer from the same IP, different port.
    pub const CHANGE_PORT: Self = Self {
        change_ip: false,
        change_port: true,
    };

    /// True when no flag is set, so no attribute needs to be encoded.
    pub fn is_none(&self) -> bool {
        !self.change_ip && !self.change_port
    }

    /// The 4-byte attribute value: 29 zero bits then the two flags.
    ///
    /// RFC 3489 section 11.2.2 numbers the bits from the most significant of the
    /// 32-bit value, so `change IP` is bit 2 and `change port` is bit 1. Getting
    /// this the wrong way round runs the wrong filtering test and reports a
    /// filtering behaviour the NAT does not have.
    pub fn value(&self) -> [u8; 4] {
        let mut flags = 0u8;
        if self.change_ip {
            flags |= 0b0100;
        }
        if self.change_port {
            flags |= 0b0010;
        }
        [0, 0, 0, flags]
    }

    /// Decode the 4-byte attribute value.
    pub fn from_value(value: &[u8]) -> Self {
        let raw = value.get(3).copied().unwrap_or(0);
        Self {
            change_ip: raw & 0b0100 != 0,
            change_port: raw & 0b0010 != 0,
        }
    }
}

/// A legacy, non-XOR address attribute (`MAPPED-ADDRESS`, RFC 5389 section 5.1).
///
/// Kept as a distinct type rather than folded into [`XorMappedAddress`] so that
/// the wire format is explicit: this one carries the transport address in the
/// clear, which is why it leaks to any on-path observer and why RFC 5389
/// replaced it with `XOR-MAPPED-ADDRESS`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MappedAddress {
    /// The address family: 1 for IPv4, 2 for IPv6.
    pub family: u8,
    /// The transport port, in the clear.
    pub port: u16,
    /// The IP address, in the clear.
    pub address: IpAddr,
}

impl MappedAddress {
    /// Build from a socket address.
    pub fn new(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4) => Self {
                family: FAMILY_IPV4,
                port: v4.port(),
                address: IpAddr::V4(*v4.ip()),
            },
            SocketAddr::V6(v6) => Self {
                family: FAMILY_IPV6,
                port: v6.port(),
                address: IpAddr::V6(*v6.ip()),
            },
        }
    }

    /// The address as a [`SocketAddr`].
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.address, self.port)
    }

    /// Encode the attribute value: reserved byte, family, port, address.
    pub fn encode_value(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(20);
        out.push(0);
        out.push(self.family);
        out.extend_from_slice(&self.port.to_be_bytes());
        match self.address {
            IpAddr::V4(ip) => out.extend_from_slice(&ip.octets()),
            IpAddr::V6(ip) => out.extend_from_slice(&ip.octets()),
        }
        out
    }

    /// Decode an attribute value, rejecting a bad family and a short value.
    pub fn decode_value(value: &[u8]) -> Result<Self, StunError> {
        let family = match value.get(1) {
            Some(byte) => *byte,
            None => {
                return Err(StunError::Truncated(
                    "address attribute is shorter than 2 bytes",
                ))
            }
        };
        let port_bytes = value.get(2..4).ok_or(StunError::Truncated(
            "address attribute is shorter than 4 bytes",
        ))?;
        let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
        match family {
            FAMILY_IPV4 => {
                let octets = value.get(4..8).ok_or(StunError::Truncated(
                    "IPv4 address attribute is shorter than 8 bytes",
                ))?;
                let mut ip = [0u8; 4];
                ip.copy_from_slice(octets);
                Ok(Self {
                    family: FAMILY_IPV4,
                    port,
                    address: IpAddr::V4(Ipv4Addr::from(ip)),
                })
            }
            FAMILY_IPV6 => {
                let octets = value.get(4..20).ok_or(StunError::Truncated(
                    "IPv6 address attribute is shorter than 20 bytes",
                ))?;
                let mut ip = [0u8; 16];
                ip.copy_from_slice(octets);
                Ok(Self {
                    family: FAMILY_IPV6,
                    port,
                    address: IpAddr::V6(Ipv6Addr::from(ip)),
                })
            }
            other => Err(StunError::UnknownAddressFamily { family: other }),
        }
    }
}

/// A STUN Binding Request (RFC 5389 section 7.1).
#[derive(Clone, Copy, Debug)]
pub struct BindingRequest {
    transaction_id: TransactionId,
    change_request: ChangeRequest,
}

impl BindingRequest {
    /// A Binding Request with a fresh, OS-derived transaction id and no
    /// `CHANGE-REQUEST`.
    pub fn new() -> Self {
        Self {
            transaction_id: TransactionId::generate(),
            change_request: ChangeRequest::NONE,
        }
    }

    /// A Binding Request with a caller-chosen transaction id (tests, and
    /// reproducing a captured exchange).
    pub fn with_transaction_id(transaction_id: TransactionId) -> Self {
        Self {
            transaction_id,
            change_request: ChangeRequest::NONE,
        }
    }

    /// The same request, additionally carrying `CHANGE-REQUEST` flags.
    pub fn with_change_request(mut self, change_request: ChangeRequest) -> Self {
        self.change_request = change_request;
        self
    }

    /// This request's transaction id.
    pub fn transaction_id(&self) -> TransactionId {
        self.transaction_id
    }

    /// This request's `CHANGE-REQUEST` flags.
    pub fn change_request(&self) -> ChangeRequest {
        self.change_request
    }

    /// Encode to the wire, with 4-byte-aligned padding.
    pub fn encode(&self) -> Result<Vec<u8>, StunError> {
        let mut out = Vec::with_capacity(HEADER_BYTES + 8);
        out.extend_from_slice(&encode_message_type(CLASS_REQUEST, METHOD_BINDING).to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        out.extend_from_slice(self.transaction_id.as_bytes());
        if !self.change_request.is_none() {
            push_attribute(&mut out, ATTR_CHANGE_REQUEST, &self.change_request.value())?;
        }
        set_declared_length(&mut out)?;
        Ok(out)
    }
}

impl Default for BindingRequest {
    /// Same as [`BindingRequest::new`].
    fn default() -> Self {
        Self::new()
    }
}

/// A decoded STUN message, whatever its class.
///
/// Decoding is total: it yields this struct or a typed [`StunError`].
#[derive(Clone, Debug)]
pub struct StunMessage {
    message_type: u16,
    transaction_id: TransactionId,
    change_request: Option<ChangeRequest>,
    mapped_address: Option<MappedAddress>,
    xor_mapped_address: Option<XorMappedAddress>,
}

impl StunMessage {
    /// Decode a message, rejecting anything malformed with a typed error.
    ///
    /// Trailing bytes after the declared body are ignored (some middleboxes
    /// pad); a declared body that does not fit is [`StunError::LengthOverflow`].
    pub fn decode(buffer: &[u8]) -> Result<Self, StunError> {
        if buffer.len() < HEADER_BYTES {
            return Err(StunError::Truncated("fewer than 20 header bytes"));
        }
        if buffer.len() > MAX_MESSAGE_BYTES {
            return Err(StunError::Truncated("message larger than any STUN message"));
        }
        let header = &buffer[..HEADER_BYTES];
        let message_type = u16::from_be_bytes([header[0], header[1]]);
        let declared = u16::from_be_bytes([header[2], header[3]]) as usize;
        let cookie = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
        if cookie != MAGIC_COOKIE {
            return Err(StunError::BadMagicCookie { found: cookie });
        }
        let available = buffer.len() - HEADER_BYTES;
        if declared > available {
            return Err(StunError::LengthOverflow {
                declared,
                available,
            });
        }
        let mut transaction_id = [0u8; TRANSACTION_ID_BYTES];
        transaction_id.copy_from_slice(&header[8..HEADER_BYTES]);
        let transaction_id = TransactionId(transaction_id);

        let body = &buffer[HEADER_BYTES..HEADER_BYTES + declared];
        let mut message = StunMessage {
            message_type,
            transaction_id,
            change_request: None,
            mapped_address: None,
            xor_mapped_address: None,
        };
        let mut offset = 0usize;
        while offset + 4 <= body.len() {
            let attr = u16::from_be_bytes([body[offset], body[offset + 1]]);
            let attr_len = u16::from_be_bytes([body[offset + 2], body[offset + 3]]) as usize;
            if attr_len > MAX_ATTR_VALUE_BYTES {
                return Err(StunError::BadAttributeLength {
                    attr,
                    declared: attr_len,
                    available: body.len() - offset - 4,
                });
            }
            let value_start = offset + 4;
            let value_end =
                value_start
                    .checked_add(attr_len)
                    .ok_or(StunError::BadAttributeLength {
                        attr,
                        declared: attr_len,
                        available: body.len().saturating_sub(value_start),
                    })?;
            if value_end > body.len() {
                return Err(StunError::BadAttributeLength {
                    attr,
                    declared: attr_len,
                    available: body.len() - value_start,
                });
            }
            let value = &body[value_start..value_end];
            match attr {
                ATTR_CHANGE_REQUEST => {
                    message.change_request = Some(ChangeRequest::from_value(value));
                }
                ATTR_XOR_MAPPED_ADDRESS => {
                    message.xor_mapped_address =
                        Some(XorMappedAddress::decode_value(value, transaction_id)?);
                }
                ATTR_MAPPED_ADDRESS => {
                    message.mapped_address = Some(MappedAddress::decode_value(value)?);
                }
                _ => {}
            }
            offset = value_end + padding(attr_len);
        }
        if offset < body.len() && offset + 4 > body.len() {
            // A trailing fragment shorter than an attribute header: reject
            // rather than silently accepting a truncated attribute.
            return Err(StunError::Truncated(
                "attribute header truncated after the previous attribute",
            ));
        }
        Ok(message)
    }

    /// The raw 14-bit message type.
    pub fn message_type(&self) -> u16 {
        self.message_type
    }

    /// This message's transaction id.
    pub fn transaction_id(&self) -> TransactionId {
        self.transaction_id
    }

    /// The decoded `CHANGE-REQUEST` flags, if the attribute was present.
    pub fn change_request(&self) -> Option<ChangeRequest> {
        self.change_request
    }

    /// The decoded legacy `MAPPED-ADDRESS`, if present.
    pub fn mapped_address(&self) -> Option<MappedAddress> {
        self.mapped_address
    }

    /// The decoded `XOR-MAPPED-ADDRESS`, if present.
    pub fn xor_mapped_address(&self) -> Option<XorMappedAddress> {
        self.xor_mapped_address
    }

    /// The 2-bit message class (bits 8 and 4).
    pub fn class(&self) -> u16 {
        ((self.message_type >> 4) & 0x01) | ((self.message_type >> 7) & 0x02)
    }

    /// The 12-bit method (bits 13 and 3-0).
    pub fn method(&self) -> u16 {
        ((self.message_type >> 2) & 0x0F80) | (self.message_type & 0x000F)
    }

    /// True for a Binding Success Response.
    pub fn is_success_response(&self) -> bool {
        self.class() == CLASS_SUCCESS_RESPONSE && self.method() == METHOD_BINDING
    }

    /// True for a Binding Error Response.
    pub fn is_error_response(&self) -> bool {
        self.class() == CLASS_ERROR_RESPONSE && self.method() == METHOD_BINDING
    }
}

/// A Binding Response under construction (tests and, later, a server).
#[derive(Clone, Debug)]
pub struct BindingResponse {
    transaction_id: TransactionId,
    class: u16,
    error_code: Option<u16>,
    error_reason: &'static str,
    mapped_address: Option<XorMappedAddress>,
    legacy_mapped_address: Option<MappedAddress>,
    change_request: Option<ChangeRequest>,
}

impl BindingResponse {
    /// A success response that will carry `XOR-MAPPED-ADDRESS` for `addr`.
    pub fn success(transaction_id: TransactionId, mapped: XorMappedAddress) -> Self {
        Self {
            transaction_id,
            class: CLASS_SUCCESS_RESPONSE,
            error_code: None,
            error_reason: "Error",
            mapped_address: Some(mapped),
            legacy_mapped_address: None,
            change_request: None,
        }
    }

    /// An error response (non-zero class), for tests of the error path.
    pub fn error(transaction_id: TransactionId, code: u16, reason: &'static str) -> Self {
        Self {
            transaction_id,
            class: CLASS_ERROR_RESPONSE,
            error_code: Some(code),
            error_reason: reason,
            mapped_address: None,
            legacy_mapped_address: None,
            change_request: None,
        }
    }

    /// Replace the mapped address this response reports.
    pub fn with_mapped(mut self, mapped: XorMappedAddress) -> Self {
        self.mapped_address = Some(mapped);
        self
    }

    /// Additionally emit a legacy `MAPPED-ADDRESS` attribute.
    pub fn with_legacy_mapped(mut self, addr: SocketAddr) -> Self {
        self.legacy_mapped_address = Some(MappedAddress::new(addr));
        self
    }

    /// Additionally echo `CHANGE-REQUEST` flags (some servers do this).
    pub fn with_change_request(mut self, change_request: ChangeRequest) -> Self {
        self.change_request = Some(change_request);
        self
    }

    /// Encode to the wire, with 4-byte-aligned padding on every attribute.
    pub fn encode(&self) -> Result<Vec<u8>, StunError> {
        let mut out = Vec::with_capacity(HEADER_BYTES + 32);
        out.extend_from_slice(&encode_message_type(self.class, METHOD_BINDING).to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        out.extend_from_slice(self.transaction_id.as_bytes());
        if let Some(mapped) = &self.mapped_address {
            push_attribute(&mut out, ATTR_XOR_MAPPED_ADDRESS, &mapped.encode_value()?)?;
        }
        if let Some(addr) = &self.legacy_mapped_address {
            push_attribute(&mut out, ATTR_MAPPED_ADDRESS, &addr.encode_value())?;
        }
        if let Some(change_request) = self.change_request {
            push_attribute(&mut out, ATTR_CHANGE_REQUEST, &change_request.value())?;
        }
        if let Some(code) = self.error_code {
            let mut value = vec![0u8, 0u8, (code / 100) as u8, (code % 100) as u8];
            value.extend_from_slice(self.error_reason.as_bytes());
            push_attribute(&mut out, 0x0009, &value)?;
        }
        set_declared_length(&mut out)?;
        Ok(out)
    }

    /// The encoded message's transaction id.
    pub fn transaction_id(&self) -> TransactionId {
        self.transaction_id
    }
}

/// A transport address a STUN server reported for us, plus where that report
/// came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReflexiveAddress {
    /// The mapped transport address the server observed.
    pub mapped: SocketAddr,
    /// The server that reported it 閳?i.e. the destination the mapping was
    /// created for. Classifying NAT mapping behaviour means comparing this
    /// field across probes.
    pub source: SocketAddr,
}

/// A full Binding exchange: the reflexive address, the transaction id that
/// authorised it, and the decoded response.
#[derive(Clone, Copy, Debug)]
pub struct BindingReply {
    /// The mapped address and the server that reported it.
    pub reflexive: ReflexiveAddress,
    /// The transaction id the response echoed.
    pub transaction_id: TransactionId,
    /// The address the datagram actually came from (equal to
    /// [`ReflexiveAddress::source`] unless a `CHANGE-REQUEST` was honoured).
    pub response_source: SocketAddr,
}

/// The message type field for a class and the Binding method.
///
/// RFC 5389 section 6 spreads the 14-bit type across the 16-bit field: the
/// method's high 4 bits sit at 9..13, its low 4 bits at 0..4, the class's high
/// bit at 8 and its low bit at 4.
const fn encode_message_type(class: u16, method: u16) -> u16 {
    let method_high = (method & 0x0F80) << 2;
    let method_low = method & 0x000F;
    let class_high = (class & 0x02) << 7;
    let class_low = (class & 0x01) << 4;
    method_high | method_low | class_high | class_low
}

/// Pad an attribute value length up to the next multiple of four (RFC 5389 section 15).
const fn padding(value_len: usize) -> usize {
    (4 - (value_len % 4)) % 4
}

/// Append a padded TLV attribute.
fn push_attribute(out: &mut Vec<u8>, attr: u16, value: &[u8]) -> Result<(), StunError> {
    if value.len() > MAX_ATTR_VALUE_BYTES {
        return Err(StunError::BadAttributeLength {
            attr,
            declared: value.len(),
            available: MAX_ATTR_VALUE_BYTES,
        });
    }
    out.extend_from_slice(&attr.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
    // Zero-fill up to the next 4-byte boundary (`repeat_n` needs Rust 1.82 and
    // this crate's MSRV is 1.75).
    out.resize(out.len() + padding(value.len()), 0);
    Ok(())
}

/// Write the body length into the header's length field.
///
/// Takes a slice because it only needs to read the length and write two bytes;
/// requiring `&mut Vec` would suggest it may reallocate.
fn set_declared_length(out: &mut [u8]) -> Result<(), StunError> {
    let body = out.len().saturating_sub(HEADER_BYTES);
    let declared = u16::try_from(body).map_err(|_| StunError::LengthOverflow {
        declared: body,
        available: MAX_ATTR_VALUE_BYTES,
    })?;
    out[2..4].copy_from_slice(&declared.to_be_bytes());
    Ok(())
}

/// Discover this host's reflexive transport address as seen by `server`.
///
/// Sends a Binding Request from a fresh UDP socket bound to `0.0.0.0:0` and
/// returns the mapped address the server reports. The datagram is re-sent up to
/// [`BINDING_REQUEST_ATTEMPTS`] times, each with a *fresh* transaction id, until
/// the deadline is spent; a response whose transaction id does not match the
/// request that produced it is discarded and the socket keeps waiting.
///
/// Fails with [`StunError::Timeout`] when nothing valid arrives in time, and
/// with the relevant [`StunError`] for a malformed response. It never returns a
/// placeholder address.
///
/// // upstream v2.5.6 fix: upstream's `nat` module had no network call at all
/// // and returned `NatType::PortRestrictedCone` unconditionally. This function
/// // has no success value it can produce without a reply from the server.
pub async fn binding_request(
    server: SocketAddr,
    timeout: Duration,
) -> Result<ReflexiveAddress, StunError> {
    Ok(binding_request_reply(server, ChangeRequest::NONE, timeout)
        .await?
        .reflexive)
}

/// [`binding_request`] without discarding the transaction id, the real datagram
/// source and the `CHANGE-REQUEST` flags; used by [`crate::nat::StunProbe`].
pub(crate) async fn binding_request_reply(
    server: SocketAddr,
    change_request: ChangeRequest,
    timeout: Duration,
) -> Result<BindingReply, StunError> {
    let local: SocketAddr = if server.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    };
    let socket = UdpSocket::bind(local).await?;
    let per_attempt = per_attempt_budget(timeout);
    let attempts = if timeout.is_zero() {
        0
    } else {
        BINDING_REQUEST_ATTEMPTS
    };
    let mut sent = 0u32;
    for _ in 0..attempts {
        sent = sent.saturating_add(1);
        let request = BindingRequest::new().with_change_request(change_request);
        let bytes = request.encode()?;
        // A refusal for a datagram we sent earlier in this loop surfaces here on
        // some platforms (Windows reports ICMP port-unreachable as ECONNRESET on
        // the next socket call), so it means "that attempt failed", not "this
        // socket is broken".
        match socket.send_to(&bytes, server).await {
            Ok(_) => {}
            Err(error) if is_transient_udp(&error) => continue,
            Err(error) => return Err(StunError::Io(error)),
        }
        match exchange_once(&socket, &request, server, per_attempt).await {
            Ok(reply) => return Ok(reply),
            // A lost datagram, a spoofed datagram and a refused port all mean
            // "this attempt produced nothing usable"; the next attempt decides.
            Err(StunError::Io(error)) if is_transient_udp(&error) => continue,
            Err(other) => return Err(other),
        }
    }
    Err(StunError::Timeout {
        server,
        budget: timeout,
        attempts: sent,
    })
}

/// One send/receive round: wait for a datagram, decode it, and accept it only
/// if it echoes `request`'s transaction id.
///
/// A response with a mismatched transaction id is *discarded* and the wait
/// continues, until `window` expires 閳?the anti-spoofing property of RFC 5389.
async fn exchange_once(
    socket: &UdpSocket,
    request: &BindingRequest,
    server: SocketAddr,
    window: Duration,
) -> Result<BindingReply, StunError> {
    let deadline = tokio::time::Instant::now() + window;
    loop {
        let mut buffer = [0u8; 1500];
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(StunError::Timeout {
                server,
                budget: window,
                attempts: 1,
            });
        }
        let (len, from) = match tokio::time::timeout(remaining, socket.recv_from(&mut buffer)).await
        {
            Ok(Ok(received)) => received,
            Ok(Err(error)) => return Err(StunError::Io(error)),
            Err(_) => {
                return Err(StunError::Timeout {
                    server,
                    budget: window,
                    attempts: 1,
                })
            }
        };
        let message = match StunMessage::decode(&buffer[..len]) {
            Ok(message) => message,
            // Garbage on the socket is not this exchange's answer.
            Err(_) => continue,
        };
        if message.transaction_id() != request.transaction_id() {
            continue;
        }
        if message.is_error_response() {
            return Err(StunError::ErrorResponse);
        }
        if !message.is_success_response() {
            return Err(StunError::UnexpectedMessageType(message.message_type()));
        }
        // XOR-MAPPED-ADDRESS is the RFC 5389 form; MAPPED-ADDRESS is the RFC
        // 3489 fallback for servers that never learned to XOR.
        let mapped = match (message.xor_mapped_address(), message.mapped_address()) {
            (Some(xor), _) => xor.socket_addr(),
            (None, Some(plain)) => plain.socket_addr(),
            (None, None) => return Err(StunError::MissingAddress),
        };
        return Ok(BindingReply {
            reflexive: ReflexiveAddress {
                mapped,
                source: server,
            },
            transaction_id: request.transaction_id(),
            response_source: from,
        });
    }
}

/// Split the caller's deadline across [`BINDING_REQUEST_ATTEMPTS`] attempts,
/// never returning zero (a zero-length wait would fail without sending).
fn per_attempt_budget(total: Duration) -> Duration {
    let window = total / BINDING_REQUEST_ATTEMPTS;
    if window.is_zero() {
        Duration::from_millis(1)
    } else {
        window
    }
}

/// Whether a UDP error means "this attempt failed, try again" rather than
/// "this socket is unusable".
///
/// On Windows an ICMP port-unreachable for a previous datagram surfaces as
/// `ConnectionReset` on the *next* socket call, so a probe of a closed port
/// would otherwise be reported as an I/O error instead of a timeout.
fn is_transient_udp(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::WouldBlock
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The RFC 5389 section 6 example framing, with a fixed transaction id so the
    /// bytes are reproducible.
    fn fixed_id() -> TransactionId {
        TransactionId([
            0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
        ])
    }

    /// Deterministic PRNG for the fuzz-ish tests: no dev-dependency, and a
    /// failure is reproducible from the seed alone.
    fn lcg(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *state
    }

    #[test]
    fn a_bare_binding_request_has_the_rfc_framing() {
        let request = BindingRequest::with_transaction_id(fixed_id());
        let bytes = request.encode().expect("encode");
        // 20-byte header, no attributes, so no body at all.
        assert_eq!(bytes.len(), HEADER_BYTES);
        assert_eq!(&bytes[..2], &[0x00, 0x01], "Binding Request type");
        assert_eq!(&bytes[2..4], &[0x00, 0x00], "declared length 0");
        assert_eq!(
            &bytes[4..8],
            &MAGIC_COOKIE.to_be_bytes(),
            "magic cookie 0x2112A442"
        );
        assert_eq!(&bytes[8..20], fixed_id().as_bytes());
        // The first two bits of the type field must be zero.
        assert_eq!(bytes[0] & 0b1100_0000, 0);
    }

    #[test]
    fn binding_request_round_trips_through_decode() {
        let request = BindingRequest::with_transaction_id(fixed_id())
            .with_change_request(ChangeRequest::CHANGE_PORT);
        let bytes = request.encode().expect("encode");
        let decoded = StunMessage::decode(&bytes).expect("decode");
        assert_eq!(decoded.message_type(), 0x0001);
        assert_eq!(decoded.method(), METHOD_BINDING);
        assert_eq!(decoded.class(), CLASS_REQUEST);
        assert_eq!(decoded.transaction_id(), fixed_id());
        let change = decoded.change_request().expect("CHANGE-REQUEST survives");
        assert!(!change.change_ip);
        assert!(change.change_port);
        assert!(!decoded.is_success_response());
        assert!(!decoded.is_error_response());
    }

    #[test]
    fn change_request_encodes_the_rfc_flag_bits() {
        // RFC 3489 section 11.2.2: change IP is bit 2, change port is bit 1.
        assert_eq!(ChangeRequest::CHANGE_IP.value(), [0, 0, 0, 0b0100]);
        assert_eq!(ChangeRequest::CHANGE_PORT.value(), [0, 0, 0, 0b0010]);
        assert_eq!(ChangeRequest::CHANGE_IP_AND_PORT.value(), [0, 0, 0, 0b0110]);
        assert_eq!(ChangeRequest::NONE.value(), [0, 0, 0, 0]);

        let request = BindingRequest::with_transaction_id(fixed_id())
            .with_change_request(ChangeRequest::CHANGE_IP_AND_PORT);
        let bytes = request.encode().expect("encode");
        assert_eq!(bytes.len(), 28, "20 header + 4 TLV header + 4 value");
        assert_eq!(&bytes[20..22], &ATTR_CHANGE_REQUEST.to_be_bytes());
        assert_eq!(&bytes[22..24], &[0x00, 0x04]);
        assert_eq!(&bytes[24..28], &[0, 0, 0, 0b0000_0110]);

        // Round-trip each flag independently, so a swap cannot pass unnoticed.
        // `NONE` emits no attribute at all, so it decodes back to `None` — an
        // absent `CHANGE-REQUEST` and an empty one mean the same thing.
        for flags in [
            ChangeRequest::CHANGE_IP,
            ChangeRequest::CHANGE_PORT,
            ChangeRequest::CHANGE_IP_AND_PORT,
        ] {
            let bytes = BindingRequest::with_transaction_id(fixed_id())
                .with_change_request(flags)
                .encode()
                .expect("encode");
            let decoded = StunMessage::decode(&bytes).expect("decode");
            assert_eq!(decoded.change_request(), Some(flags));
        }
        let none = BindingRequest::with_transaction_id(fixed_id())
            .with_change_request(ChangeRequest::NONE)
            .encode()
            .expect("encode");
        let decoded = StunMessage::decode(&none).expect("decode");
        assert_eq!(decoded.change_request(), None);
        // A malformed short value decodes to "no flags" rather than panicking.
        assert_eq!(ChangeRequest::from_value(&[]), ChangeRequest::NONE);
        assert_eq!(
            ChangeRequest::from_value(&[0, 0, 0, 0b0110]),
            ChangeRequest::CHANGE_IP_AND_PORT
        );
    }

    #[test]
    fn an_empty_change_request_emits_no_attribute() {
        let bytes = BindingRequest::with_transaction_id(fixed_id())
            .with_change_request(ChangeRequest::NONE)
            .encode()
            .expect("encode");
        assert_eq!(bytes.len(), HEADER_BYTES);
        assert!(ChangeRequest::NONE.is_none());
        assert!(!ChangeRequest::CHANGE_PORT.is_none());
    }

    #[test]
    fn xor_mapped_address_round_trips_for_ipv4() {
        let addr: SocketAddr = "203.0.113.7:54321".parse().expect("literal");
        let attribute = XorMappedAddress::ipv4(addr, fixed_id()).expect("v4");
        let value = attribute.encode_value().expect("encode");
        assert_eq!(value.len(), 8, "1 reserved + 1 family + 2 port + 4 ipv4");
        assert_eq!(value[0], 0, "first byte is reserved");
        assert_eq!(value[1], FAMILY_IPV4);
        // The XOR must actually have been applied, byte for byte against the
        // cookie: on the wire 54321 appears as 54321 ^ 0x2112.
        assert_eq!(value[2..4], (54321u16 ^ 0x2112u16).to_be_bytes());
        assert_eq!(
            value[4..8],
            [203 ^ 0x21, 0x12, 113 ^ 0xA4, 7 ^ 0x42],
            "IPv4 XORs against the magic cookie in order 21 12 A4 42"
        );

        let decoded = XorMappedAddress::decode_value(&value, fixed_id()).expect("decode");
        assert_eq!(decoded.family, FAMILY_IPV4);
        assert_eq!(decoded.socket_addr(), addr);
        // A different transaction id must not change the IPv4 interpretation.
        let other = TransactionId([0x5A; TRANSACTION_ID_BYTES]);
        assert_eq!(
            XorMappedAddress::decode_value(&value, other)
                .expect("decode")
                .socket_addr(),
            addr
        );
    }

    #[test]
    fn xor_mapped_address_round_trips_for_ipv6() {
        let addr: SocketAddr = "[2001:db8::dead:beef]:3478".parse().expect("literal");
        let attribute = XorMappedAddress::ipv6(addr, fixed_id()).expect("v6");
        let value = attribute.encode_value().expect("encode");
        assert_eq!(value.len(), 20, "1 + 1 + 2 + 16");
        assert_eq!(value[1], FAMILY_IPV6);
        let decoded = XorMappedAddress::decode_value(&value, fixed_id()).expect("decode");
        assert_eq!(decoded.family, FAMILY_IPV6);
        assert_eq!(decoded.socket_addr(), addr);
    }

    #[test]
    fn the_ipv6_mask_is_the_cookie_followed_by_the_transaction_id() {
        // RFC 5389 section 5.2: IPv6 XORs against cookie || transaction-id, IPv4 only
        // against the cookie. Asking for an IPv4 shape but XOR-ing an IPv6
        // address is exactly the bug this asserts against.
        let addr: SocketAddr = "[2001:db8::1]:1".parse().expect("literal");
        let attribute = XorMappedAddress::ipv6(addr, fixed_id()).expect("v6");
        let mask = attribute.mask();
        assert_eq!(
            &mask[2..6],
            &MAGIC_COOKIE.to_be_bytes(),
            "cookie masks the port and the first two IPv6 bytes"
        );
        assert_eq!(
            &mask[6..18],
            fixed_id().as_bytes(),
            "transaction id masks the rest of the IPv6 address"
        );

        let v4 = XorMappedAddress::ipv4("203.0.113.7:1".parse().expect("literal"), fixed_id())
            .expect("v4");
        let v4_mask = v4.mask();
        assert_eq!(&v4_mask[2..6], &MAGIC_COOKIE.to_be_bytes());
        assert_eq!(
            v4_mask[6..],
            [0u8; 16],
            "an IPv4 mask must not use the transaction id"
        );

        // A different transaction id changes the IPv6 bytes but not the IPv4 ones.
        let other = TransactionId([0x11; TRANSACTION_ID_BYTES]);
        let v6_other = XorMappedAddress::ipv6(addr, other)
            .expect("v6")
            .encode_value()
            .expect("encode");
        let v6_same = attribute.encode_value().expect("encode");
        assert_ne!(v6_other, v6_same);
        let v4_other = XorMappedAddress::ipv4("203.0.113.7:1".parse().expect("literal"), other)
            .expect("v4")
            .encode_value()
            .expect("encode");
        assert_eq!(v4_other, v4.encode_value().expect("encode"));
    }

    #[test]
    fn every_attribute_padding_width_is_aligned() {
        // Value lengths 0..=3 give every possible padding remainder.
        for value_len in 0..4usize {
            let mut out = Vec::new();
            let value = vec![0xABu8; value_len];
            push_attribute(&mut out, 0x8000, &value).expect("push");
            assert_eq!(
                out.len(),
                4 + value_len + padding(value_len),
                "attribute with {value_len} value bytes"
            );
            assert_eq!(out.len() % 4, 0, "attributes are 4-byte aligned");
            assert_eq!(padding(value_len), (4 - value_len % 4) % 4);
        }
        assert_eq!(padding(0), 0);
        assert_eq!(padding(1), 3);
        assert_eq!(padding(2), 2);
        assert_eq!(padding(3), 1);
        assert_eq!(padding(4), 0);
        assert_eq!(padding(5), 3);
    }

    #[test]
    fn padded_attributes_still_decode_to_the_same_values() {
        // CHANGE-REQUEST has a 4-byte value (no padding); a legacy
        // MAPPED-ADDRESS for IPv4 has 8. Force padding by crafting an
        // unknown 3-byte attribute ahead of a real XOR-MAPPED-ADDRESS.
        let id = fixed_id();
        let mapped: SocketAddr = "198.51.100.9:40000".parse().expect("literal");
        let attribute = XorMappedAddress::ipv4(mapped, id).expect("v4");
        let mapped_value = attribute.encode_value().expect("encode");

        let mut body = Vec::new();
        push_attribute(&mut body, 0x8022, &[1, 2, 3]).expect("push unknown");
        assert_eq!(body.len(), 8, "4 TLV + 3 value + 1 padding");
        push_attribute(&mut body, ATTR_XOR_MAPPED_ADDRESS, &mapped_value).expect("push mapped");
        assert_eq!(body.len(), 8 + 12, "8 for the 8-byte value plus its TLV");

        let mut message = Vec::new();
        message.extend_from_slice(&0x0101u16.to_be_bytes());
        message.extend_from_slice(&(body.len() as u16).to_be_bytes());
        message.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        message.extend_from_slice(id.as_bytes());
        message.extend_from_slice(&body);

        let decoded = StunMessage::decode(&message).expect("decode");
        assert_eq!(
            decoded.xor_mapped_address().expect("mapped").socket_addr(),
            mapped,
            "padding must be skipped, not folded into the next attribute"
        );
        assert!(decoded.is_success_response());
    }

    #[test]
    fn a_padded_three_byte_attribute_is_skipped_correctly() {
        // The classic bug: reading the next attribute after a value whose
        // length is not a multiple of four without adding the padding.
        let id = fixed_id();
        let first: SocketAddr = "203.0.113.1:1".parse().expect("literal");
        let second: SocketAddr = "203.0.113.2:2".parse().expect("literal");

        let mut body = Vec::new();
        let first_attribute = XorMappedAddress::ipv4(first, id).expect("v4");
        push_attribute(
            &mut body,
            ATTR_XOR_MAPPED_ADDRESS,
            &first_attribute.encode_value().expect("encode"),
        )
        .expect("push");
        // An unknown attribute with a 6-byte value: 2 bytes of padding.
        push_attribute(&mut body, 0x8023, &[9, 9, 9, 9, 9, 9]).expect("push");
        let second_attribute = XorMappedAddress::ipv4(second, id).expect("v4");
        push_attribute(
            &mut body,
            ATTR_XOR_MAPPED_ADDRESS,
            &second_attribute.encode_value().expect("encode"),
        )
        .expect("push");

        let mut message = Vec::new();
        message.extend_from_slice(&0x0101u16.to_be_bytes());
        message.extend_from_slice(&(body.len() as u16).to_be_bytes());
        message.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        message.extend_from_slice(id.as_bytes());
        message.extend_from_slice(&body);

        let decoded = StunMessage::decode(&message).expect("decode");
        // The decoder keeps the last XOR-MAPPED-ADDRESS it saw, so this proves
        // it reached the second one instead of desynchronising.
        assert_eq!(
            decoded.xor_mapped_address().expect("mapped").socket_addr(),
            second
        );
    }

    #[test]
    fn a_response_round_trips_and_the_legacy_attribute_still_decodes() {
        let id = fixed_id();
        let mapped: SocketAddr = "203.0.113.99:65000".parse().expect("literal");
        let response =
            BindingResponse::success(id, XorMappedAddress::ipv4(mapped, id).expect("v4"))
                .with_legacy_mapped("198.51.100.4:1234".parse().expect("literal"))
                .with_change_request(ChangeRequest::CHANGE_IP);
        let bytes = response.encode().expect("encode");
        let decoded = StunMessage::decode(&bytes).expect("decode");
        assert!(decoded.is_success_response());
        assert_eq!(decoded.transaction_id(), id);
        assert_eq!(
            decoded.xor_mapped_address().expect("xor").socket_addr(),
            mapped
        );
        assert_eq!(
            decoded.mapped_address().expect("legacy").socket_addr(),
            "198.51.100.4:1234".parse().expect("literal"),
            "MAPPED-ADDRESS is not XOR-ed"
        );
        assert_eq!(
            decoded.change_request().expect("flags"),
            ChangeRequest::CHANGE_IP
        );
    }

    #[test]
    fn a_legacy_only_response_is_enough_to_read_the_address() {
        // RFC 5389 servers should send XOR-MAPPED-ADDRESS, but RFC 3489 ones
        // send only MAPPED-ADDRESS; the fallback path must work. The message is
        // assembled by hand so that no XOR attribute is present at all.
        let id = fixed_id();
        let addr: SocketAddr = "192.0.2.55:3478".parse().expect("literal");
        let value = MappedAddress::new(addr).encode_value();
        assert_eq!(value.len(), 8);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x0101u16.to_be_bytes());
        bytes.extend_from_slice(&(4u16 + value.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        bytes.extend_from_slice(id.as_bytes());
        bytes.extend_from_slice(&ATTR_MAPPED_ADDRESS.to_be_bytes());
        bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&value);

        let decoded = StunMessage::decode(&bytes).expect("decode");
        assert!(decoded.is_success_response());
        assert!(decoded.xor_mapped_address().is_none());
        assert_eq!(
            decoded.mapped_address().expect("legacy").socket_addr(),
            addr
        );
    }

    #[test]
    fn a_legacy_sixteen_byte_mapped_address_decodes_as_ipv6() {
        let id = fixed_id();
        let addr: SocketAddr = "[2001:db8::5]:99".parse().expect("literal");
        let value = MappedAddress::new(addr).encode_value();
        assert_eq!(value.len(), 20);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x0101u16.to_be_bytes());
        bytes.extend_from_slice(&(4u16 + value.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        bytes.extend_from_slice(id.as_bytes());
        bytes.extend_from_slice(&ATTR_MAPPED_ADDRESS.to_be_bytes());
        bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&value);

        let decoded = StunMessage::decode(&bytes).expect("decode");
        assert_eq!(
            decoded.mapped_address().expect("legacy").socket_addr(),
            addr
        );
    }

    #[test]
    fn an_error_response_is_recognised() {
        let id = fixed_id();
        let bytes = BindingResponse::error(id, 401, "Unauthorized")
            .encode()
            .expect("encode");
        let decoded = StunMessage::decode(&bytes).expect("decode");
        assert!(decoded.is_error_response());
        assert!(!decoded.is_success_response());
        assert_eq!(decoded.transaction_id(), id);
    }

    #[test]
    fn refuse_a_message_shorter_than_the_header() {
        for len in 0..HEADER_BYTES {
            let error = StunMessage::decode(&vec![0u8; len]).expect_err("too short");
            assert!(
                matches!(error, StunError::Truncated(_)),
                "len {len} gave {error:?}"
            );
        }
    }

    #[test]
    fn refuse_a_bad_magic_cookie() {
        let mut bytes = BindingRequest::with_transaction_id(fixed_id())
            .encode()
            .expect("encode");
        bytes[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        let error = StunMessage::decode(&bytes).expect_err("bad cookie");
        match error {
            StunError::BadMagicCookie { found } => assert_eq!(found, 0xDEAD_BEEF),
            other => panic!("expected BadMagicCookie, got {other:?}"),
        }
    }

    #[test]
    fn refuse_a_declared_length_that_exceeds_the_buffer() {
        let mut bytes = BindingRequest::with_transaction_id(fixed_id())
            .encode()
            .expect("encode");
        bytes[2..4].copy_from_slice(&64u16.to_be_bytes());
        let error = StunMessage::decode(&bytes).expect_err("length overflow");
        match error {
            StunError::LengthOverflow {
                declared,
                available,
            } => {
                assert_eq!(declared, 64);
                assert_eq!(available, 0);
            }
            other => panic!("expected LengthOverflow, got {other:?}"),
        }
        // u16::MAX must not be able to index anywhere.
        bytes[2..4].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(matches!(
            StunMessage::decode(&bytes),
            Err(StunError::LengthOverflow { .. })
        ));
    }

    #[test]
    fn refuse_an_unknown_address_family() {
        let id = fixed_id();
        let mut body = Vec::new();
        push_attribute(
            &mut body,
            ATTR_XOR_MAPPED_ADDRESS,
            &[0, 0x07, 0, 1, 1, 2, 3, 4],
        )
        .expect("push");
        let mut message = Vec::new();
        message.extend_from_slice(&0x0101u16.to_be_bytes());
        message.extend_from_slice(&(body.len() as u16).to_be_bytes());
        message.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        message.extend_from_slice(id.as_bytes());
        message.extend_from_slice(&body);
        match StunMessage::decode(&message) {
            Err(StunError::UnknownAddressFamily { family }) => assert_eq!(family, 0x07),
            other => panic!("expected UnknownAddressFamily, got {other:?}"),
        }
    }

    #[test]
    fn refuse_a_truncated_address_attribute() {
        let id = fixed_id();
        // A declared family with too few address bytes: truncated.
        for (family, value_len) in [
            (FAMILY_IPV4, 0usize),
            (FAMILY_IPV4, 1),
            (FAMILY_IPV4, 2),
            (FAMILY_IPV4, 3),
            (FAMILY_IPV4, 4),
            (FAMILY_IPV4, 7),
            (FAMILY_IPV6, 4),
            (FAMILY_IPV6, 19),
        ] {
            let mut value = vec![0u8; value_len];
            if value_len >= 2 {
                value[1] = family;
            }
            let mut body = Vec::new();
            push_attribute(&mut body, ATTR_XOR_MAPPED_ADDRESS, &value).expect("push");
            let mut message = Vec::new();
            message.extend_from_slice(&0x0101u16.to_be_bytes());
            message.extend_from_slice(&(body.len() as u16).to_be_bytes());
            message.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
            message.extend_from_slice(id.as_bytes());
            message.extend_from_slice(&body);
            let error = StunMessage::decode(&message).expect_err("truncated value");
            assert!(
                matches!(error, StunError::Truncated(_)),
                "family {family} with value len {value_len} gave {error:?}"
            );
        }

        // Too short to even carry a family byte: also truncated, not a panic and
        // not an out-of-bounds index.
        for value_len in [0usize, 1] {
            let mut body = Vec::new();
            push_attribute(&mut body, ATTR_XOR_MAPPED_ADDRESS, &vec![0u8; value_len])
                .expect("push");
            let mut message = Vec::new();
            message.extend_from_slice(&0x0101u16.to_be_bytes());
            message.extend_from_slice(&(body.len() as u16).to_be_bytes());
            message.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
            message.extend_from_slice(id.as_bytes());
            message.extend_from_slice(&body);
            let error = StunMessage::decode(&message).expect_err("truncated value");
            assert!(
                matches!(error, StunError::Truncated(_)),
                "value len {value_len} gave {error:?}"
            );
        }

        // A legible but unsupported family is a *different* typed error.
        let mut body = Vec::new();
        push_attribute(&mut body, ATTR_XOR_MAPPED_ADDRESS, &[0, 0, 0, 0]).expect("push");
        let mut message = Vec::new();
        message.extend_from_slice(&0x0101u16.to_be_bytes());
        message.extend_from_slice(&(body.len() as u16).to_be_bytes());
        message.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        message.extend_from_slice(id.as_bytes());
        message.extend_from_slice(&body);
        assert!(matches!(
            StunMessage::decode(&message),
            Err(StunError::UnknownAddressFamily { family: 0 })
        ));
    }

    #[test]
    fn refuse_an_ipv6_attribute_with_an_ipv4_length() {
        let id = fixed_id();
        let mut body = Vec::new();
        let mut value = vec![0u8, FAMILY_IPV6, 0, 1];
        value.extend_from_slice(&[0u8; 4]);
        push_attribute(&mut body, ATTR_XOR_MAPPED_ADDRESS, &value).expect("push");
        let mut message = Vec::new();
        message.extend_from_slice(&0x0101u16.to_be_bytes());
        message.extend_from_slice(&(body.len() as u16).to_be_bytes());
        message.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        message.extend_from_slice(id.as_bytes());
        message.extend_from_slice(&body);
        assert!(matches!(
            StunMessage::decode(&message),
            Err(StunError::Truncated(_))
        ));
    }

    #[test]
    fn refuse_an_attribute_longer_than_the_message() {
        let id = fixed_id();
        let mut message = Vec::new();
        message.extend_from_slice(&0x0101u16.to_be_bytes());
        message.extend_from_slice(&4u16.to_be_bytes());
        message.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        message.extend_from_slice(id.as_bytes());
        message.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        message.extend_from_slice(&u16::MAX.to_be_bytes());
        match StunMessage::decode(&message) {
            Err(StunError::BadAttributeLength {
                attr,
                declared,
                available,
            }) => {
                assert_eq!(attr, ATTR_XOR_MAPPED_ADDRESS);
                assert_eq!(declared, MAX_ATTR_VALUE_BYTES);
                assert_eq!(available, 0);
            }
            other => panic!("expected BadAttributeLength, got {other:?}"),
        }
    }

    #[test]
    fn refuse_an_attribute_that_runs_past_the_body() {
        let id = fixed_id();
        let mut message = Vec::new();
        message.extend_from_slice(&0x0101u16.to_be_bytes());
        message.extend_from_slice(&8u16.to_be_bytes());
        message.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        message.extend_from_slice(id.as_bytes());
        message.extend_from_slice(&0x8022u16.to_be_bytes());
        message.extend_from_slice(&9u16.to_be_bytes());
        message.extend_from_slice(&[0u8; 4]);
        assert!(matches!(
            StunMessage::decode(&message),
            Err(StunError::BadAttributeLength { .. })
        ));
    }

    #[test]
    fn refuse_a_trailing_fragment_shorter_than_an_attribute() {
        let mut bytes = BindingRequest::with_transaction_id(fixed_id())
            .encode()
            .expect("encode");
        bytes.extend_from_slice(&[0x80, 0x22]);
        bytes[2..4].copy_from_slice(&2u16.to_be_bytes());
        assert!(matches!(
            StunMessage::decode(&bytes),
            Err(StunError::Truncated(_))
        ));
    }

    #[test]
    fn trailing_bytes_after_the_declared_body_are_ignored() {
        let mut bytes = BindingRequest::with_transaction_id(fixed_id())
            .encode()
            .expect("encode");
        bytes.extend_from_slice(&[0xFF; 9]);
        let decoded = StunMessage::decode(&bytes).expect("decode");
        assert_eq!(decoded.transaction_id(), fixed_id());
    }

    #[test]
    fn refuse_a_message_larger_than_any_stun_message() {
        let error =
            StunMessage::decode(&vec![0u8; MAX_MESSAGE_BYTES + 1]).expect_err("absurd length");
        assert!(matches!(error, StunError::Truncated(_)));
    }

    #[test]
    fn random_truncations_never_panic() {
        let id = fixed_id();
        let addr: SocketAddr = "203.0.113.7:54321".parse().expect("literal");
        let valid = BindingResponse::success(id, XorMappedAddress::ipv4(addr, id).expect("v4"))
            .with_legacy_mapped("198.51.100.4:1234".parse().expect("literal"))
            .with_change_request(ChangeRequest::CHANGE_IP_AND_PORT)
            .encode()
            .expect("encode");

        // Every possible truncation of a valid message.
        for len in 0..valid.len() {
            let _ = StunMessage::decode(&valid[..len]);
        }
        // Every possible truncation starting one byte in, so that the header is
        // shifted rather than merely short.
        for len in 0..valid.len() {
            let _ = StunMessage::decode(&valid[1..=len.min(valid.len() - 1)]);
        }

        // Random single-byte corruption, plus random truncations of that.
        let mut state = 0x1234_5678_9ABC_DEF0u64;
        for _ in 0..2000 {
            let mut mutated = valid.clone();
            let index = (lcg(&mut state) as usize) % mutated.len();
            mutated[index] = (lcg(&mut state) & 0xFF) as u8;
            let drop = (lcg(&mut state) as usize) % (mutated.len() + 1);
            let candidate = &mutated[..mutated.len() - drop.min(mutated.len())];
            let _ = StunMessage::decode(candidate);
        }

        // Pure random buffers of every length up to the header plus a bit.
        for len in 0..48usize {
            let mut buffer = vec![0u8; len];
            for byte in buffer.iter_mut() {
                *byte = (lcg(&mut state) & 0xFF) as u8;
            }
            let _ = StunMessage::decode(&buffer);
        }
    }

    #[test]
    fn transaction_ids_come_from_os_entropy_and_do_not_repeat() {
        // Not a statistical test of the entropy source; a regression test
        // against "return a constant", which is the upstream defect.
        let first = TransactionId::generate();
        let second = TransactionId::generate();
        assert_ne!(first, second);
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..64 {
            assert!(seen.insert(TransactionId::generate().0), "collision");
        }
        assert_eq!(first.as_bytes().len(), TRANSACTION_ID_BYTES);
    }

    #[test]
    fn a_mismatched_transaction_id_is_discarded() {
        // This is the anti-spoofing property, exercised through the real
        // exchange loop: a datagram whose id does not echo the request must not
        // complete the exchange.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
            let server_addr = server.local_addr().expect("addr");
            let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
            let request = BindingRequest::new();

            // A spoofed datagram carrying the wrong transaction id.
            let spoofed_id = TransactionId([0u8; TRANSACTION_ID_BYTES]);
            assert_ne!(spoofed_id, request.transaction_id());
            let spoofed = BindingResponse::success(
                spoofed_id,
                XorMappedAddress::ipv4("203.0.113.7:1234".parse().expect("literal"), spoofed_id)
                    .expect("v4"),
            )
            .encode()
            .expect("encode");
            socket
                .send_to(&spoofed, server_addr)
                .await
                .expect("send spoof");

            let reply =
                exchange_once(&socket, &request, server_addr, Duration::from_millis(200)).await;
            match reply {
                Err(StunError::Timeout { .. }) => {}
                other => panic!("a spoofed response was accepted: {other:?}"),
            }
        });
    }

    #[test]
    fn a_matching_transaction_id_completes_the_exchange() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
            let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
            let peer_addr = peer.local_addr().expect("addr");
            let request = BindingRequest::new();
            let mapped: SocketAddr = "203.0.113.7:1234".parse().expect("literal");
            let bytes = BindingResponse::success(
                request.transaction_id(),
                XorMappedAddress::ipv4(mapped, request.transaction_id()).expect("v4"),
            )
            .encode()
            .expect("encode");
            peer.send_to(&bytes, socket.local_addr().expect("addr"))
                .await
                .expect("send");

            let reply = exchange_once(&socket, &request, peer_addr, Duration::from_millis(500))
                .await
                .expect("exchange");
            assert_eq!(reply.reflexive.mapped, mapped);
            assert_eq!(reply.reflexive.source, peer_addr);
            assert_eq!(reply.response_source, peer_addr);
            assert_eq!(reply.transaction_id, request.transaction_id());
        });
    }

    #[test]
    fn a_binding_request_against_a_silent_server_times_out_within_the_deadline() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            // Bound but never read from, so datagrams are dropped rather than
            // refused: this is the portable "nothing replies" case.
            let silent = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
            let addr = silent.local_addr().expect("addr");
            let budget = Duration::from_millis(300);
            let started = std::time::Instant::now();
            let result = binding_request(addr, budget).await;
            let elapsed = started.elapsed();
            match result {
                Err(StunError::Timeout {
                    server, attempts, ..
                }) => {
                    assert_eq!(server, addr);
                    assert!(attempts <= BINDING_REQUEST_ATTEMPTS);
                }
                other => panic!("expected Timeout, got {other:?}"),
            }
            assert!(
                elapsed < Duration::from_secs(2),
                "returned after {elapsed:?}, well past the {budget:?} deadline"
            );
        });
    }

    #[test]
    fn a_zero_deadline_reports_a_timeout_rather_than_succeeding() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let silent = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
            let addr = silent.local_addr().expect("addr");
            assert!(matches!(
                binding_request(addr, Duration::ZERO).await,
                Err(StunError::Timeout { attempts: 0, .. })
            ));
        });
    }

    #[test]
    fn per_attempt_budget_never_returns_zero_and_stays_inside_the_total() {
        let total = Duration::from_millis(300);
        let window = per_attempt_budget(total);
        assert_eq!(window, Duration::from_millis(100));
        assert!(
            window * BINDING_REQUEST_ATTEMPTS <= total,
            "the attempts cannot overrun the deadline"
        );
        // A deadline shorter than one tick per attempt still yields a non-zero
        // window, so the datagram is actually sent.
        let tiny = per_attempt_budget(Duration::from_micros(2));
        assert!(!tiny.is_zero());
        assert!(tiny <= Duration::from_millis(1));
        assert_eq!(per_attempt_budget(Duration::ZERO), Duration::from_millis(1));
    }

    #[test]
    fn message_type_encoding_matches_the_rfc_tables() {
        assert_eq!(encode_message_type(CLASS_REQUEST, METHOD_BINDING), 0x0001);
        assert_eq!(
            encode_message_type(CLASS_SUCCESS_RESPONSE, METHOD_BINDING),
            0x0101
        );
        assert_eq!(
            encode_message_type(CLASS_ERROR_RESPONSE, METHOD_BINDING),
            0x0111
        );
        // Allocate (0x003), class request, must be 0x0003.
        assert_eq!(encode_message_type(CLASS_REQUEST, 0x003), 0x0003);
        // Binding Indication (0x0011) per RFC 5389 section 6's table.
        assert_eq!(encode_message_type(0b01, METHOD_BINDING), 0x0011);
    }
}
