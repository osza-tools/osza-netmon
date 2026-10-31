// SPDX-License-Identifier: GPL-3.0-only

//! Interface discovery and scope derivation (plan §6.2 FR-SC-01…05,
//! task T-101).
//!
//! This layer answers the scope-screen questions of plan §6.2 before any
//! packet is sent:
//!
//! * [`enumerate_interfaces`] — the FR-SC-01 inventory: name, index, MAC,
//!   IPv4 address/prefix, link type, up/running state and the
//!   default-route gateway of every interface.
//! * [`InterfaceInfo::eligibility`] — the FR-SC-03 rules, with a typed
//!   [`IneligibleReason`] so an ineligible interface can be listed with
//!   the reason instead of silently disappearing.
//! * [`InterfaceInfo::class`] — the FR-SC-02 [`InterfaceClass`]
//!   (virtual devices such as `docker*`, `veth*`, `tun*`, `lo` are
//!   labeled `virtual` and rank last).
//! * [`suggest_interface`] — the FR-SC-02 ranking; the default-route
//!   carrier is suggested, else the best eligible interface.
//! * [`parse_routes`] / [`find_default_gateway`] — the total parser for
//!   `/proc/net/route` (plan Appendix E: hexadecimal, **little-endian**
//!   address words) and the default-route lookup.
//! * [`derive_scope`] — FR-SC-04: the scan scope is the selected
//!   interface's own IPv4 network, as an [`Ipv4Net`] whose host math
//!   implements FR-SC-05 and whose caps implement FR-SC-06.
//!
//! Data sources (ADR-017): `getifaddrs(3)` through the `nix` safe wrapper
//! for the interface inventory, `/proc/net/route` through a pure parser
//! for the default gateways. No network I/O of any kind happens here
//! (plan §2.3); a `getifaddrs` call only asks the kernel about the local
//! configuration.
//!
//! All parsing is total (plan SR-02): any input — including a corrupted
//! or hostile `/proc/net/route` — either produces values or is skipped;
//! nothing panics, and no value is repaired silently. The name, index,
//! flags and addresses are read-only kernel facts, so this layer contains
//! no `unsafe` and no capability requirement (ADR-005).

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::net::Ipv4Addr;

use nix::net::if_::InterfaceFlags;
use nix::sys::socket::SockaddrStorage;

use crate::model::ipv4::Ipv4Net;
use crate::model::mac::MacAddr;

/// The kernel's IPv4 routing table (plan Appendix E).
const ROUTE_TABLE_PATH: &str = "/proc/net/route";

/// Upper bound accepted when reading the routing table. A real table has
/// one short line per route; anything beyond this bound is truncated
/// before parsing (plan §1.3: bound all sizes).
const ROUTE_TABLE_MAX_BYTES: u64 = 64 * 1024;

/// `ARPHRD_ETHER` — Ethernet-like, ARP-capable links (wired NICs, Wi-Fi,
/// bridges, veth pairs). FR-SC-03 requires this family for eligibility.
const ARPHRD_ETHER: u16 = 1;

/// `ARPHRD_LOOPBACK` — the software loopback device.
const ARPHRD_LOOPBACK: u16 = 772;

/// `RTF_GATEWAY` — the route leaves through a gateway (plan Appendix E:
/// Flags `0x2` = GATEWAY).
const RTF_GATEWAY: u16 = 0x2;

// ---------------------------------------------------------------------------
// Route table parsing (Appendix E)
// ---------------------------------------------------------------------------

/// One parsed route line from `/proc/net/route` (plan Appendix E).
///
/// Built only by [`parse_routes`]; the fields are private and read
/// through accessors. Address columns are stored as decoded
/// [`Ipv4Addr`] values — the little-endian hex of the file never
/// escapes this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    /// The owning interface (`Iface` column).
    iface: String,
    /// The destination network (`Destination`).
    destination: Ipv4Addr,
    /// The gateway (`Gateway`); `0.0.0.0` when the route is on-link.
    gateway: Ipv4Addr,
    /// Route flags (`Flags`): `0x1` UP, `0x2` GATEWAY (Appendix E).
    flags: u16,
    /// The route metric (`Metric`).
    metric: u32,
    /// The netmask (`Mask`).
    mask: Ipv4Addr,
}

impl RouteEntry {
    /// The owning interface name (`Iface`).
    pub fn iface(&self) -> &str {
        &self.iface
    }

    /// The destination network (`Destination`), `0.0.0.0` for a default
    /// route.
    pub fn destination(&self) -> Ipv4Addr {
        self.destination
    }

    /// The gateway (`Gateway`); `0.0.0.0` when the route is on-link.
    pub fn gateway(&self) -> Ipv4Addr {
        self.gateway
    }

    /// The route flags (`Flags`); `0x1` = UP, `0x2` = GATEWAY.
    pub fn flags(&self) -> u16 {
        self.flags
    }

    /// The route metric (`Metric`).
    pub fn metric(&self) -> u32 {
        self.metric
    }

    /// The netmask (`Mask`).
    pub fn mask(&self) -> Ipv4Addr {
        self.mask
    }

    /// `true` for a default-gateway route: `Destination` and `Mask` are
    /// both `00000000` and the `RTF_GATEWAY` flag (`0x2`) is set
    /// (task card §5.5, plan Appendix E).
    ///
    /// A zero-destination route *without* the gateway flag (an on-link
    /// default) is deliberately not a default *gateway* route.
    pub fn is_default_gateway(&self) -> bool {
        self.destination == Ipv4Addr::UNSPECIFIED
            && self.mask == Ipv4Addr::UNSPECIFIED
            && self.flags & RTF_GATEWAY != 0
    }
}

/// Parses the content of `/proc/net/route` (plan Appendix E).
///
/// The format is `Iface · Destination · Gateway · Flags · RefCnt · Use ·
/// Metric · Mask · MTU · Window · IRTT`; the first line is the header and
/// is skipped. Address and mask columns are hexadecimal, **little-endian**
/// words: `0100A8C0` decodes to `192.168.0.1`. Hex digits of either case
/// are accepted.
///
/// The parser is total (plan SR-02) and tolerant exactly as the task card
/// §5.5 requires:
///
/// * extra whitespace between columns is accepted (any run of Unicode
///   whitespace separates two columns, so CRLF files parse too);
/// * a line with fewer than 11 columns is skipped;
/// * a line where **any** column is not a valid hexadecimal value for its
///   type is skipped;
/// * columns beyond the 11 the kernel defines are ignored;
/// * empty input (or a header-only file) yields an empty vector.
///
/// # Examples
///
/// ```
/// use osza_netmon::net::interfaces::parse_routes;
///
/// let routes = parse_routes(
///     "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n\
///      eth0  00000000    0100A8C0 0003   0      0   100    00000000 0    0      0\n",
/// );
/// // Little-endian: 0100A8C0 is the gateway 192.168.0.1 (Appendix E).
/// assert_eq!(
///     routes.first().map(|r| r.gateway().to_string()),
///     Some("192.168.0.1".to_owned())
/// );
/// ```
pub fn parse_routes(content: &str) -> Vec<RouteEntry> {
    let mut routes = Vec::new();
    for (line_number, line) in content.lines().enumerate() {
        // Line 0 is the header (`Iface Destination …`); the kernel always
        // writes it (plan Appendix E).
        if line_number == 0 {
            continue;
        }
        let mut columns = line.split_whitespace();
        // All 11 columns must be present; a short line is skipped whole.
        let (
            Some(iface),
            Some(destination),
            Some(gateway),
            Some(flags),
            Some(refcnt),
            Some(use_),
            Some(metric),
            Some(mask),
            Some(mtu),
            Some(window),
            Some(irtt),
        ) = (
            columns.next(),
            columns.next(),
            columns.next(),
            columns.next(),
            columns.next(),
            columns.next(),
            columns.next(),
            columns.next(),
            columns.next(),
            columns.next(),
            columns.next(),
        )
        else {
            continue;
        };
        // Every column must be a hexadecimal value of its type — one bad
        // column marks the whole line as not kernel output, and it is
        // skipped. The five columns this layer does not store (RefCnt,
        // Use, MTU, Window, IRTT) are validated as well.
        let (
            Ok(destination),
            Ok(gateway),
            Ok(flags),
            Ok(_refcnt),
            Ok(_use),
            Ok(metric),
            Ok(mask),
            Ok(_mtu),
            Ok(_window),
            Ok(_irtt),
        ) = (
            u32::from_str_radix(destination, 16),
            u32::from_str_radix(gateway, 16),
            u16::from_str_radix(flags, 16),
            u32::from_str_radix(refcnt, 16),
            u32::from_str_radix(use_, 16),
            u32::from_str_radix(metric, 16),
            u32::from_str_radix(mask, 16),
            u32::from_str_radix(mtu, 16),
            u32::from_str_radix(window, 16),
            u32::from_str_radix(irtt, 16),
        )
        else {
            continue;
        };
        routes.push(RouteEntry {
            iface: iface.to_owned(),
            destination: little_endian_to_ipv4(destination),
            gateway: little_endian_to_ipv4(gateway),
            flags,
            metric,
            mask: little_endian_to_ipv4(mask),
        });
    }
    routes
}

/// Returns the default-gateway route of `routes`
/// ([`RouteEntry::is_default_gateway`]).
///
/// When several default-gateway routes exist, the one with the lowest
/// metric wins — the same preference the kernel applies — and a metric
/// tie keeps the first route in file order, so the result is
/// deterministic.
///
/// # Examples
///
/// ```
/// use osza_netmon::net::interfaces::{find_default_gateway, parse_routes};
///
/// let routes = parse_routes(
///     "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n\
///      wlan0 00000000  0100A8C0 0003 0 0 600 00000000 0 0 0\n",
/// );
/// let default = find_default_gateway(&routes);
/// assert_eq!(default.map(|r| r.iface().to_owned()), Some("wlan0".to_owned()));
/// ```
pub fn find_default_gateway(routes: &[RouteEntry]) -> Option<RouteEntry> {
    routes
        .iter()
        .filter(|route| route.is_default_gateway())
        .min_by_key(|route| route.metric)
        .cloned()
}

/// Decodes one `/proc/net/route` address word: the column is a
/// little-endian hexadecimal number, so `0100A8C0` is `192.168.0.1`
/// (plan Appendix E).
fn little_endian_to_ipv4(word: u32) -> Ipv4Addr {
    Ipv4Addr::from(word.swap_bytes())
}

// ---------------------------------------------------------------------------
// Interface classification (FR-SC-02, FR-SC-03)
// ---------------------------------------------------------------------------

/// The link-layer type of an interface (FR-SC-01 "link type"), from the
/// `ARPHRD_*` number the kernel reports for the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkType {
    /// `ARPHRD_ETHER` (1): an Ethernet-like, ARP-capable link — wired
    /// NICs, Wi-Fi radios, bridges and veth pairs all report this type.
    Ethernet,
    /// `ARPHRD_LOOPBACK` (772): the software loopback device.
    Loopback,
    /// Any other hardware type (PPP, IP tunnels, …), kept by its raw
    /// `ARPHRD` number. Never Ethernet-like, so never ARP-capable.
    Other(u16),
}

impl LinkType {
    /// Classifies a raw `ARPHRD` number.
    pub fn from_arphrd(raw: u16) -> Self {
        match raw {
            ARPHRD_ETHER => LinkType::Ethernet,
            ARPHRD_LOOPBACK => LinkType::Loopback,
            other => LinkType::Other(other),
        }
    }

    /// The raw `ARPHRD` number of this link type.
    pub fn raw(&self) -> u16 {
        match self {
            LinkType::Ethernet => ARPHRD_ETHER,
            LinkType::Loopback => ARPHRD_LOOPBACK,
            LinkType::Other(raw) => *raw,
        }
    }

    /// `true` only for [`LinkType::Ethernet`] — the ARP-capable family
    /// FR-SC-03 requires. Loopback and every [`LinkType::Other`] device
    /// are excluded.
    pub fn is_ethernet(&self) -> bool {
        matches!(self, LinkType::Ethernet)
    }
}

/// Why an interface cannot be scanned (FR-SC-03). Ineligible interfaces
/// are listed disabled **with the reason** — the wording below follows
/// the plan §5.4 controlled vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IneligibleReason {
    /// The interface is administratively down (`IFF_UP` is clear).
    NotUp,
    /// The link type is not Ethernet-like, so ARP is not possible on it.
    NotEthernet,
    /// The interface has no IPv4 address.
    NoIpv4Address,
    /// The interface is the loopback device.
    Loopback,
}

impl fmt::Display for IneligibleReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            IneligibleReason::NotUp => "interface is down",
            IneligibleReason::NotEthernet => "not an Ethernet-type link",
            IneligibleReason::NoIpv4Address => "no IPv4 address",
            IneligibleReason::Loopback => "loopback interface",
        };
        f.write_str(text)
    }
}

/// The FR-SC-03 eligibility of an interface for scanning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Eligibility {
    /// Up, Ethernet-type link, IPv4 address present, not loopback.
    Eligible,
    /// Ineligible, with the first failing rule as the reason.
    Ineligible(IneligibleReason),
}

/// The FR-SC-02 classification of an interface by name pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InterfaceClass {
    /// A device that matches none of the virtual name patterns — the
    /// physical NICs (`eth0`, `wlan0`, `enp3s0`, …).
    Physical,
    /// A virtual device: names starting with `docker`, `veth`, `br-`,
    /// `virbr`, `tun`, `tap` or `wg`, and the name `lo` exactly
    /// (task card §5.4). Virtual interfaces rank last and are labeled
    /// `virtual` on the FR-SC screens.
    Virtual,
}

impl fmt::Display for InterfaceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // FR-SC-02: virtual interfaces "are labeled `virtual`".
        let text = match self {
            InterfaceClass::Physical => "physical",
            InterfaceClass::Virtual => "virtual",
        };
        f.write_str(text)
    }
}

// ---------------------------------------------------------------------------
// InterfaceInfo (FR-SC-01)
// ---------------------------------------------------------------------------

/// Everything FR-SC-01 requires to know about one interface.
///
/// All fields are private; read them through the accessors. Values come
/// from [`enumerate_interfaces`] (kernel data, ADR-017) — the only
/// production constructor — and, inside this module's tests, from direct
/// struct literals with synthetic data.
///
/// The derived views — [`class`](InterfaceInfo::class) (FR-SC-02) and
/// [`eligibility`](InterfaceInfo::eligibility) (FR-SC-03) — are computed,
/// never stored, so they cannot disagree with the underlying facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceInfo {
    /// Kernel interface name (`eth0`, `wlan0`, `docker0`, …).
    name: String,
    /// The interface index (`ifindex`); `DeviceKey` keys on it (§5.2).
    index: u32,
    /// The hardware address, when the device reports one that satisfies
    /// the §5.3 sender rules (`lo` reports all-zero and yields `None`).
    mac: Option<MacAddr>,
    /// The interface's own IPv4 address and prefix length.
    ipv4: Option<(Ipv4Addr, u8)>,
    /// The link-layer type.
    link_type: LinkType,
    /// `IFF_UP` — administratively up.
    is_up: bool,
    /// `IFF_RUNNING` — operational (carrier present).
    is_running: bool,
    /// `IFF_LOOPBACK`.
    is_loopback: bool,
    /// The default-route gateway of this interface, when it carries a
    /// default-gateway route (FR-SC-01).
    default_gateway: Option<Ipv4Addr>,
}

impl InterfaceInfo {
    /// The kernel interface name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The interface index (`ifindex`).
    pub fn index(&self) -> u32 {
        self.index
    }

    /// The hardware address, if the device reports a valid one. `None`
    /// for interfaces with no hardware address and for values the §5.3
    /// boundary rules reject (all-zero — e.g. `lo` —, broadcast,
    /// multicast).
    pub fn mac(&self) -> Option<MacAddr> {
        self.mac
    }

    /// The interface's own IPv4 address, if it has one.
    pub fn ipv4(&self) -> Option<Ipv4Addr> {
        self.ipv4.map(|(addr, _)| addr)
    }

    /// The prefix length of the interface's own IPv4 network
    /// (`0..=32`), if it has an IPv4 address.
    pub fn prefix_len(&self) -> Option<u8> {
        self.ipv4.map(|(_, prefix_len)| prefix_len)
    }

    /// The link-layer type (FR-SC-01).
    pub fn link_type(&self) -> LinkType {
        self.link_type
    }

    /// `true` when the interface is administratively up (`IFF_UP`).
    pub fn is_up(&self) -> bool {
        self.is_up
    }

    /// `true` when the interface is operationally running
    /// (`IFF_RUNNING` — a carrier is present). Informational for the
    /// FR-SC-03 rules, which key on [`is_up`](Self::is_up).
    pub fn is_running(&self) -> bool {
        self.is_running
    }

    /// `true` for the loopback device (`IFF_LOOPBACK`).
    pub fn is_loopback(&self) -> bool {
        self.is_loopback
    }

    /// The default-route gateway of this interface, if it carries a
    /// default-gateway route (FR-SC-01). `Some(0.0.0.0)` means the
    /// default route is on-link (no gateway address); `None` means the
    /// interface carries no default route.
    pub fn default_gateway(&self) -> Option<Ipv4Addr> {
        self.default_gateway
    }

    /// `true` when a default-gateway route uses this interface — the
    /// top FR-SC-02 ranking tier.
    pub fn carries_default_route(&self) -> bool {
        self.default_gateway.is_some()
    }

    /// The FR-SC-02 class of the interface, from its name: `docker*`,
    /// `veth*`, `br-*`, `virbr*`, `tun*`, `tap*`, `wg*` and `lo` are
    /// [`InterfaceClass::Virtual`]; every other name is
    /// [`InterfaceClass::Physical`] (task card §5.4).
    pub fn class(&self) -> InterfaceClass {
        let virtual_device = self.name == "lo"
            || self.name.starts_with("docker")
            || self.name.starts_with("veth")
            || self.name.starts_with("br-")
            || self.name.starts_with("virbr")
            || self.name.starts_with("tun")
            || self.name.starts_with("tap")
            || self.name.starts_with("wg");
        if virtual_device {
            InterfaceClass::Virtual
        } else {
            InterfaceClass::Physical
        }
    }

    /// The FR-SC-03 eligibility: up, Ethernet-type link, IPv4 address,
    /// not loopback.
    ///
    /// The checks are applied in a fixed order so the reported reason is
    /// deterministic: loopback first (a categorical exclusion), then
    /// administrative state, then link type, then addressing. `IFF_UP`
    /// is the state FR-SC-03 names; an up interface without carrier
    /// ([`is_running`](Self::is_running) false) stays eligible because
    /// the neighbor-table path still works on it.
    pub fn eligibility(&self) -> Eligibility {
        if self.is_loopback {
            Eligibility::Ineligible(IneligibleReason::Loopback)
        } else if !self.is_up {
            Eligibility::Ineligible(IneligibleReason::NotUp)
        } else if !self.link_type.is_ethernet() {
            Eligibility::Ineligible(IneligibleReason::NotEthernet)
        } else if self.ipv4.is_none() {
            Eligibility::Ineligible(IneligibleReason::NoIpv4Address)
        } else {
            Eligibility::Eligible
        }
    }
}

// ---------------------------------------------------------------------------
// Enumeration (ADR-017 data source) and suggestion (FR-SC-02)
// ---------------------------------------------------------------------------

/// Enumerates the system's network interfaces with every FR-SC-01 field.
///
/// Data source (ADR-017): `getifaddrs(3)` through the `nix` safe wrapper
/// gives the name, index, flags (`IFF_UP`/`IFF_RUNNING`/`IFF_LOOPBACK`),
/// hardware address, `ARPHRD` link type (the `AF_PACKET` record) and the
/// IPv4 address with its netmask (the `AF_INET` record); the bounded
/// [`parse_routes`] read of `/proc/net/route` adds each interface's
/// default-route gateway. No socket is opened and no packet is sent.
///
/// The result is sorted by interface name so the list is deterministic.
/// If the kernel reports no interfaces at all (or a source cannot be
/// read), the result is empty — an interface-less machine has nothing to
/// suggest; callers render that state, they do not panic on it.
pub fn enumerate_interfaces() -> Vec<InterfaceInfo> {
    let routes = read_route_table();
    let ifaddrs = match nix::ifaddrs::getifaddrs() {
        Ok(ifaddrs) => ifaddrs,
        // Without the interface inventory there is nothing to report.
        Err(_) => return Vec::new(),
    };

    let mut raws: Vec<RawInterface> = Vec::new();
    for ifaddr in ifaddrs {
        // Find (or open) the accumulator of this interface; `position`
        // plus `get_mut` keeps the loop free of indexing (SR-02).
        let position = match raws
            .iter()
            .position(|raw| raw.name == ifaddr.interface_name)
        {
            Some(position) => position,
            None => {
                let position = raws.len();
                raws.push(RawInterface::new(&ifaddr.interface_name, ifaddr.flags));
                position
            }
        };
        let Some(raw) = raws.get_mut(position) else {
            // Unreachable by construction (pushed above); kept total.
            continue;
        };
        // Link-layer record (AF_PACKET): index, hardware address and
        // ARPHRD link type.
        if let Some(link) = ifaddr
            .address
            .as_ref()
            .and_then(SockaddrStorage::as_link_addr)
        {
            if let Ok(index) = u32::try_from(link.ifindex()) {
                raw.index = index;
            }
            raw.hatype = link.hatype();
            if let Some(octets) = link.addr() {
                // §5.3 boundary rules: all-zero (e.g. `lo`), broadcast
                // and multicast addresses are rejected, not repaired.
                raw.mac = MacAddr::from_octets(octets).ok();
            }
        }
        // Internet-layer record (AF_INET): the interface's own address
        // and prefix. The first address wins — FR-SC-01 models one
        // IPv4/prefix per interface.
        if raw.ipv4.is_none()
            && let Some(inet) = ifaddr
                .address
                .as_ref()
                .and_then(SockaddrStorage::as_sockaddr_in)
        {
            let prefix_len = ifaddr
                .netmask
                .as_ref()
                .and_then(SockaddrStorage::as_sockaddr_in)
                .map(|netmask| u32::from(netmask.ip()).leading_ones() as u8);
            if let Some(prefix_len) = prefix_len {
                raw.ipv4 = Some((inet.ip(), prefix_len));
            }
        }
    }

    let mut interfaces: Vec<InterfaceInfo> = raws
        .into_iter()
        .map(|raw| {
            let default_gateway = default_gateway_of(&raw.name, &routes);
            InterfaceInfo {
                name: raw.name,
                index: raw.index,
                mac: raw.mac,
                ipv4: raw.ipv4,
                link_type: LinkType::from_arphrd(raw.hatype),
                is_up: raw.is_up,
                is_running: raw.is_running,
                is_loopback: raw.is_loopback,
                default_gateway,
            }
        })
        .collect();
    // Deterministic order for the FR-SC screens and for tests.
    interfaces.sort_by(|a, b| a.name.cmp(&b.name));
    interfaces
}

/// Suggests the interface to scan (FR-SC-02): the highest-ranked eligible
/// interface, never an ineligible one.
///
/// Priority order (higher wins):
///
/// 1. eligible and carries a default-gateway route — even a virtual one
///    (a VPN's `tun0` outranks an idle physical link, per FR-SC-02
///    "the one carrying the default route");
/// 2. eligible, physical class;
/// 3. eligible, virtual class.
///
/// Within one tier the interface name decides, so the suggestion is
/// deterministic. `None` when no interface is eligible (or the list is
/// empty).
pub fn suggest_interface(interfaces: &[InterfaceInfo]) -> Option<&InterfaceInfo> {
    interfaces
        .iter()
        .filter(|info| info.eligibility() == Eligibility::Eligible)
        // `min_by` with the tier comparison inverted: the highest FR-SC-02
        // tier becomes the smallest key; within a tier the interface name
        // decides, ascending — so the result is deterministic.
        .min_by(|a, b| {
            ranking_tier(b)
                .cmp(&ranking_tier(a))
                .then_with(|| a.name().cmp(b.name()))
        })
}

/// Derives the scan scope from the interface's own IPv4 network
/// (FR-SC-04): exactly `Ipv4Net::new(address, prefix_len)` of the
/// selected interface — arbitrary or remote ranges never enter here.
///
/// `None` when the interface has no IPv4 address. Host counting and cap
/// enforcement stay on the returned [`Ipv4Net`] (FR-SC-05 host ranges,
/// FR-SC-06 default cap 1,022 hosts with the explicit raised-cap path).
pub fn derive_scope(interface: &InterfaceInfo) -> Option<Ipv4Net> {
    let (addr, prefix_len) = interface.ipv4?;
    // prefix_len is 0..=32 by construction, so `new` cannot fail; `.ok()`
    // keeps this total regardless.
    Ipv4Net::new(addr, prefix_len).ok()
}

/// The FR-SC-02 tier of an eligible interface: 2 = carries a
/// default-gateway route, 1 = physical, 0 = virtual.
fn ranking_tier(info: &InterfaceInfo) -> u8 {
    if info.carries_default_route() {
        2
    } else if info.class() == InterfaceClass::Physical {
        1
    } else {
        0
    }
}

/// The default-route gateway of `iface` in `routes`: the lowest-metric
/// default-gateway route whose interface matches; file order breaks
/// metric ties.
fn default_gateway_of(iface: &str, routes: &[RouteEntry]) -> Option<Ipv4Addr> {
    routes
        .iter()
        .filter(|route| route.iface() == iface && route.is_default_gateway())
        .min_by_key(|route| route.metric)
        .map(|route| route.gateway())
}

/// Reads and parses `/proc/net/route`, bounded by
/// [`ROUTE_TABLE_MAX_BYTES`]. Any failure yields no routes — interfaces
/// then simply carry no default gateway, which the FR-SC-03 list shows.
fn read_route_table() -> Vec<RouteEntry> {
    let Ok(file) = File::open(ROUTE_TABLE_PATH) else {
        return Vec::new();
    };
    let mut content = String::new();
    // Bound the read (plan §1.3): a routing table is a few KiB at most.
    if file
        .take(ROUTE_TABLE_MAX_BYTES)
        .read_to_string(&mut content)
        .is_err()
    {
        return Vec::new();
    }
    parse_routes(&content)
}

/// Per-interface accumulator used while folding the `getifaddrs` stream;
/// becomes an [`InterfaceInfo`] once the whole stream was seen.
struct RawInterface {
    /// Kernel interface name.
    name: String,
    /// `ifindex`; 0 while unknown.
    index: u32,
    /// Validated hardware address, if any.
    mac: Option<MacAddr>,
    /// Raw `ARPHRD` link type; 0 while unknown.
    hatype: u16,
    /// `IFF_UP`.
    is_up: bool,
    /// `IFF_RUNNING`.
    is_running: bool,
    /// `IFF_LOOPBACK`.
    is_loopback: bool,
    /// Own IPv4 address and prefix; the first AF_INET record wins.
    ipv4: Option<(Ipv4Addr, u8)>,
}

impl RawInterface {
    /// A fresh accumulator from the first `getifaddrs` record of the
    /// interface — its flags, which the kernel reports identically on
    /// every record of the same interface.
    fn new(name: &str, flags: InterfaceFlags) -> Self {
        RawInterface {
            name: name.to_owned(),
            index: 0,
            mac: None,
            hatype: 0,
            is_up: flags.contains(InterfaceFlags::IFF_UP),
            is_running: flags.contains(InterfaceFlags::IFF_RUNNING),
            is_loopback: flags.contains(InterfaceFlags::IFF_LOOPBACK),
            ipv4: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ipv4::{ABSOLUTE_MAX_HOSTS, DEFAULT_MAX_HOSTS, Ipv4NetError};
    use crate::model::testing::Lcg;

    /// Header of `/proc/net/route` exactly as the kernel writes it
    /// (plan Appendix E; the kernel pads `Gateway`, `Mask` and beyond
    /// with spaces/tabs — the parser splits on whitespace runs).
    const ROUTE_HEADER: &str =
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT";

    /// A realistic single-LAN table: default route via 192.168.0.1 on
    /// eth0 (metric 100 = hex `64`), the on-link 192.168.0.0/24 route,
    /// and docker0's 172.17.0.0/16 bridge network. All words
    /// little-endian hex, exactly as the kernel writes them.
    const REALISTIC_TABLE: &str = concat!(
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n",
        "eth0\t00000000\t0100A8C0\t0003\t0\t0\t64\t00000000\t0\t0\t0\n",
        "eth0\t0000A8C0\t00000000\t0001\t0\t0\t64\t00FFFFFF\t0\t0\t0\n",
        "docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n",
    );

    /// Builds an eligible physical interface named `name` (Ethernet,
    /// up, running, 192.168.1.130/24, a valid MAC, no default route).
    fn eligible_physical(name: &str) -> InterfaceInfo {
        InterfaceInfo {
            name: name.to_owned(),
            index: 2,
            mac: Some("aa:bb:cc:dd:ee:01".parse().unwrap()),
            ipv4: Some((Ipv4Addr::new(192, 168, 1, 130), 24)),
            link_type: LinkType::Ethernet,
            is_up: true,
            is_running: true,
            is_loopback: false,
            default_gateway: None,
        }
    }

    /// Builds an eligible virtual interface named `name` (Ethernet link
    /// type — bridges and veth pairs report ARPHRD_ETHER).
    fn eligible_virtual(name: &str) -> InterfaceInfo {
        InterfaceInfo {
            name: name.to_owned(),
            index: 4,
            mac: Some("02:42:ac:11:00:01".parse().unwrap()),
            ipv4: Some((Ipv4Addr::new(172, 17, 0, 1), 16)),
            link_type: LinkType::Ethernet,
            is_up: true,
            is_running: true,
            is_loopback: false,
            default_gateway: None,
        }
    }

    /// The loopback device: up, loopback flag, 127.0.0.1/8, no MAC.
    fn loopback_interface() -> InterfaceInfo {
        InterfaceInfo {
            name: "lo".to_owned(),
            index: 1,
            mac: None,
            ipv4: Some((Ipv4Addr::new(127, 0, 0, 1), 8)),
            link_type: LinkType::Loopback,
            is_up: true,
            is_running: true,
            is_loopback: true,
            default_gateway: None,
        }
    }

    // ---- parse_routes (card §7: fixtures, malformed lines, empty input) --

    #[test]
    fn parses_a_realistic_route_table() {
        let routes = parse_routes(REALISTIC_TABLE);
        assert_eq!(routes.len(), 3);

        let default = routes.first().cloned().expect("entry 0");
        assert_eq!(default.iface(), "eth0");
        assert_eq!(default.destination(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(
            default.gateway(),
            Ipv4Addr::new(192, 168, 0, 1), // 0100A8C0 (card §5.5 example)
        );
        assert_eq!(default.flags(), 0x3);
        assert_eq!(default.metric(), 100, "metric is hex 64 = decimal 100");
        assert_eq!(default.mask(), Ipv4Addr::UNSPECIFIED);

        let lan = routes.get(1).cloned().expect("entry 1");
        assert_eq!(lan.iface(), "eth0");
        assert_eq!(lan.destination(), Ipv4Addr::new(192, 168, 0, 0));
        assert_eq!(lan.gateway(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(lan.flags(), 0x1);
        assert_eq!(lan.mask(), Ipv4Addr::new(255, 255, 255, 0));

        let bridge = routes.get(2).cloned().expect("entry 2");
        assert_eq!(bridge.iface(), "docker0");
        assert_eq!(bridge.destination(), Ipv4Addr::new(172, 17, 0, 0));
        assert_eq!(bridge.mask(), Ipv4Addr::new(255, 255, 0, 0));
    }

    #[test]
    fn empty_and_header_only_input_yield_no_routes() {
        assert!(parse_routes("").is_empty());
        assert!(parse_routes("\n").is_empty());
        assert!(parse_routes(ROUTE_HEADER).is_empty());
        assert!(parse_routes(&format!("{ROUTE_HEADER}\n")).is_empty());
    }

    #[test]
    fn malformed_lines_are_skipped_and_valid_lines_are_kept() {
        // Around two well-formed lines: a truncated line (10 columns),
        // a wrong-hex Gateway, a wrong-hex RefCnt (a column we do not
        // even store), a word that overflows u32, an empty line and a
        // bare word. Only the two valid routes survive.
        let content = concat!(
            "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n",
            "eth0  00000000    0100A8C0 0003   0      0   100    00000000 0    0      0\n",
            "eth0  0000A8C0    00000000 0001   0      0   100    FFFFFF00\n", // 10 columns
            "wlan0 00000000    GATEWAY!  0003   0      0   50     00000000 0    0      0\n",
            "wlan0 00000000    0A00000A  0003   XX     0   50     00000000 0    0      0\n",
            "\n",
            "lonely\n",
            "tap0  00000000    123456789 0003   0      0   1      00000000 0    0      0\n",
            "wg0   00000000    0A00000A  0003   0      0   1      00000000 0    0      0\n",
        );
        let routes = parse_routes(content);
        assert_eq!(routes.len(), 2, "only the two well-formed lines parse");
        let first = routes.first().cloned().expect("eth0 line parses");
        assert_eq!(first.iface(), "eth0");
        assert_eq!(
            first.gateway(),
            Ipv4Addr::new(192, 168, 0, 1),
            "0100A8C0 = 192.168.0.1 (little-endian)"
        );
        let second = routes.get(1).cloned().expect("wg0 line parses");
        assert_eq!(second.iface(), "wg0");
        assert_eq!(second.gateway(), Ipv4Addr::new(10, 0, 0, 10));
    }

    #[test]
    fn hex_columns_are_case_insensitive_and_whitespace_runs_are_tolerated() {
        // Lowercase hex, CRLF endings and multi-space runs between
        // columns (the kernel pads some headers with spaces).
        let content = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\r\n\
                       wlan0  00000000  0a00000a  0003  0  0  600  00000000  0  0  0\r\n";
        let routes = parse_routes(content);
        assert_eq!(routes.len(), 1);
        let route = routes.first().cloned().expect("the line is well-formed");
        assert_eq!(route.gateway(), Ipv4Addr::new(10, 0, 0, 10));
    }

    #[test]
    fn columns_past_the_eleventh_are_ignored() {
        // The kernel writes exactly 11 columns; a longer line keeps its
        // first 11 and drops the rest (documented tolerance).
        let content = concat!(
            "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n",
            "eth0  00000000 0100A8C0 0003 0 0 100 00000000 0 0 0 EXTRA EXTRA\n",
        );
        let routes = parse_routes(content);
        assert_eq!(routes.len(), 1);
        let route = routes.first().cloned().expect("the line is well-formed");
        assert_eq!(route.iface(), "eth0");
    }

    #[test]
    fn headerless_input_loses_only_its_first_line() {
        // Appendix E files always carry the header; a headerless (i.e.
        // non-kernel) file still parses from its second line, and the
        // first line is consumed as the header. Documented behavior.
        let content = "eth0  00000000 0100A8C0 0003 0 0 100 00000000 0 0 0\n\
                       wlan0 00000000 0A00000A 0003 0 0 50  00000000 0 0 0\n";
        let routes = parse_routes(content);
        assert_eq!(routes.len(), 1);
        let route = routes.first().cloned().expect("the wlan0 line parses");
        assert_eq!(route.iface(), "wlan0");
    }

    // ---- find_default_gateway (card §7: present / absent / rule) ---------

    #[test]
    fn finds_the_default_gateway_when_present() {
        let routes = parse_routes(REALISTIC_TABLE);
        let default = find_default_gateway(&routes).expect("eth0 carries the default route");
        assert_eq!(default.iface(), "eth0");
        assert_eq!(default.gateway(), Ipv4Addr::new(192, 168, 0, 1));
    }

    #[test]
    fn returns_none_when_no_default_route_exists() {
        // Only the on-link LAN and docker bridge routes — no default.
        let content = concat!(
            "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n",
            "eth0 0000A8C0 00000000 0001 0 0 100 00FFFFFF 0 0 0\n",
            "docker0 000011AC 00000000 0001 0 0 0 0000FFFF 0 0 0\n",
        );
        let routes = parse_routes(content);
        assert_eq!(find_default_gateway(&routes), None);
    }

    #[test]
    fn default_gateway_requires_zero_destination_zero_mask_and_gateway_flag() {
        // (destination, mask, flags, is a default-gateway route)
        let table: [(&str, &str, &str, bool); 5] = [
            ("00000000", "00000000", "0003", true),  // UP|GATEWAY
            ("00000000", "00000000", "0002", true),  // GATEWAY alone is enough
            ("00000000", "00000000", "0001", false), // on-link default, no GATEWAY
            ("00000000", "FFFFFF00", "0003", false), // masked zero destination
            ("0000A8C0", "00000000", "0003", false), // non-zero destination
        ];
        for (destination, mask, flags, expected) in table {
            let content = format!(
                "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n\
                 eth0 {destination} 0100A8C0 {flags} 0 0 100 {mask} 0 0 0\n"
            );
            let routes = parse_routes(&content);
            let entry = routes.first().cloned().expect("the line is well-formed");
            assert_eq!(
                entry.is_default_gateway(),
                expected,
                "Destination {destination} Mask {mask} Flags {flags}"
            );
            assert_eq!(
                find_default_gateway(&routes).is_some(),
                expected,
                "lookup with Destination {destination} Mask {mask} Flags {flags}"
            );
        }
    }

    #[test]
    fn lowest_metric_wins_and_file_order_breaks_ties() {
        // Three default routes: eth0 metric 100 (hex `64`), tun0
        // metric 1, then wlan0 metric 1 — the tie keeps the first in
        // file order (tun0).
        let content = concat!(
            "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n",
            "eth0  00000000 0100A8C0 0003 0 0 64  00000000 0 0 0\n",
            "tun0  00000000 0A00000A 0003 0 0 1   00000000 0 0 0\n",
            "wlan0 00000000 0A000014 0003 0 0 1   00000000 0 0 0\n",
        );
        let routes = parse_routes(content);
        let default = find_default_gateway(&routes).expect("three default routes are present");
        assert_eq!(
            default.iface(),
            "tun0",
            "metric 1 beats 100; file order breaks the tie"
        );
        assert_eq!(default.metric(), 1);
    }

    // ---- property tests (card §7: 1000 hostile inputs, never a panic) -----

    #[test]
    fn property_parse_routes_never_panics_on_hostile_input() {
        // 1,000 strings of random bytes (lossily decoded): the parser
        // must return quietly on every one of them.
        let mut rng = Lcg::seeded(0x7101_0001);
        for _ in 0..1000 {
            let len = rng.next_below(300) as usize;
            let bytes: Vec<u8> = (0..len).map(|_| rng.next_u8()).collect();
            let content = String::from_utf8_lossy(&bytes);
            let routes = parse_routes(&content);
            assert!(
                routes.len() <= content.lines().count(),
                "a parser can never emit more entries than lines"
            );
        }
    }

    #[test]
    fn property_parse_routes_never_panics_on_token_soup() {
        // 1,000 lines of column-shaped garbage: 0..16 tokens, each
        // either random hex digits (any case), oversized hex, or
        // non-hex junk, joined by random whitespace runs.
        let mut rng = Lcg::seeded(0x7101_0002);
        let junk: [&str; 5] = ["!!", "ZZ", "0x1", "-", "ÿ"];
        let spaces: [&str; 3] = [" ", "\t", "  "];
        for _ in 0..1000 {
            let columns = rng.next_below(16);
            let line: Vec<String> = (0..columns)
                .map(|_| {
                    match rng.next_below(4) {
                        0 | 1 => {
                            let digits = rng.next_below(11);
                            (0..digits)
                                .map(|_| {
                                    const HEX: [char; 22] = [
                                        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b',
                                        'c', 'd', 'e', 'f', 'A', 'B', 'C', 'D', 'E', 'F',
                                    ];
                                    let idx = rng.next_below(HEX.len() as u64) as usize;
                                    HEX.get(idx).copied().into_iter().collect::<String>()
                                })
                                .collect()
                        }
                        2 => junk[rng.next_below(junk.len() as u64) as usize].to_owned(),
                        _ => "123456789".to_owned(), // overflows every column type
                    }
                })
                .collect();
            let separator = spaces[rng.next_below(spaces.len() as u64) as usize];
            let joined = line.join(separator);
            let content = format!("{ROUTE_HEADER}\n{joined}\n");
            let routes = parse_routes(&content);
            assert!(routes.len() <= 1);
        }
    }

    // ---- class / eligibility / ranking (FR-SC-02, FR-SC-03) --------------

    #[test]
    fn classifies_virtual_and_physical_names() {
        // (name, expected class) — the §5.4 pattern list plus boundary
        // names a strict reading of the rules keeps physical.
        let table: [(&str, InterfaceClass); 14] = [
            ("docker0", InterfaceClass::Virtual),
            ("vethabc", InterfaceClass::Virtual),
            ("br-int", InterfaceClass::Virtual),
            ("virbr0", InterfaceClass::Virtual),
            ("tun0", InterfaceClass::Virtual),
            ("tap0", InterfaceClass::Virtual),
            ("wg0", InterfaceClass::Virtual),
            ("lo", InterfaceClass::Virtual),
            ("eth0", InterfaceClass::Physical),
            ("wlan0", InterfaceClass::Physical),
            // Boundary cases the card's pattern list decides:
            ("br0", InterfaceClass::Physical), // pattern is `br-`, not `br`
            ("lo0", InterfaceClass::Physical), // `lo` matches by equality only
            ("wlp3s0", InterfaceClass::Physical),
            ("tunl0", InterfaceClass::Virtual), // starts with `tun`
        ];
        for (name, expected) in table {
            let info = eligible_physical(name);
            assert_eq!(info.class(), expected, "class of {name}");
        }
    }

    #[test]
    fn eligibility_reports_each_reason() {
        // NotUp: administratively down.
        let mut info = eligible_physical("eth0");
        info.is_up = false;
        info.is_running = false;
        assert_eq!(
            info.eligibility(),
            Eligibility::Ineligible(IneligibleReason::NotUp)
        );

        // NotEthernet: a PPP link (ARPHRD_PPP = 512).
        let mut info = eligible_physical("ppp0");
        info.link_type = LinkType::Other(512);
        assert_eq!(
            info.eligibility(),
            Eligibility::Ineligible(IneligibleReason::NotEthernet)
        );

        // NoIpv4Address: no address configured.
        let mut info = eligible_physical("eth1");
        info.ipv4 = None;
        assert_eq!(
            info.eligibility(),
            Eligibility::Ineligible(IneligibleReason::NoIpv4Address)
        );

        // Loopback: `lo`, even though it is up and has an address.
        assert_eq!(
            loopback_interface().eligibility(),
            Eligibility::Ineligible(IneligibleReason::Loopback)
        );

        // The baseline fixture is eligible.
        assert_eq!(
            eligible_physical("eth0").eligibility(),
            Eligibility::Eligible
        );
    }

    #[test]
    fn eligibility_check_order_is_deterministic() {
        // Loopback beats every other rule (a categorical exclusion) …
        let mut lo = loopback_interface();
        lo.is_up = false;
        lo.ipv4 = None;
        assert_eq!(
            lo.eligibility(),
            Eligibility::Ineligible(IneligibleReason::Loopback)
        );
        // … then down beats link type and addressing …
        let mut info = eligible_physical("eth0");
        info.is_up = false;
        info.link_type = LinkType::Other(512);
        info.ipv4 = None;
        assert_eq!(
            info.eligibility(),
            Eligibility::Ineligible(IneligibleReason::NotUp)
        );
        // … then link type beats addressing.
        let mut info = eligible_physical("eth0");
        info.link_type = LinkType::Other(512);
        info.ipv4 = None;
        assert_eq!(
            info.eligibility(),
            Eligibility::Ineligible(IneligibleReason::NotEthernet)
        );
    }

    #[test]
    fn an_up_but_not_running_interface_stays_eligible() {
        // FR-SC-03 names "up"; IFF_RUNNING is reported but not required
        // (the neighbor-table path works without a carrier).
        let mut info = eligible_physical("wlan0");
        info.is_running = false;
        assert_eq!(info.eligibility(), Eligibility::Eligible);
        assert!(!info.is_running());
    }

    #[test]
    fn ranking_follows_the_fr_sc_02_priority() {
        // The card §7 scenario, deliberately shuffled: the Wi-Fi
        // interface (eligible, physical, default-route carrier) must be
        // suggested over the Ethernet NIC, the docker bridge, the veth
        // pair and the ineligible loopback.
        let mut wlan = eligible_physical("wlan0");
        wlan.default_gateway = Some(Ipv4Addr::new(192, 168, 1, 1));
        let interfaces = vec![
            eligible_virtual("veth123"),
            loopback_interface(),
            eligible_virtual("docker0"),
            eligible_physical("eth0"),
            wlan,
        ];
        assert_eq!(
            suggest_interface(&interfaces).map(|i| i.name().to_owned()),
            Some("wlan0".to_owned())
        );

        // Draining the suggestion proves the full order:
        // Wi-Fi (default) > Ethernet > docker0 > veth123 > (lo never).
        let mut rest = interfaces;
        let mut order: Vec<String> = Vec::new();
        while let Some(best) = suggest_interface(&rest) {
            order.push(best.name().to_owned());
            let position = rest.iter().position(|i| i.name() == best.name());
            if let Some(position) = position {
                rest.remove(position);
            }
        }
        assert_eq!(order, ["wlan0", "eth0", "docker0", "veth123"]);
        // `lo` was never suggested: the list drained without it.
        assert!(rest.iter().any(|i| i.name() == "lo"));
    }

    #[test]
    fn same_tier_breaks_ties_by_name() {
        let interfaces = vec![
            eligible_physical("wlan0"),
            eligible_physical("eth0"),
            eligible_physical("enp3s0"),
        ];
        assert_eq!(
            suggest_interface(&interfaces).map(|i| i.name().to_owned()),
            Some("enp3s0".to_owned()),
            "alphabetical within the (eligible, physical, no default) tier"
        );
    }

    #[test]
    fn a_default_route_carrier_outranks_physical_interfaces() {
        // FR-SC-02 names the default-route carrier first — even when it
        // is a virtual device (a VPN tunnel here).
        let mut tun = eligible_virtual("tun0");
        tun.default_gateway = Some(Ipv4Addr::new(10, 10, 0, 1));
        let interfaces = vec![eligible_physical("eth0"), tun, eligible_physical("wlan0")];
        assert_eq!(
            suggest_interface(&interfaces).map(|i| i.name().to_owned()),
            Some("tun0".to_owned())
        );
    }

    #[test]
    fn suggest_returns_none_without_eligible_interfaces() {
        assert_eq!(suggest_interface(&[]), None);

        let mut down = eligible_physical("eth0");
        down.is_up = false;
        let mut no_ip = eligible_physical("wlan0");
        no_ip.ipv4 = None;
        assert_eq!(
            suggest_interface(&[loopback_interface(), down, no_ip]),
            None
        );
    }

    // ---- derive_scope (FR-SC-04, FR-SC-05, FR-SC-06) ----------------------

    #[test]
    fn derives_scope_for_the_card_prefix_lengths() {
        /// (name, address, prefix, network base, usable hosts)
        type ScopeCase<'a> = (&'a str, [u8; 4], u8, [u8; 4], u32);
        let cases: [ScopeCase<'_>; 5] = [
            ("wlan0", [192, 168, 1, 130], 24, [192, 168, 1, 0], 254),
            ("eth0", [10, 0, 4, 130], 22, [10, 0, 4, 0], 1022),
            ("ptp0", [192, 168, 1, 5], 30, [192, 168, 1, 4], 2),
            ("rfc3021", [10, 0, 0, 0], 31, [10, 0, 0, 0], 2),
            ("single", [10, 0, 0, 5], 32, [10, 0, 0, 5], 1),
        ];
        for (name, address, prefix, network, hosts) in cases {
            let mut info = eligible_physical(name);
            info.ipv4 = Some((Ipv4Addr::from(address), prefix));
            let scope = derive_scope(&info).expect("interface has an IPv4 address");
            assert_eq!(scope.network(), Ipv4Addr::from(network), "{name} network");
            assert_eq!(scope.prefix_len(), prefix, "{name} prefix");
            assert_eq!(scope.host_count(), hosts, "{name} host count");
        }
    }

    #[test]
    fn derived_scope_covers_the_interfaces_own_network_only() {
        // FR-SC-04: the scope is exactly the interface's own network —
        // host bits are masked off, nothing else is reachable.
        let mut info = eligible_physical("wlan0");
        info.ipv4 = Some((Ipv4Addr::new(192, 168, 1, 130), 24));
        let scope = derive_scope(&info).expect("address present");
        assert!(scope.contains(Ipv4Addr::new(192, 168, 1, 130)));
        assert!(scope.contains(Ipv4Addr::new(192, 168, 1, 254)));
        assert!(!scope.contains(Ipv4Addr::new(192, 168, 2, 1)));
        assert!(!scope.contains(Ipv4Addr::new(192, 168, 0, 255)));
        // FR-SC-05 host range for the /24: .1 through .254.
        let range = scope.host_range().expect("/24 is under the default cap");
        assert_eq!(range.first(), Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(range.last(), Ipv4Addr::new(192, 168, 1, 254));
        // /22 sits exactly at the default cap (FR-SC-06, inclusive).
        let mut info = eligible_physical("eth0");
        info.ipv4 = Some((Ipv4Addr::new(10, 0, 4, 130), 22));
        let scope = derive_scope(&info).expect("address present");
        let range = scope.host_range().expect("1022 == DEFAULT_MAX_HOSTS");
        assert_eq!(range.first(), Ipv4Addr::new(10, 0, 4, 1));
        assert_eq!(range.last(), Ipv4Addr::new(10, 0, 7, 254));
        // RFC 3021: both /31 addresses are usable hosts.
        let mut info = eligible_physical("rfc3021");
        info.ipv4 = Some((Ipv4Addr::new(10, 0, 0, 0), 31));
        let scope = derive_scope(&info).expect("address present");
        let range = scope.host_range().expect("2 <= 1022");
        assert_eq!(range.first(), Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(range.last(), Ipv4Addr::new(10, 0, 0, 1));
        // /32 is a single host.
        let mut info = eligible_physical("single");
        info.ipv4 = Some((Ipv4Addr::new(10, 0, 0, 5), 32));
        let scope = derive_scope(&info).expect("address present");
        let range = scope.host_range().expect("1 <= 1022");
        assert_eq!(range.first(), Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(range.last(), Ipv4Addr::new(10, 0, 0, 5));
    }

    #[test]
    fn a_16_scope_exceeds_the_default_cap_per_fr_sc_06() {
        let mut info = eligible_physical("biglan");
        info.ipv4 = Some((Ipv4Addr::new(172, 16, 0, 1), 16));
        let scope = derive_scope(&info).expect("address present");
        assert_eq!(scope.host_count(), 65_534);
        // FR-SC-06: 1,022 hosts (/22) by default — a /16 must raise the
        // cap explicitly and confirm in-app.
        assert_eq!(
            scope.host_range().unwrap_err(),
            Ipv4NetError::OverCapacity {
                requested: 65_534,
                cap: DEFAULT_MAX_HOSTS,
            }
        );
        // Raising to the absolute ceiling (65,534) admits the /16 …
        let range = scope
            .host_range_capped(ABSOLUTE_MAX_HOSTS)
            .expect("65,534 == the ceiling");
        assert_eq!(range.first(), Ipv4Addr::new(172, 16, 0, 1));
        assert_eq!(range.last(), Ipv4Addr::new(172, 16, 255, 254));
        // … but nothing larger can ever be scanned (a /15).
        let mut info = eligible_physical("huge");
        info.ipv4 = Some((Ipv4Addr::new(10, 0, 0, 1), 15));
        let scope = derive_scope(&info).expect("address present");
        assert_eq!(
            scope.host_range_capped(ABSOLUTE_MAX_HOSTS).unwrap_err(),
            Ipv4NetError::OverCapacity {
                requested: 131_070,
                cap: ABSOLUTE_MAX_HOSTS,
            }
        );
    }

    #[test]
    fn derive_scope_returns_none_without_an_ipv4_address() {
        let mut info = eligible_physical("eth9");
        info.ipv4 = None;
        assert_eq!(derive_scope(&info), None);
    }

    // ---- LinkType and display labels ---------------------------------------

    #[test]
    fn link_type_classifies_arphrd_numbers() {
        assert_eq!(LinkType::from_arphrd(1), LinkType::Ethernet);
        assert_eq!(LinkType::from_arphrd(772), LinkType::Loopback);
        assert_eq!(LinkType::from_arphrd(512), LinkType::Other(512)); // ARPHRD_PPP
        assert_eq!(LinkType::from_arphrd(65534), LinkType::Other(65534)); // ARPHRD_NONE
        // raw() round-trips every constructor input.
        for raw in [0u16, 1, 512, 772, 65535] {
            assert_eq!(LinkType::from_arphrd(raw).raw(), raw);
        }
        // Only the Ethernet family is ARP-capable (FR-SC-03).
        assert!(LinkType::Ethernet.is_ethernet());
        assert!(!LinkType::Loopback.is_ethernet());
        assert!(!LinkType::Other(512).is_ethernet());
    }

    #[test]
    fn display_labels_follow_the_controlled_vocabulary() {
        assert_eq!(InterfaceClass::Virtual.to_string(), "virtual");
        assert_eq!(InterfaceClass::Physical.to_string(), "physical");
        assert_eq!(IneligibleReason::NotUp.to_string(), "interface is down");
        assert_eq!(
            IneligibleReason::NotEthernet.to_string(),
            "not an Ethernet-type link"
        );
        assert_eq!(
            IneligibleReason::NoIpv4Address.to_string(),
            "no IPv4 address"
        );
        assert_eq!(IneligibleReason::Loopback.to_string(), "loopback interface");
    }

    #[test]
    fn accessors_expose_every_fr_sc_01_field() {
        let mut info = eligible_physical("wlan0");
        info.index = 7;
        info.default_gateway = Some(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(info.name(), "wlan0");
        assert_eq!(info.index(), 7);
        assert_eq!(
            info.mac().map(|m| m.to_string()),
            Some("aa:bb:cc:dd:ee:01".to_owned())
        );
        assert_eq!(info.ipv4(), Some(Ipv4Addr::new(192, 168, 1, 130)));
        assert_eq!(info.prefix_len(), Some(24));
        assert_eq!(info.link_type(), LinkType::Ethernet);
        assert!(info.is_up());
        assert!(info.is_running());
        assert!(!info.is_loopback());
        assert_eq!(info.default_gateway(), Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(info.carries_default_route());
        // Without a default route there is nothing to carry.
        let plain = eligible_physical("eth0");
        assert_eq!(plain.default_gateway(), None);
        assert!(!plain.carries_default_route());
    }

    // ---- live system smoke test (invariants, not values) -------------------

    #[test]
    fn live_enumeration_satisfies_the_documented_invariants() {
        let interfaces = enumerate_interfaces();

        // Deterministic, unique, non-empty names.
        let names: Vec<&str> = interfaces.iter().map(|i| i.name()).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "sorted by name");
        let mut unique = sorted.clone();
        unique.dedup();
        assert_eq!(sorted.len(), unique.len(), "interface names are unique");
        assert!(names.iter().all(|n| !n.is_empty()));

        // A Linux system always has `lo`, and it is what FR-SC-03 says.
        let lo = interfaces
            .iter()
            .find(|i| i.name() == "lo")
            .expect("the kernel always provides lo");
        assert!(lo.is_loopback());
        assert_eq!(lo.class(), InterfaceClass::Virtual);
        assert_eq!(
            lo.eligibility(),
            Eligibility::Ineligible(IneligibleReason::Loopback)
        );
        // The loopback MAC (all-zero) is rejected by the §5.3 boundary
        // rules rather than fabricated.
        assert_eq!(lo.mac(), None);

        // Any suggestion is eligible and yields a scope; ineligible
        // interfaces are never suggested (FR-SC-02).
        if let Some(suggested) = suggest_interface(&interfaces) {
            assert_eq!(suggested.eligibility(), Eligibility::Eligible);
            let scope = derive_scope(suggested).expect("eligible implies an IPv4 address");
            let address = suggested.ipv4().expect("eligible implies an address");
            assert!(scope.contains(address));
        }

        // Enumerating twice yields the same inventory (read-only).
        let again = enumerate_interfaces();
        assert_eq!(interfaces, again);
    }
}
