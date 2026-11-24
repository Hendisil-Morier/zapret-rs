//! Kernel routing source-address lookup and network interface enumeration (`get_source_ip`, `get_ifaddrs`).

/// Interface lookup index map preserving insertion order.
use std::collections::HashMap;
/// C string parsing and conversion for interface names.
use std::ffi::{CStr, CString, c_int};
/// IP address types and non-blocking UDP route-lookup socket.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
/// Safe FD wrapper for the temporary `SIOCGIFMTU` ioctl socket.
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// One address entry attached to a network interface returned by [`get_ifaddrs`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceAddr {
    /// Interface unicast IPv4 or IPv6 address.
    pub addr: IpAddr,
    /// Optional subnet mask associated with `addr`.
    pub netmask: Option<IpAddr>,
    /// Optional broadcast address when `IFF_BROADCAST` is set.
    pub broadcast: Option<IpAddr>,
    /// Optional point-to-point peer address when `IFF_POINTOPOINT` is set.
    pub dst: Option<IpAddr>,
}

/// Network interface summary returned by [`get_ifaddrs`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceInfo {
    /// Kernel interface name (e.g., `"lo"`, `"eth0"`).
    pub name: String,
    /// Kernel interface index from `if_nametoindex`, if available.
    pub index: Option<u32>,
    /// Interface flags (`ifa_flags`).
    pub flags: u32,
    /// Interface MTU queried via `SIOCGIFMTU`, if available.
    pub mtu: Option<i32>,
    /// List of IPv4/IPv6 addresses configured on this interface.
    pub addrs: Vec<InterfaceAddr>,
}

/// RAII guard ensuring `libc::freeifaddrs` is called even if processing returns early.
struct IfAddrsGuard {
    /// Linked-list head returned by `libc::getifaddrs`.
    head: *mut libc::ifaddrs,
}

impl Drop for IfAddrsGuard {
    /// Releases the linked list allocated by `libc::getifaddrs`.
    fn drop(&mut self) {
        if !self.head.is_null() {
            // SAFETY: `self.head` was returned by a successful `libc::getifaddrs` call.
            unsafe { libc::freeifaddrs(self.head) };
        }
    }
}

/// Queries the kernel routing table for the source IP address used to reach `target`.
pub fn get_source_ip(target: IpAddr) -> Option<IpAddr> {
    let bind_addr = match target {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let sock = UdpSocket::bind(bind_addr).ok()?;
    sock.connect((target, 65535)).ok()?;
    sock.local_addr().ok().map(|local| local.ip())
}

/// Converts a raw `libc::sockaddr` pointer into an IPv4 or IPv6 [`IpAddr`].
fn sockaddr_to_ip(sa: *const libc::sockaddr) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    // SAFETY: Caller verified `sa` is non-null and points to a `libc::sockaddr` header.
    let family = unsafe { (*sa).sa_family as c_int };
    match family {
        libc::AF_INET => {
            // SAFETY: `sa_family == AF_INET` guarantees a `libc::sockaddr_in` struct.
            let sin = unsafe { &*(sa.cast::<libc::sockaddr_in>()) };
            Some(IpAddr::V4(Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes())))
        }
        libc::AF_INET6 => {
            // SAFETY: `sa_family == AF_INET6` guarantees a `libc::sockaddr_in6` struct.
            let sin6 = unsafe { &*(sa.cast::<libc::sockaddr_in6>()) };
            Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

/// Queries the MTU of interface `ifname` via `SIOCGIFMTU` using an already-opened datagram FD.
fn query_interface_mtu(ioctl_fd: Option<&OwnedFd>, ifname: &str) -> Option<i32> {
    let fd = ioctl_fd?.as_raw_fd();
    let name_bytes = ifname.as_bytes();
    if name_bytes.len() >= libc::IFNAMSIZ {
        return None;
    }

    // SAFETY: Zeroed `libc::ifreq` is valid for all union members before writing `ifr_name`.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (idx, &byte) in name_bytes.iter().enumerate() {
        ifr.ifr_name[idx] = byte as libc::c_char;
    }

    // SAFETY: `fd` is a valid `AF_INET` socket FD and `ifr` is a valid mutable `libc::ifreq`.
    let rc = unsafe { libc::ioctl(fd, libc::SIOCGIFMTU as _, &raw mut ifr) };
    if rc == 0 {
        // SAFETY: Successful `SIOCGIFMTU` initializes `ifr.ifr_ifru.ifru_mtu`.
        Some(unsafe { ifr.ifr_ifru.ifru_mtu })
    } else {
        None
    }
}

/// Enumerates active IPv4/IPv6 network interfaces and their addresses via Linux `getifaddrs`.
pub fn get_ifaddrs() -> std::io::Result<Vec<InterfaceInfo>> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `head` is a valid out-pointer for `libc::getifaddrs`.
    let rc = unsafe { libc::getifaddrs(&raw mut head) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let _guard = IfAddrsGuard { head };

    // SAFETY: `libc::socket` returns a valid FD or `-1`; failure merely omits MTU metadata.
    let ioctl_fd = unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd >= 0 {
            Some(OwnedFd::from_raw_fd(fd))
        } else {
            None
        }
    };

    let mut interfaces: Vec<InterfaceInfo> = Vec::new();
    let mut index_by_name: HashMap<String, usize> = HashMap::new();
    let mut cur = head;

    while !cur.is_null() {
        // SAFETY: `cur` is a non-null node in the linked list owned by `_guard`.
        let entry = unsafe { &*cur };
        if let Some(addr) = sockaddr_to_ip(entry.ifa_addr)
            && !entry.ifa_name.is_null()
        {
            // SAFETY: `ifa_name` is a non-null NUL-terminated C string from `getifaddrs`.
            let c_name = unsafe { CStr::from_ptr(entry.ifa_name) };
            let name = c_name.to_string_lossy().into_owned();
            if !name.is_empty() {
                let info_idx = if let Some(&existing) = index_by_name.get(&name) {
                    existing
                } else {
                    let ifindex = CString::new(name.as_str()).ok().and_then(|cn| {
                        // SAFETY: `cn` is a valid NUL-terminated interface name string.
                        let idx = unsafe { libc::if_nametoindex(cn.as_ptr()) };
                        if idx != 0 { Some(idx) } else { None }
                    });
                    let mtu = query_interface_mtu(ioctl_fd.as_ref(), &name);
                    let pos = interfaces.len();
                    interfaces.push(InterfaceInfo {
                        name: name.clone(),
                        index: ifindex,
                        flags: entry.ifa_flags,
                        mtu,
                        addrs: Vec::new(),
                    });
                    index_by_name.insert(name, pos);
                    pos
                };

                let netmask = sockaddr_to_ip(entry.ifa_netmask);
                let flags = entry.ifa_flags as c_int;
                let (broadcast, dst) = if (flags & libc::IFF_BROADCAST) != 0 {
                    (sockaddr_to_ip(entry.ifa_ifu), None)
                } else if (flags & libc::IFF_POINTOPOINT) != 0 {
                    (None, sockaddr_to_ip(entry.ifa_ifu))
                } else {
                    (None, None)
                };

                interfaces[info_idx].addrs.push(InterfaceAddr {
                    addr,
                    netmask,
                    broadcast,
                    dst,
                });
            }
        }
        cur = entry.ifa_next;
    }

    Ok(interfaces)
}
