//! Disjoint IPv4/IPv6 CIDR prefix sets, gzip/plain ipset loaders, and dual-IP checks.

/// Interior mutability for sharing cached ipset files across profile collections.
use std::cell::RefCell;
/// Ordered prefix interval map providing O(log N) CIDR lookup and collapsing.
use std::collections::BTreeMap;
/// Standard IPv4, IPv6, and unified IP address types.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
/// Filesystem path storage for reloadable ipset files.
use std::path::{Path, PathBuf};
/// Single-thread reference counting for deduplicating shared ipset files across profiles.
use std::rc::Rc;
/// IP literal string parser trait reused by the shared CIDR parser helper.
use std::str::FromStr;

/// Modification signature, token line extractor, and streaming gzip/plain loader helpers.
use crate::lists::file_loader::{
    FileModSig, load_list_initial, parse_list_line_token, read_list_lines, reload_cached_list,
};

/// Bit-width abstraction computing aligned `(start, end)` CIDR intervals for IPv4 and IPv6.
trait IpBits: Copy + Ord
{
    /// Total address bit length (`32` for IPv4, `128` for IPv6).
    const ADDR_BITS: u8;

    /// Computes inclusive `(network_start, broadcast_end)` bounds for `self / preflen`.
    fn cidr_bounds(self, preflen: u8) -> Option<(Self, Self)>;
}

impl IpBits for u32
{
    const ADDR_BITS: u8 = 32;

    fn cidr_bounds(self, preflen: u8) -> Option<(Self, Self)>
    {
        if preflen > Self::ADDR_BITS
        {
            return None;
        }
        if preflen == 0
        {
            return Some((0, Self::MAX));
        }
        let shift = u32::from(Self::ADDR_BITS - preflen);
        let mask = (!0u32) << shift;
        let start = self & mask;
        let end = start | !mask;
        Some((start, end))
    }
}

impl IpBits for u128
{
    const ADDR_BITS: u8 = 128;

    fn cidr_bounds(self, preflen: u8) -> Option<(Self, Self)>
    {
        if preflen > Self::ADDR_BITS
        {
            return None;
        }
        if preflen == 0
        {
            return Some((0, Self::MAX));
        }
        let shift = u32::from(Self::ADDR_BITS - preflen);
        let mask = (!0u128) << shift;
        let start = self & mask;
        let end = start | !mask;
        Some((start, end))
    }
}

/// Disjoint binary prefix interval tree collapsing overlapping CIDRs (`kavl_bit` equivalent).
#[derive(Debug, Default, Clone)]
struct PrefixSet<T>
{
    /// Non-overlapping inclusive `[start, end]` intervals keyed by network start integer.
    ranges: BTreeMap<T, T>,
}

impl<T: IpBits> PrefixSet<T>
{
    /// Inserts `addr / preflen`, coalescing narrower subsets or skipping if already covered.
    fn insert(&mut self, addr: T, preflen: u8) -> bool
    {
        let Some((start, end)) = addr.cidr_bounds(preflen)
        else
        {
            return false;
        };
        if let Some((_, &prev_end)) = self.ranges.range(..=start).next_back()
            && prev_end >= end
        {
            return true;
        }
        let covered: Vec<T> = self.ranges.range(start..=end).map(|(&k, _)| k).collect();
        for key in covered
        {
            self.ranges.remove(&key);
        }
        self.ranges.insert(start, end);
        true
    }

    /// Returns `true` when `addr` falls within any stored CIDR interval in O(log N).
    fn contains(&self, addr: T) -> bool
    {
        self.ranges.range(..=addr).next_back().is_some_and(|(_, &end)| addr <= end)
    }

    /// Returns the number of disjoint CIDR prefixes currently stored.
    fn len(&self) -> usize
    {
        self.ranges.len()
    }

    /// Returns `true` when no CIDR prefixes are stored.
    fn is_empty(&self) -> bool
    {
        self.ranges.is_empty()
    }

    /// Clears all stored prefixes.
    fn clear(&mut self)
    {
        self.ranges.clear();
    }
}

/// Shared CIDR `<ip>[/<preflen>]` parser validating ASCII prefix lengths up to `max_prefix`.
fn parse_cidr<A: FromStr>(s: &str, max_prefix: u8) -> Option<(A, u8)>
{
    let (ip_str, preflen) = match s.split_once('/')
    {
        Some((ip, prefix)) =>
        {
            if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit())
            {
                return None;
            }
            let plen = prefix.parse::<u8>().ok()?;
            if plen > max_prefix
            {
                return None;
            }
            (ip, plen)
        }
        None => (s, max_prefix),
    };
    let addr = ip_str.parse::<A>().ok()?;
    Some((addr, preflen))
}

/// Parses an IPv4 address or CIDR (`1.2.3.4` or `10.0.0.0/8`) (`parse_cidr4` in `filter.c`).
pub fn parse_cidr4(s: &str) -> Option<(Ipv4Addr, u8)>
{
    parse_cidr::<Ipv4Addr>(s, 32)
}

/// Parses an IPv6 address or CIDR (`2001:db8::/32` or `::1`) (`parse_cidr6` in `filter.c`).
pub fn parse_cidr6(s: &str) -> Option<(Ipv6Addr, u8)>
{
    parse_cidr::<Ipv6Addr>(s, 128)
}

/// Disjoint dual-stack IPv4 and IPv6 CIDR matcher (`struct ipset` in `pools.h`).
#[derive(Debug, Default, Clone)]
pub struct IpSet
{
    /// Non-overlapping IPv4 prefix tree.
    v4: PrefixSet<u32>,
    /// Non-overlapping IPv6 prefix tree.
    v6: PrefixSet<u128>,
}

impl IpSet
{
    /// Creates an empty [`IpSet`].
    pub fn new() -> Self
    {
        Self::default()
    }

    /// Returns `true` when neither IPv4 nor IPv6 prefixes are stored (`IPSET_EMPTY`).
    pub fn is_empty(&self) -> bool
    {
        self.v4.is_empty() && self.v6.is_empty()
    }

    /// Returns the count of stored disjoint IPv4 prefixes.
    pub fn len_v4(&self) -> usize
    {
        self.v4.len()
    }

    /// Returns the count of stored disjoint IPv6 prefixes.
    pub fn len_v6(&self) -> usize
    {
        self.v6.len()
    }

    /// Removes all IPv4 and IPv6 prefixes (`ipsetDestroy`).
    pub fn clear(&mut self)
    {
        self.v4.clear();
        self.v6.clear();
    }

    /// Inserts an IPv4 CIDR into the disjoint v4 prefix tree (`ipset4Add`).
    pub fn add_v4(&mut self, addr: Ipv4Addr, preflen: u8) -> bool
    {
        self.v4.insert(u32::from(addr), preflen)
    }

    /// Inserts an IPv6 CIDR into the disjoint v6 prefix tree (`ipset6Add`).
    pub fn add_v6(&mut self, addr: Ipv6Addr, preflen: u8) -> bool
    {
        self.v6.insert(u128::from(addr), preflen)
    }

    /// Parses one raw ipset line, ignoring comments and logging invalid CIDRs non-fatally.
    pub fn add_raw_line(&mut self, line: &str) -> bool
    {
        let Some(token) = parse_list_line_token(line)
        else
        {
            return true;
        };
        if let Some((addr, plen)) = parse_cidr4(token)
        {
            return self.add_v4(addr, plen);
        }
        if let Some((addr, plen)) = parse_cidr6(token)
        {
            return self.add_v6(addr, plen);
        }
        eprintln!("bad ip or subnet : {token}");
        false
    }

    /// Returns `true` when `addr` is matched by a stored IPv4 or IPv6 CIDR prefix.
    pub fn contains(&self, addr: IpAddr) -> bool
    {
        match addr
        {
            IpAddr::V4(ip) => self.v4.contains(u32::from(ip)),
            IpAddr::V6(ip) => self.v6.contains(u128::from(ip)),
        }
    }
}

/// Reads a plain or gzip ipset file from disk into a fresh [`IpSet`], skipping malformed CIDR lines.
fn parse_ipset_file(path: &Path) -> std::io::Result<IpSet>
{
    let mut set = IpSet::new();
    read_list_lines(path, |line| {
        let _ = set.add_raw_line(line);
    })?;
    Ok(set)
}

/// Single inline or file-backed ipset paired with its cached modification signature (`ipset_file`).
#[derive(Debug, Default, Clone)]
pub struct IpsetFile
{
    /// Optional backing filesystem path (`None` for inline `--ipset-ip` pools).
    pub path: Option<PathBuf>,
    /// Last loaded `(mtime_sec, mtime_nsec, size)` signature for change detection.
    pub mod_sig: FileModSig,
    /// In-memory disjoint CIDR prefix set.
    pub ipset: IpSet,
}

impl IpsetFile
{
    /// Creates an in-memory inline ipset without a backing file.
    pub fn inline() -> Self
    {
        Self::default()
    }

    /// Creates an unloaded file-backed [`IpsetFile`] pointing to `path`.
    pub fn from_path(path: PathBuf) -> Self
    {
        Self { path: Some(path), mod_sig: FileModSig::default(), ipset: IpSet::new() }
    }

    /// Clears `mod_sig` so the next reload check forces a full disk reload (`SIGHUP`).
    pub fn reset_mod_sig(&mut self)
    {
        self.mod_sig.reset();
    }

    /// Strictly loads the backing file at startup (`test_list_files`), failing on I/O or gzip error.
    pub fn load_initial(&mut self) -> std::io::Result<()>
    {
        load_list_initial(self.path.as_deref(), &mut self.mod_sig, &mut self.ipset, parse_ipset_file)
    }

    /// Reloads the file if its signature changed, keeping existing entries on transient access error.
    pub fn reload_if_changed(&mut self) -> std::io::Result<bool>
    {
        reload_cached_list(
            self.path.as_deref(),
            &mut self.mod_sig,
            &mut self.ipset,
            "ipset",
            IpSet::clear,
            parse_ipset_file,
        )
    }
}

/// Ordered include and exclude ipset collections evaluated for one profile.
#[derive(Debug, Default, Clone)]
pub struct IpsetCollection
{
    /// Include ipsets (one match => pass; all pools empty => pass all).
    pub include: Vec<Rc<RefCell<IpsetFile>>>,
    /// Exclude ipsets (checked before `include`; any match denies).
    pub exclude: Vec<Rc<RefCell<IpsetFile>>>,
}

impl IpsetCollection
{
    /// Returns `true` when neither include nor exclude ipsets are configured (`PROFILE_IPSETS_ABSENT`).
    pub fn is_absent(&self) -> bool
    {
        self.include.is_empty() && self.exclude.is_empty()
    }

    /// Checks and reloads modified include/exclude ipset files (`IpsetsReloadCheckForProfile`).
    pub fn reload_check(&self) -> std::io::Result<bool>
    {
        let mut any_changed = false;
        for file in &self.include
        {
            if file.borrow_mut().reload_if_changed()?
            {
                any_changed = true;
            }
        }
        for file in &self.exclude
        {
            if file.borrow_mut().reload_if_changed()?
            {
                any_changed = true;
            }
        }
        Ok(any_changed)
    }

    /// Evaluates `primary` and optional `reverse` IP against exclude then include ipsets (`IpsetCheck`).
    pub fn check(&self, primary: IpAddr, reverse: Option<IpAddr>, skip_reload: bool) -> bool
    {
        if self.is_absent()
        {
            return true;
        }
        if !skip_reload && self.reload_check().is_err()
        {
            return false;
        }

        for ex_file in &self.exclude
        {
            let ex = ex_file.borrow();
            if ex.ipset.contains(primary) || reverse.is_some_and(|r| ex.ipset.contains(r))
            {
                return false;
            }
        }

        if self.include.iter().all(|f| f.borrow().ipset.is_empty())
        {
            return true;
        }

        for inc_file in &self.include
        {
            let inc = inc_file.borrow();
            if inc.ipset.contains(primary) || reverse.is_some_and(|r| inc.ipset.contains(r))
            {
                return true;
            }
        }

        false
    }
}
