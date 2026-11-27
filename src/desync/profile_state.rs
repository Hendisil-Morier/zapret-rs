//! Deduplicated hostlist/ipset registries, autohostlist pools, and full Milestone 3 profile matching.

/// Single-threaded interior mutability and cooldown cells for shared lists and counters.
use std::cell::{Cell, RefCell};
/// Deduplication map keying file-backed hostlists and ipsets by canonical/configured path.
use std::collections::HashMap;
/// Filesystem probing, gzip magic verification, and creatable/writable autohostlist verification.
use std::fs::OpenOptions;
/// Error classification for gzip checks on autohostlist files.
use std::io::ErrorKind;
/// Standard IPv4/IPv6 endpoint representation forwarded into [`IpsetCollection::check`].
use std::net::IpAddr;
/// Owned and borrowed filesystem path types.
use std::path::{Path, PathBuf};
/// Reference counting for sharing loaded list files across multiple profiles.
use std::rc::Rc;

/// Configuration models evaluated when building runtime lists and matching profiles.
use crate::config::{AppConfig, DesyncProfile, ProfileMatchInput};
/// Per-flow connection tracking record whose cached hostlist and cutoff flags reset on profile change.
use crate::conntrack::CtrackEntry;
/// Domain hostlists, CIDR ipsets, and time-windowed autohostlist failure counter pools.
use crate::lists::{
    HostFailPool, HostlistCollection, HostlistFile, HostlistRef, IpsetCollection, IpsetFile,
    detect_gzip_and_rewind,
};
/// Precomputed `<func>_<profile_n>_<func_n>` action instance name helper (`desync_instance`).
use crate::lua::desync_encode::desync_instance_name;
/// Monotonic boottime seconds clock used to throttle list `stat(2)` reload probes.
use crate::timer::boottime_secs;

/// Process-wide cache of deduplicated hostlist and ipset files supporting startup validation and `SIGHUP`.
#[derive(Debug, Default)]
pub(crate) struct ListRegistry {
    /// File-backed hostlists in load order, reused across profiles sharing a path.
    hostlists: Vec<Rc<RefCell<HostlistFile>>>,
    /// File-backed ipsets in load order, reused across profiles sharing a path.
    ipsets: Vec<Rc<RefCell<IpsetFile>>>,
}

/// Per-profile instantiated hostlists, autohostlist handle, CIDR ipsets, failure pool, and cached instance names.
#[derive(Debug)]
pub(crate) struct ProfileRuntime {
    /// Include and exclude domain lists bound to this profile.
    pub(crate) hostlists: HostlistCollection,
    /// Writable `--hostlist-auto` file backing this profile, if configured.
    pub(crate) autolist: Option<Rc<RefCell<HostlistFile>>>,
    /// Include and exclude CIDR prefix sets bound to this profile.
    pub(crate) ipsets: IpsetCollection,
    /// Fixed-window failure counter pool for autohostlist promotion (`hostfail_pool`).
    pub(crate) fail_pool: RefCell<HostFailPool>,
    /// Precomputed `<func>_<profile_n>_<func_n>` instance labels aligned 1:1 with `DesyncProfile::actions`.
    pub(crate) action_instances: Vec<String>,
    /// Last monotonic boottime second when file-backed lists were checked via `stat(2)`.
    last_reload_check_sec: Cell<i64>,
}

/// Full packet, IP endpoint, and hostname tuple evaluated during `zapret2` `dp_match` selection.
pub(crate) struct FullMatchInput<'a> {
    /// Baseline L3/L4/L7/mark filters evaluated by [`DesyncProfile::matches`].
    pub(crate) base: ProfileMatchInput,
    /// Primary target (or destination) IP address checked against `ipset`.
    pub(crate) primary_ip: IpAddr,
    /// Optional peer source IP address checked in dual-IP ICMP/raw-IP paths.
    pub(crate) reverse_ip: Option<IpAddr>,
    /// Discovered domain or IP literal hostname (`None` when unknown).
    pub(crate) hostname: Option<&'a str>,
    /// `true` when `hostname` is an IP string (`no_match_subdomains`).
    pub(crate) hostname_is_ip: bool,
}

impl ListRegistry {
    /// Loads and deduplicates all hostlists, ipsets, autohostlists, and debug log files for `config`.
    ///
    /// Returns the path of the first unreadable/unwritable/gzip-invalid list file on error.
    pub(crate) fn load_from_config(
        config: &AppConfig,
    ) -> Result<(Self, Vec<ProfileRuntime>), (PathBuf, std::io::Error)> {
        if let Some(debug_path) = &config.hostlist_auto_debug {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(debug_path)
                .map_err(|err| (debug_path.clone(), err))?;
        }
        Self::load_from_profiles(&config.profiles)
    }

    /// Loads and deduplicates all hostlists and ipsets referenced by `profiles`.
    pub(crate) fn load_from_profiles(
        profiles: &[DesyncProfile],
    ) -> Result<(Self, Vec<ProfileRuntime>), (PathBuf, std::io::Error)> {
        let mut hl_by_path: HashMap<PathBuf, Rc<RefCell<HostlistFile>>> = HashMap::new();
        let mut ip_by_path: HashMap<PathBuf, Rc<RefCell<IpsetFile>>> = HashMap::new();
        let mut hostlists = Vec::new();
        let mut ipsets = Vec::new();
        let mut runtimes = Vec::with_capacity(profiles.len());

        for profile in profiles {
            let rt = build_profile_runtime(
                profile,
                &mut hl_by_path,
                &mut ip_by_path,
                &mut hostlists,
                &mut ipsets,
            )?;
            runtimes.push(rt);
        }

        Ok((Self { hostlists, ipsets }, runtimes))
    }

    /// Resets cached file signatures (`SIGHUP`) and reloads all changed hostlists and ipsets.
    pub(crate) fn reload_all(&self, runtimes: &[ProfileRuntime]) {
        for file in &self.hostlists {
            let mut guard = file.borrow_mut();
            guard.reset_mod_sig();
            if let Err(err) = guard.reload_if_changed()
                && let Some(path) = &guard.path
            {
                eprintln!("hostlist reload '{}': {err}", path.display());
            }
        }
        for file in &self.ipsets {
            let mut guard = file.borrow_mut();
            guard.reset_mod_sig();
            if let Err(err) = guard.reload_if_changed()
                && let Some(path) = &guard.path
            {
                eprintln!("ipset reload '{}': {err}", path.display());
            }
        }
        for rt in runtimes {
            rt.hostlists.ensure_autolists_non_empty();
            rt.last_reload_check_sec.set(i64::MIN);
        }
    }
}

/// Validates every list, autohostlist, ipset, and autohostlist debug log file referenced by `config`.
///
/// Shared by `--dry-run` / startup checks in `nfqws2` (`test_list_files`) so path and privilege-drop
/// diagnostics match [`ListRegistry::load_from_config`] without duplicate file checks.
pub fn verify_config_list_files(config: &AppConfig) -> Result<(), (PathBuf, std::io::Error)> {
    ListRegistry::load_from_config(config).map(|_| ())
}

/// Loads one profile's include/exclude hostlists, optional autohostlist, and CIDR ipsets.
fn build_profile_runtime(
    profile: &DesyncProfile,
    hl_by_path: &mut HashMap<PathBuf, Rc<RefCell<HostlistFile>>>,
    ip_by_path: &mut HashMap<PathBuf, Rc<RefCell<IpsetFile>>>,
    hl_registry: &mut Vec<Rc<RefCell<HostlistFile>>>,
    ip_registry: &mut Vec<Rc<RefCell<IpsetFile>>>,
) -> Result<ProfileRuntime, (PathBuf, std::io::Error)> {
    let mut hl_col = HostlistCollection::default();
    for path in &profile.lists.hostlist {
        let file = get_or_load_hostlist(path, hl_by_path, hl_registry, false)?;
        hl_col.include.push(HostlistRef {
            file,
            is_autolist: false,
        });
    }
    if !profile.lists.hostlist_domains.is_empty() {
        let mut inline = HostlistFile::inline();
        for domain in &profile.lists.hostlist_domains {
            let _ = inline.pool.add_raw_line(domain);
        }
        hl_col.include.push(HostlistRef {
            file: Rc::new(RefCell::new(inline)),
            is_autolist: false,
        });
    }

    let autolist = if let Some(path) = &profile.lists.hostlist_auto {
        let file = get_or_load_hostlist(path, hl_by_path, hl_registry, true)?;
        hl_col.include.push(HostlistRef {
            file: Rc::clone(&file),
            is_autolist: true,
        });
        Some(file)
    } else {
        None
    };

    for path in &profile.lists.hostlist_exclude {
        let file = get_or_load_hostlist(path, hl_by_path, hl_registry, false)?;
        hl_col.exclude.push(file);
    }
    if !profile.lists.hostlist_exclude_domains.is_empty() {
        let mut inline = HostlistFile::inline();
        for domain in &profile.lists.hostlist_exclude_domains {
            let _ = inline.pool.add_raw_line(domain);
        }
        hl_col.exclude.push(Rc::new(RefCell::new(inline)));
    }
    hl_col.ensure_autolists_non_empty();

    let mut ip_col = IpsetCollection::default();
    for path in &profile.lists.ipset {
        let file = get_or_load_ipset(path, ip_by_path, ip_registry)?;
        ip_col.include.push(file);
    }
    if !profile.lists.ipset_ip.is_empty() {
        let mut inline = IpsetFile::inline();
        for token in &profile.lists.ipset_ip {
            let _ = inline.ipset.add_raw_line(token);
        }
        ip_col.include.push(Rc::new(RefCell::new(inline)));
    }
    for path in &profile.lists.ipset_exclude {
        let file = get_or_load_ipset(path, ip_by_path, ip_registry)?;
        ip_col.exclude.push(file);
    }
    if !profile.lists.ipset_exclude_ip.is_empty() {
        let mut inline = IpsetFile::inline();
        for token in &profile.lists.ipset_exclude_ip {
            let _ = inline.ipset.add_raw_line(token);
        }
        ip_col.exclude.push(Rc::new(RefCell::new(inline)));
    }

    let action_instances = profile
        .actions
        .iter()
        .enumerate()
        .map(|(idx, action)| desync_instance_name(&action.func, profile.index, (idx as u32) + 1))
        .collect();

    Ok(ProfileRuntime {
        hostlists: hl_col,
        autolist,
        ipsets: ip_col,
        fail_pool: RefCell::new(HostFailPool::new()),
        action_instances,
        last_reload_check_sec: Cell::new(i64::MIN),
    })
}

/// Returns a deduplicated [`HostlistFile`] handle after initial load (and writable check for autolists).
fn get_or_load_hostlist(
    path: &Path,
    by_path: &mut HashMap<PathBuf, Rc<RefCell<HostlistFile>>>,
    registry: &mut Vec<Rc<RefCell<HostlistFile>>>,
    is_autolist: bool,
) -> Result<Rc<RefCell<HostlistFile>>, (PathBuf, std::io::Error)> {
    if is_autolist {
        verify_autolist_writable_plain(path).map_err(|err| (path.to_path_buf(), err))?;
    }
    if let Some(existing) = by_path.get(path) {
        return Ok(Rc::clone(existing));
    }
    let mut file = HostlistFile::from_path(path.to_path_buf());
    file.load_initial()
        .map_err(|err| (path.to_path_buf(), err))?;
    let shared = Rc::new(RefCell::new(file));
    by_path.insert(path.to_path_buf(), Rc::clone(&shared));
    registry.push(Rc::clone(&shared));
    Ok(shared)
}

/// Ensures an `--hostlist-auto` file is creatable/writable and not compressed with gzip (`nfqws.c`).
fn verify_autolist_writable_plain(path: &Path) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .open(path)?;
    if detect_gzip_and_rewind(&mut file)? {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "gzipped auto hostlists are not supported",
        ));
    }
    Ok(())
}

/// Returns a deduplicated [`IpsetFile`] handle after strict initial parse (`test_list_files`).
fn get_or_load_ipset(
    path: &Path,
    by_path: &mut HashMap<PathBuf, Rc<RefCell<IpsetFile>>>,
    registry: &mut Vec<Rc<RefCell<IpsetFile>>>,
) -> Result<Rc<RefCell<IpsetFile>>, (PathBuf, std::io::Error)> {
    if let Some(existing) = by_path.get(path) {
        return Ok(Rc::clone(existing));
    }
    let mut file = IpsetFile::from_path(path.to_path_buf());
    file.load_initial()
        .map_err(|err| (path.to_path_buf(), err))?;
    let shared = Rc::new(RefCell::new(file));
    by_path.insert(path.to_path_buf(), Rc::clone(&shared));
    registry.push(Rc::clone(&shared));
    Ok(shared)
}

/// Returns `true` when every configured include/exclude hostlist pool on `col` is empty (`PROFILE_HOSTLISTS_EMPTY`).
pub(crate) fn hostlists_are_empty(col: &HostlistCollection) -> bool {
    let inc_empty = col
        .include
        .iter()
        .all(|item| item.file.borrow().pool.is_empty());
    let exc_empty = col.exclude.iter().all(|file| file.borrow().pool.is_empty());
    inc_empty && exc_empty
}

/// Evaluates `profile` + runtime hostlists/ipsets against `input` (`dp_match` in `desync.c:221-290`).
pub(crate) fn profile_matches_full(
    profile: &DesyncProfile,
    rt: &ProfileRuntime,
    input: &FullMatchInput<'_>,
) -> bool {
    if !profile.matches(&input.base) {
        return false;
    }
    let now_sec = boottime_secs();
    let do_reload = rt.last_reload_check_sec.get() != now_sec;
    if do_reload {
        rt.last_reload_check_sec.set(now_sec);
        if rt.hostlists.reload_check().is_err() {
            return false;
        }
    }
    let hl_empty = hostlists_are_empty(&rt.hostlists);
    if rt.autolist.is_none() && input.hostname.is_none() && !hl_empty {
        return false;
    }
    if !rt.ipsets.check(input.primary_ip, input.reverse_ip, !do_reload) {
        return false;
    }
    if rt.autolist.is_some() && input.hostname.is_some() {
        return true;
    }
    if hl_empty {
        return true;
    }
    input
        .hostname
        .is_some_and(|host| rt.hostlists.check(host, input.hostname_is_ip, true).matched)
}

/// Returns the 0-based index of the first active profile matching `input` (`dp_find`).
pub(crate) fn find_matching_profile(
    profiles: &[Rc<DesyncProfile>],
    runtimes: &[ProfileRuntime],
    input: &FullMatchInput<'_>,
) -> Option<usize> {
    profiles
        .iter()
        .zip(runtimes.iter())
        .position(|(profile, rt)| profile_matches_full(profile, rt, input))
}

/// Bundled registry, profile snapshots, and runtime states produced by [`build_swapped_profiles`].
pub(crate) struct SwappedProfiles {
    /// Deduplicated filesystem list handles for the swapped profiles.
    pub(crate) registry: ListRegistry,
    /// Ordered `Rc`-wrapped profiles ready for engine dispatch.
    pub(crate) profiles: Vec<Rc<DesyncProfile>>,
    /// Per-profile hostlist/ipset runtimes and action instance labels.
    pub(crate) runtimes: Vec<ProfileRuntime>,
}

/// Validates Lua desync callbacks and builds runtime state for hot-swapping `profiles`.
pub(crate) fn build_swapped_profiles(
    profiles: Vec<DesyncProfile>,
    runtime: &crate::lua::LuaRuntime,
) -> Result<SwappedProfiles, crate::lua::LuaEngineError> {
    runtime.verify_desync_functions(&profiles)?;
    let (registry, runtimes) = ListRegistry::load_from_profiles(&profiles)
        .map_err(|(_, err)| crate::lua::LuaEngineError::Io(err))?;
    let profiles = profiles.into_iter().map(Rc::new).collect();
    Ok(SwappedProfiles {
        registry,
        profiles,
        runtimes,
    })
}

/// Clears cached cutoffs and per-hostlist state when a flow transitions between profiles (`dp_changed`).
pub(crate) fn on_profile_changed(ctrack: Option<&Rc<RefCell<CtrackEntry>>>) {
    let Some(entry_rc) = ctrack else {
        return;
    };
    let mut entry = entry_rc.borrow_mut();
    entry.lua_in_cutoff = false;
    entry.lua_out_cutoff = false;
    entry.check_done = false;
    entry.hostname_ah_check = false;
}
