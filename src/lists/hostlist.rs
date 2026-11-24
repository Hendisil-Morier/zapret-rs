//! Domain hostlist pools, subdomain/flag matching (`^`/`!`), reload checks, and collections.

/// Case-normalization clone avoidance when incoming hostnames are already lowercase.
use std::borrow::Cow;
/// Interior mutability for sharing cached hostlist files across profile collections.
use std::cell::RefCell;
/// Hash map mapping normalized hostname tokens to `HOSTLIST_FLAG_*` bitmasks.
use std::collections::HashMap;
/// Filesystem path storage for reloadable hostlist files.
use std::path::{Path, PathBuf};
/// Single-thread reference counting for deduplicating shared hostlist files across profiles.
use std::rc::Rc;

/// Modification signature, token line extractor, and streaming gzip/plain loader helpers.
use crate::lists::file_loader::{
    FileModSig, load_list_initial, parse_list_line_token, read_list_lines, reload_cached_list,
};

/// Flag forbidding subdomain suffix matches (`^` prefix, `HOSTLIST_POOL_FLAG_STRICT_MATCH`).
pub const HOSTLIST_FLAG_STRICT_MATCH: u32 = 1;
/// Flag exempting the matched hostname/suffix (`!` prefix, `HOSTLIST_POOL_FLAG_EXCEMPT`).
pub const HOSTLIST_FLAG_EXEMPT: u32 = 2;
/// Sentinel inserted into empty autohostlists so include checks do not degrade to match-all (`"@&()"`).
pub const EMPTY_AUTOLIST_SENTINEL: &str = "@&()";

/// Result of searching one [`HostlistPool`] for a normalized hostname (`SearchHostList`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostlistSearchResult {
    /// Neither the host nor any eligible parent domain exists in the pool.
    NotFound,
    /// Host or parent domain matched without an exempt flag.
    Matched,
    /// Host or parent domain matched an exempt (`!`) rule before any non-exempt match.
    Exempted,
}

/// Combined outcome returned by [`HostlistCollection::check`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostlistCheckOutcome {
    /// `true` when traffic should be treated as included by the profile's hostlist rules.
    pub matched: bool,
    /// `true` when explicitly excluded by `--hostlist-exclude` or an autohostlist `!` exemption.
    pub excluded: bool,
}

/// Hash-backed hostname/domain matcher with strict (`^`) and exempt (`!`) flags (`hostlist_pool`).
#[derive(Debug, Default, Clone)]
pub struct HostlistPool {
    /// Normalized lowercase host entries mapped to bitflags (`STRICT_MATCH` | `EXEMPT`).
    entries: HashMap<String, u32>,
}

impl HostlistPool {
    /// Creates an empty [`HostlistPool`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if no entries are stored in the pool.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the number of distinct entries stored in the pool.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Removes all host entries from the pool (`HostlistPoolDestroy`).
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Inserts a lowercase-normalized host entry with `flags` if not already present.
    pub fn add_host(&mut self, host: &str, flags: u32) {
        let lower = host.to_ascii_lowercase();
        self.entries.entry(lower).or_insert(flags);
    }

    /// Parses one raw hostlist line (skipping comments, extracting `^`/`!` flags) and adds it.
    pub fn add_raw_line(&mut self, line: &str) -> bool {
        let Some(token) = parse_list_line_token(line) else {
            return true;
        };
        let mut flags = 0u32;
        let mut rest = token;
        while let Some(prefix) = rest.as_bytes().first().copied() {
            match prefix {
                b'^' => flags |= HOSTLIST_FLAG_STRICT_MATCH,
                b'!' => flags |= HOSTLIST_FLAG_EXEMPT,
                _ => break,
            }
            rest = &rest[1..];
        }
        if !rest.is_empty() {
            self.add_host(rest, flags);
        }
        true
    }

    /// Inserts [`EMPTY_AUTOLIST_SENTINEL`] when the pool is empty (`NonEmptyHostlist`).
    pub fn ensure_non_empty(&mut self) {
        if self.entries.is_empty() {
            self.entries
                .insert(EMPTY_AUTOLIST_SENTINEL.to_owned(), 0);
        }
    }

    /// Searches for `host` and, unless `no_match_subdomains`, walks parent domain suffixes.
    pub fn search(&self, host: &str, no_match_subdomains: bool) -> HostlistSearchResult {
        if self.entries.is_empty() {
            return HostlistSearchResult::NotFound;
        }
        let normalized: Cow<'_, str> = if host.bytes().any(|b| b.is_ascii_uppercase()) {
            Cow::Owned(host.to_ascii_lowercase())
        } else {
            Cow::Borrowed(host)
        };

        let mut cursor: &str = normalized.as_ref();
        let mut full_host = true;
        loop {
            if let Some(&flags) = self.entries.get(cursor) {
                let strict_skip = (flags & HOSTLIST_FLAG_STRICT_MATCH) != 0 && !full_host;
                if !strict_skip {
                    if (flags & HOSTLIST_FLAG_EXEMPT) != 0 {
                        return HostlistSearchResult::Exempted;
                    }
                    return HostlistSearchResult::Matched;
                }
            }
            if no_match_subdomains {
                break;
            }
            let Some(dot_idx) = cursor.find('.') else {
                break;
            };
            cursor = &cursor[dot_idx + 1..];
            full_host = false;
        }

        HostlistSearchResult::NotFound
    }
}

/// Reads a plain or gzip hostlist file from disk into a fresh [`HostlistPool`].
fn parse_hostlist_file(path: &Path) -> std::io::Result<HostlistPool> {
    let mut pool = HostlistPool::new();
    read_list_lines(path, |line| {
        let _ = pool.add_raw_line(line);
    })?;
    Ok(pool)
}

/// Single inline or file-backed hostlist paired with its cached modification signature (`hostlist_file`).
#[derive(Debug, Default, Clone)]
pub struct HostlistFile {
    /// Optional backing filesystem path (`None` for inline `--hostlist-domains` pools).
    pub path: Option<PathBuf>,
    /// Last loaded `(mtime_sec, mtime_nsec, size)` signature for change detection.
    pub mod_sig: FileModSig,
    /// In-memory hostname/domain pool.
    pub pool: HostlistPool,
}

impl HostlistFile {
    /// Creates an in-memory inline hostlist without a backing file.
    pub fn inline() -> Self {
        Self::default()
    }

    /// Creates an unloaded file-backed [`HostlistFile`] pointing to `path`.
    pub fn from_path(path: PathBuf) -> Self {
        Self {
            path: Some(path),
            mod_sig: FileModSig::default(),
            pool: HostlistPool::new(),
        }
    }

    /// Clears `mod_sig` so the next reload check forces a full disk reload (`SIGHUP`).
    pub fn reset_mod_sig(&mut self) {
        self.mod_sig.reset();
    }

    /// Strictly loads the backing file at startup (`test_list_files`), failing on I/O or gzip error.
    pub fn load_initial(&mut self) -> std::io::Result<()> {
        load_list_initial(
            self.path.as_deref(),
            &mut self.mod_sig,
            &mut self.pool,
            parse_hostlist_file,
        )
    }

    /// Reloads the file if its signature changed, keeping existing entries on transient access error.
    pub fn reload_if_changed(&mut self) -> std::io::Result<bool> {
        reload_cached_list(
            self.path.as_deref(),
            &mut self.mod_sig,
            &mut self.pool,
            "hostlist",
            HostlistPool::clear,
            parse_hostlist_file,
        )
    }
}

/// Profile include hostlist link distinguishing autohostlists from static lists (`hostlist_item`).
#[derive(Debug, Clone)]
pub struct HostlistRef {
    /// Shared reference to the underlying inline or file-backed hostlist.
    pub file: Rc<RefCell<HostlistFile>>,
    /// `true` when this list is the profile's `--hostlist-auto` list (`b_autolist`).
    pub is_autolist: bool,
}

/// Ordered include and exclude hostlist sets evaluated for one profile.
#[derive(Debug, Default, Clone)]
pub struct HostlistCollection {
    /// Include hostlists (one entry matched => pass; all pools empty => pass all).
    pub include: Vec<HostlistRef>,
    /// Exclude hostlists (checked before `include`; any match denies).
    pub exclude: Vec<Rc<RefCell<HostlistFile>>>,
}

impl HostlistCollection {
    /// Returns `true` when neither include nor exclude hostlists are configured.
    pub fn is_absent(&self) -> bool {
        self.include.is_empty() && self.exclude.is_empty()
    }

    /// Ensures every autolist pool contains at least [`EMPTY_AUTOLIST_SENTINEL`] (`MakeAutolistsNonEmpty`).
    pub fn ensure_autolists_non_empty(&self) {
        for item in &self.include {
            if item.is_autolist {
                item.file.borrow_mut().pool.ensure_non_empty();
            }
        }
    }

    /// Checks and reloads modified include/exclude hostlist files (`HostlistsReloadCheckForProfile`).
    pub fn reload_check(&self) -> std::io::Result<bool> {
        let mut any_changed = false;
        for item in &self.include {
            if item.file.borrow_mut().reload_if_changed()? {
                any_changed = true;
            }
        }
        for file in &self.exclude {
            if file.borrow_mut().reload_if_changed()? {
                any_changed = true;
            }
        }
        if any_changed {
            self.ensure_autolists_non_empty();
        }
        Ok(any_changed)
    }

    /// Evaluates `host` against exclude then include hostlists (`HostlistCheck_`).
    pub fn check(
        &self,
        host: &str,
        no_match_subdomains: bool,
        skip_reload: bool,
    ) -> HostlistCheckOutcome {
        if !skip_reload && self.reload_check().is_err() {
            return HostlistCheckOutcome {
                matched: false,
                excluded: false,
            };
        }

        for ex_file in &self.exclude {
            if ex_file.borrow().pool.search(host, no_match_subdomains)
                == HostlistSearchResult::Matched
            {
                return HostlistCheckOutcome {
                    matched: false,
                    excluded: true,
                };
            }
        }

        if self.include.iter().all(|item| item.file.borrow().pool.is_empty()) {
            return HostlistCheckOutcome {
                matched: true,
                excluded: false,
            };
        }

        let mut excluded = false;
        for item in &self.include {
            match item.file.borrow().pool.search(host, no_match_subdomains) {
                HostlistSearchResult::Matched => {
                    return HostlistCheckOutcome {
                        matched: true,
                        excluded: false,
                    };
                }
                HostlistSearchResult::Exempted if item.is_autolist => {
                    excluded = true;
                }
                HostlistSearchResult::Exempted | HostlistSearchResult::NotFound => {}
            }
        }

        HostlistCheckOutcome {
            matched: false,
            excluded,
        }
    }
}
