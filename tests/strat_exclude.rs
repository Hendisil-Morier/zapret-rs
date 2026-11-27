//! Unit tests for shared blacklist (`hostlist_exclude`) TOML mutation and list file editing.

use std::fs;

use zapret_rs::config::AppConfig;
use zapret_rs::tools::{
    configured_autohostlist_paths, extract_exclude_domains, mutate_exclude_domains_toml,
    mutate_hostlist_file, parse_clean_domain,
};

#[test]
fn parse_clean_domain_normalizes_urls_and_rejects_bad_chars() {
    assert_eq!(parse_clean_domain(" https://Bank.Example.com/login ").as_deref(), Some("bank.example.com"));
    assert_eq!(parse_clean_domain("bad domain"), None);
    assert_eq!(parse_clean_domain("evil.com\nother.com"), None);
    assert_eq!(parse_clean_domain("nodot"), None);
}

#[test]
fn mutate_exclude_domains_toml_adds_deduplicates_and_removes_cleanly() {
    let base = "qnum = 200\nfwmark = 0x40000000\n\n[[profiles]]\nname = \"p1\"\nfilter_tcp = [\"443\"]\n";
    let added = mutate_exclude_domains_toml(base, "bank.com", true, None).expect("add");
    let cfg = AppConfig::from_toml_str(&added, None).expect("valid cfg");
    assert_eq!(extract_exclude_domains(&cfg), vec!["bank.com".to_owned()]);

    // Duplicate add stays idempotent.
    let dedup = mutate_exclude_domains_toml(&added, "BANK.COM", true, None).expect("dedup");
    let cfg2 = AppConfig::from_toml_str(&dedup, None).expect("valid cfg");
    assert_eq!(extract_exclude_domains(&cfg2), vec!["bank.com".to_owned()]);

    // Removing last entry omits empty key cleanly.
    let removed = mutate_exclude_domains_toml(&dedup, "bank.com", false, None).expect("remove");
    assert!(!removed.contains("hostlist_exclude_domains"));
    let cfg3 = AppConfig::from_toml_str(&removed, None).expect("valid cfg");
    assert!(extract_exclude_domains(&cfg3).is_empty());
}

#[test]
fn configured_autohostlist_paths_and_mutate_hostlist_file_work_end_to_end() {
    let dir = std::env::temp_dir().join(format!("zapret_exclude_{}", std::process::id()));
    fs::create_dir_all(&dir).expect("mkdir");
    let toml = "qnum = 200\nfwmark = 0x40000000\n\n[[profiles]]\nname = \"auto\"\nhostlist_auto = \"autohostlist.txt\"\n";
    let cfg = AppConfig::from_toml_str(toml, Some(&dir)).expect("valid");
    let paths = configured_autohostlist_paths(&cfg);
    assert_eq!(paths, vec![dir.join("autohostlist.txt")]);

    let updated = mutate_hostlist_file(&paths[0], "Blocked.org", true).expect("add");
    assert_eq!(updated, vec!["blocked.org".to_owned()]);
    let emptied = mutate_hostlist_file(&paths[0], "blocked.org", false).expect("remove");
    assert!(emptied.is_empty());

    let _ = fs::remove_dir_all(&dir);
}
