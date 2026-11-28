//! Integration tests verifying `resolve_pos`, `resolve_multi_pos`, `resolve_range`, `tls_mod`,
//! and unmodified `zapret2/lua/zapret-tests.lua::test_resolve()`.

/// File path resolution for unmodified `zapret2` Lua scripts and fake packet fixtures.
use std::path::Path;

/// Built-in default blob map providing `fake_default_tls` and `fake_default_http` for `zapret-tests.lua`.
use zapret_rs::config::default_blobs;
/// Embedded `zapret2`-compatible LuaJIT runtime.
use zapret_rs::lua::{LuaConfig, LuaRuntime};
/// TLS probes and SNI/extension extractors used to validate `tls_mod` outputs.
use zapret_rs::protocol::{is_tls_client_hello, tls_find_ext, tls_hello_extract_host, tls_record_len};

/// Path to `zapret2`'s unmodified `zapret-lib.lua`.
const ZAPRET_LIB_LUA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/lua/zapret-lib.lua");
/// Path to `zapret2`'s unmodified `zapret-tests.lua`.
const ZAPRET_TESTS_LUA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/lua/zapret-tests.lua");

/// Reads a binary test fixture from `tests/fixtures/fake/`.
fn read_fake_fixture(name: &str) -> Vec<u8>
{
    let path = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/fake")).join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
}

/// Builds a minimal valid TLS ClientHello with configurable Padding (ext 21) placement.
fn build_synthetic_client_hello(pad_first: bool, with_pad: bool) -> Vec<u8>
{
    let pad_ext = [0x00, 0x15, 0x00, 0x02, 0x00, 0x00];
    let sni_ext = [0x00, 0x00, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x00, 0x05, b'a', b'.', b'c', b'o', b'm'];
    let exts_len = (sni_ext.len() + if with_pad { pad_ext.len() } else { 0 }) as u16;

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // ClientVersion TLS 1.2
    body.extend_from_slice(&[0x42u8; 32]); // Random
    body.push(0); // SessionID len
    body.extend_from_slice(&2u16.to_be_bytes()); // CipherSuites len
    body.extend_from_slice(&[0x13, 0x01]);
    body.extend_from_slice(&[1, 0]); // CompressionMethods
    body.extend_from_slice(&exts_len.to_be_bytes());
    if with_pad && pad_first
    {
        body.extend_from_slice(&pad_ext);
    }
    body.extend_from_slice(&sni_ext);
    if with_pad && !pad_first
    {
        body.extend_from_slice(&pad_ext);
    }

    let hs_len = (body.len() as u32).to_be_bytes();
    let rec_len = ((4 + body.len()) as u16).to_be_bytes();
    let mut out = vec![0x16, 0x03, 0x01, rec_len[0], rec_len[1], 0x01, hs_len[1], hs_len[2], hs_len[3]];
    out.extend_from_slice(&body);
    out
}

/// Executes `zapret2/lua/zapret-tests.lua::test_resolve()` with unmodified scripts and default blobs.
#[test]
fn zapret_tests_resolve_suite_passes_unmodified()
{
    let rt = LuaRuntime::new(LuaConfig::default()).expect("LuaRuntime should initialize");
    for (name, data) in default_blobs()
    {
        rt.set_blob(&name, &data)
            .unwrap_or_else(|e| panic!("set_blob {name} failed: {e}"));
    }
    rt.exec_file(Path::new(ZAPRET_LIB_LUA))
        .expect("zapret-lib.lua should load cleanly");
    rt.exec_file(Path::new(ZAPRET_TESTS_LUA))
        .expect("zapret-tests.lua should load cleanly");
    rt.exec_str("test_resolve()")
        .expect("unmodified test_resolve() must pass");
}

/// Verifies `resolve_pos`, `resolve_multi_pos`, and `resolve_range` edge cases and strict errors in Lua.
#[test]
fn lua_position_markers_and_ranges_match_c_semantics()
{
    let rt = LuaRuntime::new(LuaConfig::default()).expect("LuaRuntime should initialize");
    let http_req = read_fake_fixture("http_iana_org.bin");
    let ch_iana = read_fake_fixture("tls_clienthello_iana_org.bin");
    rt.set_blob("http_iana", &http_req)
        .expect("set_blob http_iana");
    rt.set_blob("tls_iana", &ch_iana)
        .expect("set_blob tls_iana");

    rt.exec_str(
        r#"
        -- Default 1-based vs explicit 0-based indexing on HTTP request
        assert(resolve_pos(http_iana, "http_req", "method") == 1)
        assert(resolve_pos(http_iana, "http_req", "method", true) == 0)
        assert(resolve_pos(http_iana, "http_req", "abs+1", true) == 1)
        assert(resolve_pos(http_iana, "http_req", "-1", true) == #http_iana - 1)

        local h0 = resolve_pos(http_iana, "http_req", "host", true)
        local eh0 = resolve_pos(http_iana, "http_req", "endhost", true)
        local s0 = resolve_pos(http_iana, "http_req", "sld", true)
        local ms0 = resolve_pos(http_iana, "http_req", "midsld", true)
        local es0 = resolve_pos(http_iana, "http_req", "endsld", true)
        assert(string.sub(http_iana, h0 + 1, eh0) == "www.iana.org")
        assert(string.sub(http_iana, s0 + 1, es0) == "iana")
        assert(ms0 == s0 + 2)

        -- TLS markers with +/- signed displacements
        local th0 = resolve_pos(tls_iana, "tls_client_hello", "host", true)
        local teh0 = resolve_pos(tls_iana, "tls_client_hello", "endhost", true)
        assert(string.sub(tls_iana, th0 + 1, teh0) == "iana.org")
        assert(resolve_pos(tls_iana, "tls_client_hello", "host+2", true) == th0 + 2)
        assert(resolve_pos(tls_iana, "tls_client_hello", "sniext", true) + 5 == th0)
        assert(resolve_pos(tls_iana, "tls_client_hello", "extlen", true) < th0)

        -- 1-character SLD ("a.com") points one past SLD (`p + 1 - data`)
        local one_char_http = "GET / HTTP/1.1\r\nHost: a.com\r\n\r\n"
        local oc_sld = resolve_pos(one_char_http, "http_req", "sld", true)
        local oc_midsld = resolve_pos(one_char_http, "http_req", "midsld", true)
        assert(oc_midsld == oc_sld + 1)

        -- resolve_multi_pos drops unresolved markers, sorts, and deduplicates
        local mp = resolve_multi_pos(http_iana, "http_req", "host+2,host,sniext,host", false)
        assert(#mp == 2 and mp[1] == h0 + 1 and mp[2] == h0 + 3)

        -- resolve_range strict vs non-strict and reversed range rejection
        local r_loose = resolve_range(http_iana, "http_req", "sniext,host", false, true)
        assert(r_loose and r_loose[1] == 0 and r_loose[2] == h0)
        assert(resolve_range(http_iana, "http_req", "sniext,host", true, true) == nil)
        assert(resolve_range(http_iana, "http_req", "endhost,host", false, true) == nil)
        assert(resolve_range(http_iana, "http_req", "extlen,sniext", false, true) == nil)

        -- Strict type and validation errors
        local ok_num1, _ = pcall(resolve_pos, 123, "http_req", "host")
        assert(not ok_num1, "numeric arg1 must fail lua_reqlstring")
        local ok_num2, _ = pcall(resolve_pos, http_iana, 123, "host")
        assert(not ok_num2, "numeric arg2 must fail lua_reqstring")
        local ok_num3, _ = pcall(resolve_pos, http_iana, "http_req", 0)
        assert(not ok_num3, "numeric arg3 must fail lua_reqstring")
        local ok_bad_pl, err_pl = pcall(resolve_pos, http_iana, "no_such_pl", "host")
        assert(not ok_bad_pl and string.find(tostring(err_pl), "bad payload type", 1, true))
        local ok_bad_m, err_m = pcall(resolve_pos, http_iana, "http_req", "bogus+1")
        assert(not ok_bad_m and string.find(tostring(err_m), "bad marker", 1, true))
        local ok_rng_cnt, err_rc = pcall(resolve_range, http_iana, "http_req", "host")
        assert(not ok_rng_cnt and string.find(tostring(err_rc), "require 2 markers", 1, true))
        "#,
    )
    .expect("Lua marker assertions must pass");
}

/// Verifies `tls_mod` `sni` resize and `rndsni` mutations against the Rust TLS parser.
fn verify_tls_mod_sni_mutations(tls_mod_fn: &mlua::Function, lua: &mlua::Lua, ch_iana: &[u8])
{
    let shrunk: mlua::LuaString = tls_mod_fn
        .call((
            lua.create_string(ch_iana)
                .unwrap(),
            "sni=a.io",
        ))
        .expect("tls_mod shrink succeeds");
    let shrunk_bytes = shrunk.as_bytes();
    assert!(is_tls_client_hello(&shrunk_bytes, false));
    assert_eq!(tls_record_len(&shrunk_bytes), Some(shrunk_bytes.len()));
    assert_eq!(tls_hello_extract_host(&shrunk_bytes, false).as_deref(), Some("a.io"));

    let grown_sni = "very-long-replacement.example.org";
    let grown: mlua::LuaString = tls_mod_fn
        .call((
            lua.create_string(ch_iana)
                .unwrap(),
            format!("sni={grown_sni}"),
        ))
        .expect("tls_mod grow succeeds");
    let grown_bytes = grown.as_bytes();
    assert!(is_tls_client_hello(&grown_bytes, false));
    assert_eq!(tls_record_len(&grown_bytes), Some(grown_bytes.len()));
    assert_eq!(tls_hello_extract_host(&grown_bytes, false).as_deref(), Some(grown_sni));

    let rnd_sni_blob: mlua::LuaString = tls_mod_fn
        .call((
            lua.create_string(ch_iana)
                .unwrap(),
            "rndsni",
        ))
        .expect("tls_mod rndsni succeeds");
    let rnd_sni_bytes = rnd_sni_blob.as_bytes();
    assert_eq!(rnd_sni_bytes.len(), ch_iana.len());
    let rnd_host = tls_hello_extract_host(&rnd_sni_bytes, false).expect("valid SNI after rndsni");
    assert_eq!(rnd_host.len(), "iana.org".len());
    assert_ne!(rnd_host, "iana.org");
    assert!(rnd_host.as_bytes()[0].is_ascii_lowercase());
    assert_eq!(rnd_host.as_bytes()[rnd_host.len() - 4], b'.');
}

/// Verifies `tls_mod` modifiers (`none`, `sni`, `rndsni`, `rnd`, `dupsid`, `padencap`) and errors.
#[test]
fn lua_tls_mod_handles_all_mutations_and_edge_cases()
{
    let rt = LuaRuntime::new(LuaConfig::default()).expect("LuaRuntime should initialize");
    let ch_iana = read_fake_fixture("tls_clienthello_iana_org.bin");
    let pad_before_sni = build_synthetic_client_hello(true, true);
    let no_pad = build_synthetic_client_hello(false, false);
    let pad_trailing = build_synthetic_client_hello(false, true);
    rt.set_blob("fake_iana", &ch_iana)
        .expect("set_blob fake_iana");
    rt.set_blob("pad_mid", &pad_before_sni)
        .expect("set_blob pad_mid");

    // `none` passes through even arbitrary non-TLS blobs.
    rt.exec_str(
        r#"
        assert(tls_mod("not-a-tls-packet", "none") == "not-a-tls-packet")
        assert(tls_mod("not-a-tls-packet", "") == "not-a-tls-packet")

        local ok_bad, err_bad = pcall(tls_mod, fake_iana, "sni=")
        assert(not ok_bad and string.find(tostring(err_bad), "invalid tls mod list", 1, true))

        local ok_unk, _ = pcall(tls_mod, fake_iana, "unknownmod")
        assert(not ok_unk)

        -- Non-trailing padding extension causes padencap to return nil
        assert(tls_mod(pad_mid, "padencap", "1234") == nil)
        "#,
    )
    .expect("tls_mod passthrough/error/pad-non-trailing assertions must pass");

    let lua = rt.lua();
    let tls_mod_fn: mlua::Function = lua
        .globals()
        .get("tls_mod")
        .expect("tls_mod global");
    verify_tls_mod_sni_mutations(&tls_mod_fn, lua, &ch_iana);

    // Verify `rnd,dupsid` randomizes random[11..43] while duplicating payload's session_id.
    let mut orig_payload = ch_iana.clone();
    let sid_len = usize::from(orig_payload[43]);
    assert_eq!(sid_len, 32);
    orig_payload[44..44 + sid_len].fill(0xA5);
    let duped: mlua::LuaString = tls_mod_fn
        .call((
            lua.create_string(&ch_iana)
                .unwrap(),
            "rnd,dupsid",
            lua.create_string(&orig_payload)
                .unwrap(),
        ))
        .expect("tls_mod rnd,dupsid succeeds");
    let duped_bytes = duped.as_bytes();
    assert_ne!(&duped_bytes[11..43], &ch_iana[11..43]);
    assert_eq!(&duped_bytes[44..44 + sid_len], &orig_payload[44..44 + sid_len]);

    // Verify `padencap` adds ext 21 when absent and grows existing trailing ext 21 without appending bytes.
    let encap_payload = vec![0x77u8; 100];
    let pad_out_1: mlua::LuaString = tls_mod_fn
        .call((
            lua.create_string(&no_pad)
                .unwrap(),
            "padencap",
            lua.create_string(&encap_payload)
                .unwrap(),
        ))
        .expect("padencap insert succeeds");
    let pad1_bytes = pad_out_1.as_bytes();
    assert_eq!(pad1_bytes.len(), no_pad.len() + 4);
    assert_eq!(tls_record_len(&pad1_bytes), Some(pad1_bytes.len() + 100));
    let mut encap_wire_1 = pad1_bytes.to_vec();
    encap_wire_1.extend_from_slice(&encap_payload);
    assert!(is_tls_client_hello(&encap_wire_1, false));
    let (_, ext21_len_1) = tls_find_ext(&encap_wire_1, 21, false).expect("ext 21 inserted");
    assert_eq!(ext21_len_1, 100);

    let pad_out_2: mlua::LuaString = tls_mod_fn
        .call((
            lua.create_string(&pad_trailing)
                .unwrap(),
            "padencap",
            lua.create_string(&encap_payload)
                .unwrap(),
        ))
        .expect("padencap existing trailing succeeds");
    let pad2_bytes = pad_out_2.as_bytes();
    assert_eq!(pad2_bytes.len(), pad_trailing.len());
    assert_eq!(tls_record_len(&pad2_bytes), Some(pad2_bytes.len() + 100));
    let mut encap_wire_2 = pad2_bytes.to_vec();
    encap_wire_2.extend_from_slice(&encap_payload);
    assert!(is_tls_client_hello(&encap_wire_2, false));
    let (_, ext21_len_2) = tls_find_ext(&encap_wire_2, 21, false).expect("ext 21 updated");
    assert_eq!(ext21_len_2, 102);
}
