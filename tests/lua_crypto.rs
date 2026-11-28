//! Integration tests for pure-Rust SHA-2/HKDF/AES/AES-GCM primitives and Lua crypto bindings.

/// Interior mutability and single-thread sharing for passing mocked [`PacketSender`] handles.
use std::cell::RefCell;
/// Path type used to load unmodified `zapret2` Lua scripts.
use std::path::Path;
/// Single-thread reference counting for the mock packet sender.
use std::rc::Rc;

/// Reference AEAD and digest implementations used as an independent oracle in unit checks.
use ring::aead::{AES_128_GCM, AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
/// Reference SHA-256 implementation used to cross-check variable-length message digests.
use ring::digest::{SHA256, digest};

/// Shared mock `CapturingSender` and unmodified `zapret-lib.lua` path constant.
mod common;

/// Mock raw sender capturing any packets emitted during Lua execution.
use common::{CapturingSender, ZAPRET_LIB_LUA};
/// Pure-Rust crypto API under test.
use zapret_rs::crypto::{AesKey, HashAlg, aes_ctr_crypt, aes_gcm_crypt, hkdf_sha2, sha2_hash};
/// Embedded `zapret2`-compatible LuaJIT runtime and configuration.
use zapret_rs::lua::{LuaConfig, LuaRuntime};

/// Path to `zapret2`'s unmodified `zapret-tests.lua`.
const ZAPRET_TESTS_LUA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/lua/zapret-tests.lua");

/// Decodes a lowercase/uppercase hexadecimal string into raw bytes.
fn hex(s: &str) -> Vec<u8>
{
    assert_eq!(s.len() % 2, 0, "hex string must have even length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex byte"))
        .collect()
}

/// Evaluates a Lua snippet returning raw binary string bytes via `mlua::LuaString`.
fn eval_lua_bytes(rt: &LuaRuntime, expr: &str) -> Vec<u8>
{
    rt.lua()
        .load(expr)
        .eval::<mlua::LuaString>()
        .expect("Lua expression must return byte string")
        .as_bytes()
        .to_vec()
}

/// Evaluates a Lua snippet returning `(out_bytes, tag_bytes)` as raw byte vectors.
fn eval_lua_gcm(rt: &LuaRuntime, expr: &str) -> (Vec<u8>, Vec<u8>)
{
    let (out, tag): (mlua::LuaString, mlua::LuaString) = rt
        .lua()
        .load(expr)
        .eval()
        .expect("Lua AES-GCM expression must return two strings");
    (
        out.as_bytes()
            .to_vec(),
        tag.as_bytes()
            .to_vec(),
    )
}

/// Asserts that evaluating `expr` raises a Lua error containing `expected_substr`.
fn assert_lua_err(rt: &LuaRuntime, expr: &str, expected_substr: &str)
{
    let err = rt
        .lua()
        .load(expr)
        .exec()
        .expect_err("Lua snippet unexpectedly succeeded");
    let msg = err.to_string();
    assert!(msg.contains(expected_substr), "expected error containing '{expected_substr}', got: {msg}");
}

/// Runs `zapret2`'s unmodified `zapret-tests.lua::test_crypto()` suite inside [`LuaRuntime`].
#[test]
fn zapret_tests_test_crypto_passes()
{
    let sender = Rc::new(RefCell::new(CapturingSender::default()));
    let rt = LuaRuntime::with_sender(LuaConfig::default(), sender).expect("LuaRuntime should initialize");
    rt.exec_file(Path::new(ZAPRET_LIB_LUA))
        .expect("zapret-lib.lua should load");
    rt.exec_file(Path::new(ZAPRET_TESTS_LUA))
        .expect("zapret-tests.lua should load");
    rt.exec_str("test_crypto()")
        .expect("unmodified zapret-tests.lua test_crypto() must pass");
}

/// Verifies FIPS 180-4 SHA-224/SHA-256 vectors and cross-checks SHA-256 against `ring::digest`.
#[test]
fn sha2_kats_and_ring_oracle()
{
    let cases = [
        (
            "",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
        ),
        (
            "abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
        ),
        (
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525",
        ),
    ];

    let rt = LuaRuntime::new(LuaConfig::default()).expect("LuaRuntime should initialize");
    for (msg, exp256, exp224) in cases
    {
        assert_eq!(sha2_hash(HashAlg::Sha256, msg.as_bytes()), hex(exp256));
        assert_eq!(sha2_hash(HashAlg::Sha224, msg.as_bytes()), hex(exp224));

        rt.lua()
            .globals()
            .set("msg_in", msg)
            .expect("set msg_in");
        assert_eq!(eval_lua_bytes(&rt, "return hash('sha256', msg_in)"), hex(exp256));
        assert_eq!(eval_lua_bytes(&rt, "return hash('sha224', msg_in)"), hex(exp224));
    }

    for len in 0..=140usize
    {
        let data: Vec<u8> = (0..len)
            .map(|i| ((i * 37) ^ 0x5a) as u8)
            .collect();
        let expected = digest(&SHA256, &data);
        assert_eq!(sha2_hash(HashAlg::Sha256, &data), expected.as_ref());
    }
}

/// Verifies RFC 5869 HKDF vectors, `nil` parameters, SHA-224 consistency, and boundary `okm_len`.
#[test]
fn hkdf_rfc5869_and_boundary_lengths()
{
    let ikm = vec![0x0b; 22];
    let tc1_salt = hex("000102030405060708090a0b0c");
    let tc1_info = hex("f0f1f2f3f4f5f6f7f8f9");
    let tc1_okm = hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    let tc3_okm = hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");

    assert_eq!(hkdf_sha2(HashAlg::Sha256, Some(&tc1_salt), &ikm, &tc1_info, 42).expect("tc1"), tc1_okm);
    assert_eq!(hkdf_sha2(HashAlg::Sha256, None, &ikm, &[], 42).expect("tc3 nil"), tc3_okm);

    let rt = LuaRuntime::new(LuaConfig::default()).expect("LuaRuntime should initialize");
    let g = rt
        .lua()
        .globals();
    g.set(
        "tc1_salt",
        rt.lua()
            .create_string(&tc1_salt)
            .unwrap(),
    )
    .unwrap();
    g.set(
        "tc_ikm",
        rt.lua()
            .create_string(&ikm)
            .unwrap(),
    )
    .unwrap();
    g.set(
        "tc1_info",
        rt.lua()
            .create_string(&tc1_info)
            .unwrap(),
    )
    .unwrap();

    assert_eq!(eval_lua_bytes(&rt, "return hkdf('sha256', tc1_salt, tc_ikm, tc1_info, 42)"), tc1_okm);
    assert_eq!(eval_lua_bytes(&rt, "return hkdf('sha256', '', tc_ikm, '', 42)"), tc3_okm);
    assert_eq!(eval_lua_bytes(&rt, "return hkdf('sha256', nil, tc_ikm, nil, 42)"), tc3_okm);

    let nil_ikm = eval_lua_bytes(&rt, "return hkdf('sha256', nil, nil, nil, 16)");
    assert_eq!(nil_ikm, hkdf_sha2(HashAlg::Sha256, None, &[], &[], 16).unwrap());

    let p224_short = eval_lua_bytes(&rt, "return hkdf('sha224', tc1_salt, tc_ikm, tc1_info, 28)");
    let p224_long = eval_lua_bytes(&rt, "return hkdf('sha224', tc1_salt, tc_ikm, tc1_info, 64)");
    assert_eq!(p224_short.as_slice(), &p224_long[..28]);

    rt.exec_str(
        r#"
        assert(hkdf("sha256", "s", "k", "i", 0) == nil)
        assert(#hkdf("sha256", "s", "k", "i", 255 * 32) == 8160)
        assert(hkdf("sha256", "s", "k", "i", 255 * 32 + 1) == nil)
        assert(#hkdf("sha224", "s", "k", "i", 255 * 28) == 7140)
        assert(hkdf("sha224", "s", "k", "i", 255 * 28 + 1) == nil)
        assert(hkdf("sha256", "s", "k", "i", 1000000000) == nil)
        "#,
    )
    .expect("HKDF boundary length checks must match zapret2");
}

/// Verifies FIPS-197 AES-128/192/256 ECB vectors, AES-CTR round-trips, coercion, and carry.
#[test]
fn aes_ecb_fips197_and_ctr_carry()
{
    let pt = hex("00112233445566778899aabbccddeeff");
    let full_key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let fips_vectors = [
        (16usize, "69c4e0d86a7b0430d8cdb78070b4c55a"),
        (24usize, "dda97ca4864cdfe06eaf70a0ec0d7191"),
        (32usize, "8ea2b7ca516745bfeafc49904b496089"),
    ];

    let rt = LuaRuntime::new(LuaConfig::default()).expect("LuaRuntime should initialize");
    let pt_arr: [u8; 16] = pt
        .clone()
        .try_into()
        .unwrap();
    rt.lua()
        .globals()
        .set(
            "pt_blk",
            rt.lua()
                .create_string(&pt)
                .unwrap(),
        )
        .unwrap();

    for (klen, exp_hex) in fips_vectors
    {
        let key = &full_key[..klen];
        let exp = hex(exp_hex);
        let cipher = AesKey::new(key).expect("valid key");
        assert_eq!(
            cipher
                .encrypt_block(&pt_arr)
                .as_slice(),
            exp.as_slice()
        );
        assert_eq!(
            cipher.decrypt_block(
                &exp.as_slice()
                    .try_into()
                    .unwrap()
            ),
            pt_arr
        );

        rt.lua()
            .globals()
            .set(
                "k",
                rt.lua()
                    .create_string(key)
                    .unwrap(),
            )
            .unwrap();
        let ct_lua = eval_lua_bytes(&rt, "return aes(true, k, pt_blk)");
        assert_eq!(ct_lua, exp);
        rt.lua()
            .globals()
            .set(
                "ct_blk",
                rt.lua()
                    .create_string(&ct_lua)
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(eval_lua_bytes(&rt, "return aes(false, k, ct_blk)"), pt);
    }

    let key24 = &full_key[..24];
    let iv_carry: [u8; 16] = [0xff; 16];
    let msg: Vec<u8> = (0..37u8).collect();
    let enc = aes_ctr_crypt(key24, &iv_carry, &msg).unwrap();
    let aes = AesKey::new(key24).unwrap();
    let mut manual = Vec::new();
    for (idx, block_pt) in msg
        .chunks(16)
        .enumerate()
    {
        let ctr = if idx == 0
        {
            [0xff; 16]
        }
        else
        {
            let mut b = [0u8; 16];
            b[15] = (idx - 1) as u8;
            b
        };
        let ks = aes.encrypt_block(&ctr);
        manual.extend(
            block_pt
                .iter()
                .zip(ks.iter())
                .map(|(a, b)| a ^ b),
        );
    }
    assert_eq!(enc, manual);
    assert_eq!(aes_ctr_crypt(key24, &iv_carry, &enc).unwrap(), msg);

    rt.lua()
        .globals()
        .set(
            "ctr_k",
            rt.lua()
                .create_string(&full_key[..16])
                .unwrap(),
        )
        .unwrap();
    rt.lua()
        .globals()
        .set(
            "ctr_iv",
            rt.lua()
                .create_string(iv_carry)
                .unwrap(),
        )
        .unwrap();
    assert_eq!(eval_lua_bytes(&rt, "return aes_ctr(ctr_k, ctr_iv, '')"), Vec::<u8>::new());
    let num_ct = eval_lua_bytes(&rt, "return aes_ctr(ctr_k, ctr_iv, 12345)");
    let str_ct = eval_lua_bytes(&rt, "return aes_ctr(ctr_k, ctr_iv, '12345')");
    assert_eq!(num_ct, str_ct);
}

/// Verifies NIST SP 800-38D Test Case 1 & Test Case 2 plus Lua `aes_gcm` TC5 round-trip.
fn assert_nist_gcm_cases(rt: &LuaRuntime, tc5_k: &[u8])
{
    let (c1, t1) = aes_gcm_crypt(true, &[0u8; 16], &[0u8; 12], &[], &[]).unwrap();
    assert!(c1.is_empty());
    assert_eq!(t1, hex("58e2fccefa7e3061367f1d57a4e7455a").as_slice());

    let (c2, t2) = aes_gcm_crypt(true, &[0u8; 16], &[0u8; 12], &[0u8; 16], &[]).unwrap();
    assert_eq!(c2, hex("0388dace60b6a392f328c2b971b2fe78"));
    assert_eq!(t2, hex("ab6e47d42cec13bdf53a67b21257bddf").as_slice());

    let tc5_iv = hex("cafebabefacedbad");
    let tc5_pt = hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
    let tc5_aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    let tc5_ct = hex("61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c7423\
         73806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598");
    let tc5_tag = hex("3612d2e79e3b0785561be14aaca2fccb");

    let g = rt
        .lua()
        .globals();
    for (k, v) in
        [("k5", tc5_k), ("iv5", tc5_iv.as_slice()), ("pt5", tc5_pt.as_slice()), ("aad5", tc5_aad.as_slice())]
    {
        g.set(
            k,
            rt.lua()
                .create_string(v)
                .unwrap(),
        )
        .unwrap();
    }

    let (lua_ct, lua_tag) = eval_lua_gcm(rt, "return aes_gcm(true, k5, iv5, pt5, aad5)");
    assert_eq!(lua_ct, tc5_ct);
    assert_eq!(lua_tag, tc5_tag);

    g.set(
        "ct5",
        rt.lua()
            .create_string(&lua_ct)
            .unwrap(),
    )
    .unwrap();
    let (dec_pt, dec_tag) = eval_lua_gcm(rt, "return aes_gcm(false, k5, iv5, ct5, aad5)");
    assert_eq!(dec_pt, tc5_pt);
    assert_eq!(dec_tag, tc5_tag);
}

/// Verifies NIST SP 800-38D AES-GCM vectors (12B and 8B IV), decrypt tags, and `ring::aead` parity.
#[test]
fn aes_gcm_nist_arbitrary_iv_and_ring_oracle()
{
    let rt = LuaRuntime::new(LuaConfig::default()).expect("LuaRuntime should initialize");
    let tc5_k = hex("feffe9928665731c6d6a8f9467308308");
    let tc5_pt = hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
    assert_nist_gcm_cases(&rt, &tc5_k);

    // Non-12B IVs (1B, 16B, 60B) + tampered AAD decrypt tag mismatch behavior
    for iv_len in [1usize, 16, 60]
    {
        let iv: Vec<u8> = (0..iv_len)
            .map(|i| (i * 11 + 3) as u8)
            .collect();
        let (c, t) = aes_gcm_crypt(true, &tc5_k, &iv, &tc5_pt, b"aad").unwrap();
        let (p_bad_aad, t_bad_aad) = aes_gcm_crypt(false, &tc5_k, &iv, &c, b"wrong").unwrap();
        assert_eq!(p_bad_aad, tc5_pt);
        assert_ne!(t_bad_aad, t);
    }

    // Cross-check AES-128-GCM and AES-256-GCM (with & without optional AAD) against `ring::aead`
    let iv12 = [0x42u8; 12];
    for (alg, key_len) in [(&AES_128_GCM, 16usize), (&AES_256_GCM, 32usize)]
    {
        let key: Vec<u8> = (0..key_len)
            .map(|i| (i * 7 + 1) as u8)
            .collect();
        for use_aad in [false, true]
        {
            let aad_bytes: &[u8] = if use_aad { b"header-aad" } else { b"" };
            let plain = b"hello wireguard / quic payload test";
            let (our_ct, our_tag) = aes_gcm_crypt(true, &key, &iv12, plain, aad_bytes).unwrap();

            let unbound = UnboundKey::new(alg, &key).unwrap();
            let ring_key = LessSafeKey::new(unbound);
            let mut in_out = plain.to_vec();
            ring_key
                .seal_in_place_append_tag(
                    Nonce::assume_unique_for_key(iv12),
                    Aad::from(aad_bytes),
                    &mut in_out,
                )
                .unwrap();
            assert_eq!(our_ct.as_slice(), &in_out[..plain.len()]);
            assert_eq!(our_tag.as_slice(), &in_out[plain.len()..]);
        }
    }

    // Verify 4-arg omission of optional AAD works cleanly in Lua.
    rt.lua()
        .globals()
        .set(
            "iv12",
            rt.lua()
                .create_string(iv12)
                .unwrap(),
        )
        .unwrap();
    let (no_aad_ct, no_aad_tag) = eval_lua_gcm(&rt, "return aes_gcm(true, k5, iv12, pt5)");
    let (nil_aad_ct, nil_aad_tag) = eval_lua_gcm(&rt, "return aes_gcm(true, k5, iv12, pt5, nil)");
    assert_eq!((no_aad_ct, no_aad_tag), (nil_aad_ct, nil_aad_tag));
}

/// Verifies `zapret2` error parity for malformed crypto arguments and strict string checks.
#[test]
fn crypto_lua_error_parity()
{
    let rt = LuaRuntime::new(LuaConfig::default()).expect("LuaRuntime should initialize");
    assert_lua_err(&rt, "return hash('sha256')", "expect exactly 2 arguments");
    assert_lua_err(&rt, "return hash('sha512', 'abc')", "unsupported hash type sha512");
    assert_lua_err(&rt, "return hash('sha256', 123)", "string expected");
    assert_lua_err(&rt, "return aes(true, 'short', '0123456789abcdef')", "wrong key length 5");
    assert_lua_err(&rt, "return aes(true, '0123456789abcdef', 'short')", "wrong data length 5");
    assert_lua_err(&rt, "return aes(true, 123, '0123456789abcdef')", "string expected");
    assert_lua_err(&rt, "return aes_gcm(true, '0123456789abcdef', '', 'hi')", "zero iv length");
    assert_lua_err(&rt, "return aes_gcm(true, 'badkey', 'iviviviviviv', 'hi')", "wrong key length");
    assert_lua_err(&rt, "return aes_ctr('0123456789abcdef', '12byte_iv_!!', 'hi')", "wrong iv length 12");
    assert_lua_err(&rt, "return aes_ctr('bad', '0123456789abcdef', 'hi')", "wrong key length 3");
    assert_lua_err(&rt, "return hkdf('sha512', nil, 'k', nil, 16)", "unsupported hash type sha512");
    assert_lua_err(&rt, "return hkdf('sha256', nil, 'k', nil, -1)", "hkdf: invalid arg");
}
