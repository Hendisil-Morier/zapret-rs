# ADR-0001: Pure-Rust Cryptographic Primitives & Wire Packet Dissector

## Status

Accepted

## Date

2026-11-27

## Context

`zapret-rs` must dissect, modify, recalculate checksums for, and re-serialize IPv4/IPv6/TCP/UDP/ICMP packets at wire speed, and must also decrypt QUIC Initial packets (`AES-128-GCM`, `AES-128-ECB`, `SHA-256`, `HKDF-SHA256`) to extract SNI hostnames across QUIC v1, v2, and IETF draft versions. Cross-compiling seamlessly to `x86_64-pc-windows-gnu` from Linux without fragile OpenSSL/C toolchains is a primary requirement, while external `ring` usage inside runtime `crypto` previously introduced C/assembly build complexity.

## Decision

Implement all L3/L4 packet parsing/reconstruction in [src/packet/](../../src/packet/) using bounds-checked `ByteReader` slices, and implement FIPS-180-4 SHA-224/SHA-256, RFC 2104 HMAC, RFC 5869 HKDF, FIPS-197 AES-128/192/256, AES-CTR, and NIST SP 800-38D AES-GCM directly in pure Rust under [src/crypto/](../../src/crypto/), moving `ring` exclusively to `[dev-dependencies]` in [Cargo.toml](../../Cargo.toml).

## Alternatives Considered

### Keep `ring` or `openssl` in runtime `[dependencies]`
- **Pros:** Battle-tested C/assembly acceleration and standard APIs.
- **Cons:** Complicates `x86_64-pc-windows-gnu` cross-compilation (`cc`/assembler flags) and expands audit/FFI surface for simple QUIC Initial header-protection/16-byte tag operations.
- **Rejected:** Keeping `ring` in `[dev-dependencies]` preserves cross-verified test vectors (`cargo nextest`) while eliminating runtime C/asm crypto toolchain coupling.

### Delegate L3/L4 parsing to Lua or C helper libraries
- **Pros:** Mirrors legacy C `nfq2` memory structs directly.
- **Cons:** Raw pointer offsets risk memory corruption on malformed packets, truncated TCP options, or broken IPv6 extension chains.
- **Rejected:** `ByteReader` enforces explicit slice bounds (`PacketError`) on every header read.

## Consequences

- `zapret-rs` compiles cleanly to Linux and `x86_64-pc-windows-gnu` with zero runtime OpenSSL or `ring` dependency.
- All AES-GCM/HKDF/SHA-2 outputs remain differential-tested against `ring` vectors in `tests/`.
- Throughput relies on pure-Rust block/GHASH loops (acceptable because QUIC Initial decryption runs only on the first Initial packet of a flow, not bulk encrypted media).
