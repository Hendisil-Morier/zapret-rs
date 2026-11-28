# ADR-0005: Bounded Conntrack, Reassembly Memory & NFQUEUE Drain Ceilings

## Status

Accepted

## Date

2026-11-27

## Context

Unbounded packet-processing pools create Denial-of-Service amplification vectors under port scans, spoofed SYN floods, or stalled multi-segment TLS streams: a flood of synthetic flows could exhaust memory in `ConntrackPool`, `IpCache`, or `HostFailPool`, interleaved partial TLS handshakes could amplify `Vec<u8>` buffers indefinitely across concurrent connections, and an uninterrupted flood of NFQUEUE messages could starve timer callbacks, `SIGHUP`, and control-socket commands.

## Decision

Apply explicit, configurable resource ceilings across the packet pipeline:

- **Flow & lookup pool eviction:** Cap `ConntrackPool` at `DEFAULT_CTRACK_MAX_ENTRIES = 65_536` flows ([src/conntrack/types.rs](../../src/conntrack/types.rs)), `HostFailPool` at `DEFAULT_MAX_HOSTFAIL_ENTRIES = 16_384` hosts with `16` siblings/parent ([src/lists/hostfail.rs](../../src/lists/hostfail.rs)), and `IpCache` with bounded capacity (`src/lists/ipcache.rs`), evicting oldest entries when full.
- **Global reassembly & delayed packet memory budget:** Bound concurrent `StreamReassembler` allocations and queued delayed packets across *all* flows using a shared `GlobalBufferBudget` defaulting to `32 MiB` (`DEFAULT_GLOBAL_REASM_BUDGET_BYTES` in [src/conntrack/reasm.rs](../../src/conntrack/reasm.rs)), plus `16 KiB` (`TCP_MAX_REASM`/`UDP_MAX_REASM`) and `64` delayed packets (`RAW_PACKET_QUEUE_DELAYED_MAX`) per flow.
- **NFQUEUE batch cap:** Limit each `QueueCatcher` `poll()` wakeup to `MAX_NFQUEUE_BATCH_PACKETS = 64` messages ([src/intercepter/nfqueue.rs](../../src/intercepter/nfqueue.rs)) before returning control to timers, signal checks, and control-socket commands.
- **Bounded control IPC framing:** Reject control frames exceeding `MAX_CONTROL_LINE_BYTES = 64 KiB` ([src/control/codec.rs](../../src/control/codec.rs)).

## Alternatives Considered

### Per-flow limits without a shared global byte budget
- **Pros:** Simpler per-entry `StreamReassembler` allocation without `Rc<Cell<usize>>` accounting.
- **Cons:** An attacker opening `65,536` simultaneous flows, each holding `16 KiB` reassembly + `64` delayed packets, could allocate over `1 GiB` before hitting `max_entries`.
- **Rejected:** `GlobalBufferBudget` bounds multi-flow amplification to `32 MiB` while releasing reserved bytes deterministically upon completion, overflow, or purge.

### Drain NFQUEUE until `EAGAIN`/`EWOULDBLOCK` unconditionally
- **Pros:** Fewer `poll()` syscalls under sustained saturation.
- **Cons:** Continuous high-rate traffic starves `ControlServer` (`stop`/`reload_config`), `SIGHUP`, Lua `TimerPool`, and `do_gc()` indefinitely.
- **Rejected:** Yielding every `64` packets bounds worst-case control/timer latency with negligible syscall overhead.

## Consequences

- Memory growth from network traffic and control clients stays bounded even under adversarial loads.
- Multi-segment TLS ClientHello reassembly gracefully falls back to immediate unreassembled evaluation (`Pass` / normal single-packet probe) whenever global or per-flow budgets saturate, rather than dropping connections.
