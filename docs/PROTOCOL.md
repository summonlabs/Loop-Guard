# Loop Guard framed protocol (version 1)

Loop Guard exposes one service interface: a bounded, framed, length-prefixed protocol over
a TCP loopback connection. This document describes the wire format precisely enough to
implement a peer, and states the trust boundary honestly.

## Trust boundary

Loop Guard does **not** implement authentication, authorisation of peers, or encryption.
There is no keyed mode anywhere in the runtime, no certificate handling and no secret.
The frame digest is an **integrity** check, not a signature: it detects corruption and
accidental truncation, and it does not establish who sent the bytes.

What the runtime *does* enforce is session authority: a session identity is bound to a
socket at handshake time, every subsequent frame must carry that identity and a strictly
increasing sequence number, and no session can ever act under another session's identity,
boot or coordinator epoch. Any deployment that needs peer authentication must terminate
it in front of the loopback listener.

## Frame layout

Every frame is exactly `32 + payload_length + 32` bytes.

| Offset | Size | Field | Notes |
| --- | --- | --- | --- |
| 0 | 4 | magic | `0x3147574C`, the ASCII bytes `LWG1` little endian |
| 4 | 2 | version | `1` |
| 6 | 2 | message type | validated against the closed enumeration |
| 8 | 4 | flags | must be `0`; unknown flags are refused |
| 12 | 8 | session | `0` only in the initial `Hello` |
| 20 | 8 | sequence | strictly increasing per session, starting at `1` |
| 28 | 4 | payload length | refused above `Maxima::kFramePayload` (1 MiB) before allocation |
| 32 | N | payload | canonical little-endian codec |
| 32 + N | 32 | digest | SHA-256 over bytes `[0, 32 + N)` |

Decoding is **total and sticky**: magic, version, type, flags, length and digest are all
validated, trailing bytes are refused, and the first violation fails the decoder
permanently. A failed decoder never yields another frame. Any buffered partial frame at
end of stream is a truncation failure; a truncated frame is never accepted.

## Canonical payload codec

Little-endian, fixed width, no padding, no varints. Integers are `u8`/`u16`/`u32`/`u64`;
strings are a `u32` byte length followed by raw bytes; collections are a `u32` element
count followed by the elements. Every read validates its own bound: a length above the
ceiling is refused **before** any allocation proportional to it, an out-of-domain enum is
refused rather than clamped, a boolean must be exactly `0` or `1`, and a decoder that has
failed stays failed.

## Message types

| Value | Name | Direction | Purpose |
| --- | --- | --- | --- |
| 0 | `Hello` | peer → service | starts a session |
| 1 | `HelloAck` | service → peer | binds the session, returns identity and fence |
| 2 | `Bye` | both | ends the session |
| 3 | `Error` | service → peer | structured refusal |
| 4 | `SetTopology` | operator → service | installs a definition generation |
| 5 | `SetPolicy` | operator → service | installs a containment policy generation |
| 6 | `ConfigurationAccepted` | service → operator | acknowledgement of a configuration step |
| 7 | `SubmitObservation` | worker → service | submits one forwarding observation |
| 8 | `ObservationAccepted` | service → worker | accepted, with an outcome and a reason |
| 9 | `DetectRequest` | operator → service | asks the detection question |
| 10 | `AssessmentReply` | service → operator | the answer, with witnesses and counters |
| 11 | `PlanRequest` | operator → service | asks for a containment plan |
| 12 | `PlanReply` | service → operator | the plan, its outcome and its flags |
| 13 | `ContainIntent` | service → worker | a bounded, time-limited containment intent |
| 14 | `ContainAck` | worker → service | "I received it". Not an effect. |
| 15 | `EffectReport` | worker → service | an independent verified effect |
| 16 | `FindingQuery` | operator → service | asks for the finding table |
| 17 | `FindingReply` | service → operator | finding summaries plus a state digest |
| 18 | `FindingWithdraw` | operator → service | retracts a finding |
| 19 | `StateDigestRequest` | operator → service | asks for a state summary |
| 20 | `StateDigestReply` | service → operator | counts and digests |
| 21 | `FenceAdvance` | operator → service | advances one fence component |
| 22 | `RestartReportRequest` | operator → service | asks what the last restart did |
| 23 | `RestartReportReply` | service → operator | boot, incarnation, epoch and recovery facts |
| 24 | `FindingPublish` | operator → service | publishes a finding for the session's last assessment |
| 25 | `ContainAuthorize` | operator → service | authorizes an intent and dispatches it to workers |

Only `Hello` is accepted before a completed handshake. Every other type arriving on an
unbound socket is refused and the connection is closed.

## Session rules enforced by the coordinator

1. The protocol version in `Hello` must equal the coordinator's. A mismatch is answered
   with a `HelloAck` carrying `Outcome::Unsupported` and the connection is closed.
2. The session identity must be non-zero and must not already be bound to another
   connection. A duplicate claim is answered with `Outcome::AlreadyExists`.
3. Every frame after the handshake must carry the session identity of its socket.
   A frame carrying any other identity is refused with `ReasonCode::WireSessionMismatch`
   and the connection is closed.
4. Frame sequences must strictly increase. A repeated or regressed sequence is refused
   with `ReasonCode::WireSequenceRegressed` and the connection is closed.
5. `DetectRequest` and `ContainAuthorize` bind a fence vector. If it is not the
   coordinator's current fence the request is refused with `Outcome::Stale`; it is never
   reinterpreted under a different generation.
6. `ContainIntent` is only ever sent by the coordinator to worker sessions, and only
   after a bounded, in-scope grant authorised it. A worker's `ContainAck` moves the
   finding to `ContainmentAppliedUnverified`; only a `EffectReport` whose observation is
   exactly bound to the current fence moves it to `ContainmentVerified`.

## Shutdown

A `Bye` frame ends the session. Closing the listener releases a blocked `accept`
immediately, and closing a socket releases a blocked receive, so shutdown never waits for
a deadline to expire. Every wait in the transport is a bounded `select` with a
caller-supplied deadline, and a deadline expiring is reported as `Outcome::Indeterminate`
with the connection left usable rather than being retried silently.
