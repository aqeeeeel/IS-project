# Architecture

## Goal

Provide a prototype security architecture for PUF-backed model access control and parameter transfer with practical defenses against replay, tampering, query abuse, and noisy response mismatch.

## Components

- common: Shared types, cryptographic helpers, configuration, and noisy-recovery primitives.
- puf: Simulator interface and implementations used for deterministic challenge-response behavior.
- protocol: Authentication and transmission message builders/verifiers.
- server: Enrollment, authentication policy enforcement, and audit logging.
- device: Provisioning storage and authentication reply generation.
- modeling: Surrogate training, metrics, and attack benchmark simulations.
- ml: Parameter-stream and inference harness components.
- encryption: Matrix cipher and optional AES-GCM hybrid utilities.

## Trust boundaries

1. Device boundary: Identity seed and derived response behavior must remain local.
2. Server boundary: Enrollment records, policies, and audit logs are trusted state.
3. Transport boundary: Messages are treated as untrusted until MAC and freshness checks pass.

## Security control map

- Replay defense: NonceTracker + per-session nonce set validation.
- MITM/tamper defense: Authenticated message envelopes over challenge/reply payloads.
- Query abuse defense: Per-device query_limit_per_minute.
- Brute force and repeated failure defense: failed_auth_lockout_threshold + lockout_duration_seconds.
- Noisy response defense: ECC repetition decode and fuzzy recover paths.
- Payload confidentiality for large artifacts: Optional hybrid AES-GCM mode with PUF-derived session key.

## Diagrams

- Architecture graph: ../diagrams/architecture.mmd
- Protocol sequence: ../diagrams/protocol_sequence.mmd

## Related pages

- Threat model: threat_model.md
- Protocol flow: protocol_steps.md
- Message formats: message_formats.md
- Deployment: deployment.md
