# Threat Model

## Scope

The prototype protects model access and parameter transfer using PUF-based authentication, challenge freshness, noisy-response recovery, and optional hybrid encryption.

## Assets

- Device enrollment identity and enrollment hash.
- Challenge-response session integrity.
- Model parameters transferred to authorized devices.
- Derived session keys from PUF response material.
- Audit trail of registration and authentication events.

## Adversaries

- Passive observer: Can read traffic but cannot alter it.
- Active network attacker: Can replay, modify, and inject protocol messages.
- Query abuse attacker: Attempts repeated auth queries to gather CRP signals.
- Model extraction attacker: Tries to fit a surrogate from CRP interactions.
- Device impersonator: Tries to authenticate without correct PUF behavior.

## Attack surfaces and defenses

1. Replay of challenge/reply pairs:
- Defense: Nonce tracking and per-session nonce uniqueness checks.
- Defense: Message authentication tags and max-age checks.

2. Message tampering / MITM:
- Defense: HMAC-authenticated envelopes for challenge and device reply payloads.
- Defense: Payload integrity verification before response decode and decision.

3. Query flooding / CRP harvesting:
- Defense: Per-device query limit per minute.
- Defense: Audit events on query-limit denials.

4. Repeated failed authentication:
- Defense: Failed-attempt counter with lockout duration.
- Defense: Lockout state checked at challenge issue.

5. Noisy PUF response mismatch:
- Defense: Optional ECC repetition decode path.
- Defense: Optional fuzzy recovery bounded by configured max distance.

6. Large payload confidentiality:
- Defense: Optional hybrid mode using PUF-derived session key and AES-GCM.

## Residual risks

- Software-simulated PUFs do not capture full hardware attack behavior.
- In-memory server state is volatile and not hardened for production persistence.
- No formal secure channel binding to network identity beyond message authenticity.
- Side-channel resistance and hardware extraction defenses are out of scope.
