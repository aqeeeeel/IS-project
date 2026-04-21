# Security Assumptions

## Cryptographic assumptions

- HMAC-SHA256 and AES-GCM primitives are unbroken in configured usage.
- Keys and nonces are generated with sufficient entropy.
- Message verification uses constant-time tag comparison.

## System assumptions

- Device identity seed remains secret and stable per device.
- Enrollment hash remains confidential to enrolled peers.
- Challenge nonces and timestamps are not reused outside protocol expectations.
- Server clock skew remains bounded relative to timeout windows.

## Operational assumptions

- Lockout and query-limit policy values are chosen to match threat tolerance.
- Audit logs are retained and protected against tampering.
- Deployment environment secures Python runtime and dependency supply chain.

## Modeling assumptions

- Surrogate model quality is sufficient to validate legitimate devices under configured thresholds.
- Noise profile at authentication time is similar to enrollment/tuning assumptions.
- Fuzzy/ECC configuration balances false reject and false accept risks.
