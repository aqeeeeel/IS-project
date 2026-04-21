# Protocol Steps

## 1. Enrollment

1. Server samples CRPs from a device-specific simulator.
2. Server trains a surrogate verifier and tunes threshold.
3. Server creates an identity tag and matrix metadata set.
4. Server stores policy controls:
- Query limit per minute.
- Failed-auth lockout threshold and duration.
- ECC repetition and fuzzy max distance configuration.
5. Device receives and stores provisioning material.

## 2. Authentication challenge issue

1. Device requests authentication.
2. Server checks lockout state and query budget.
3. Server creates a new session and challenge vector.
4. Server signs challenge payload with enrollment-derived shared key.
5. Server returns challenge message with timeout, nonce, and response bit length.

## 3. Device reply creation

1. Device verifies challenge authenticity and freshness.
2. Device derives response bits from PUF identity and challenge.
3. Device optionally applies repetition encoding for ECC.
4. Device matrix-encrypts response bytes.
5. Device wraps reply metadata in authenticated envelope and returns it.

## 4. Server verification

1. Server validates session state and nonce freshness.
2. Server verifies reply message authenticity.
3. Server decrypts response bits using matrix metadata.
4. Server computes expected bits from surrogate model.
5. Optional noisy recovery path:
- ECC repetition decode.
- Fuzzy recover against expected reference.
6. Server computes Hamming ratio and compares with threshold.
7. On success:
- Session marked authenticated.
- PUF-derived session key material derived and recorded.
- Audit success event emitted.
8. On failure:
- Failure reason recorded.
- Failed-attempt count increments.
- Lockout set when threshold reached.
- Audit failure event emitted.

## 5. Parameter transmission

1. For normal payloads: encode parameter bytes into challenge-selected bitmap transmission.
2. For large payloads (hybrid mode):
- Derive session key from deterministic PUF challenge set.
- Encrypt serialized payload with AES-GCM.
- Transfer encrypted payload plus key-challenge metadata.
3. Device reconstructs key from same PUF challenge set and decrypts/rebuilds parameters.
