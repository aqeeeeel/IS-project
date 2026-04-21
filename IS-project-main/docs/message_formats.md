# Message Formats

## AuthenticationChallenge

Fields:
- session_id: Unique authentication session identifier.
- device_id: Target device identity.
- model_id: Protected model identity.
- challenge_id: Challenge identifier.
- challenge_vector: Binary challenge vector.
- server_nonce: Nonce bound to server message.
- issued_at: Epoch seconds.
- timeout_seconds: Validity duration.
- response_bit_length: Required response width.
- ecc_repetition: Optional repetition factor.
- server_message: Authenticated envelope containing canonical payload.

## AuthenticationReply

Fields:
- session_id: Must match challenge session.
- device_id: Replying device identifier.
- server_nonce: Echoed nonce from challenge.
- device_nonce: Device freshness nonce.
- matrix_id: Matrix selector used for encrypted response.
- padding_bits: Padding metadata for bit packing.
- encrypted_response_b64: Base64 ciphertext.
- device_message: Authenticated envelope over canonical reply fields.

## AuthenticationResult

Fields:
- success: Boolean decision.
- session_id: Session reference.
- device_id: Device reference.
- reason: Optional failure reason.
- hamming_distance: Optional mismatch count.
- hamming_ratio: Optional normalized mismatch ratio.
- authenticated_at: Optional success timestamp.
- session_key_b64: Optional derived session key output (server-side use).

## ParameterTransmissionEnvelope

Fields:
- packet: Encoded challenge-selection packet for bitmap mode.
- mode: puf-bitmap or hybrid-aes-gcm.
- hybrid_payload: Optional AES-GCM payload metadata.
- session_key_challenges: Optional deterministic challenge set for key derivation.

## Authenticated envelope format

Both server_message and device_message use:
- nonce
- timestamp
- payload_b64
- tag

Tag calculation is HMAC-SHA256 over nonce, timestamp, and payload bytes in canonical form.
