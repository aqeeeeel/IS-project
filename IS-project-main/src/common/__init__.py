"""Shared types and utilities for the prototype."""

from .config import AppConfig, load_config
from .crypto_utils import (
    NonceTracker,
    aesgcm_decrypt_optional,
    aesgcm_encrypt_optional,
    build_authenticated_message,
    derive_session_key,
    generate_nonce,
    safe_json_dumps,
    verify_authenticated_message,
)
from .fuzzy import (
    FuzzyHelper,
    NoisyRecoveryProfile,
    build_recovery_profile,
    fuzzy_enroll,
    fuzzy_recover,
    recover_noisy_bits,
    repetition_decode,
    repetition_encode,
)
from .hashing import blake2b_hex, compare_digest, hmac_sha256_hex, sha256_hex
from .logging_utils import configure_logging, get_logger
from .serialization import from_json, to_json
from .types import (
    Challenge,
    IdentityTag,
    MatrixMetadata,
    Nonce,
    ParameterPayload,
    ProtocolMessage,
    ProtocolMessageType,
    Response,
)

__all__ = [
    "AppConfig",
    "Challenge",
    "IdentityTag",
    "MatrixMetadata",
    "NonceTracker",
    "FuzzyHelper",
    "NoisyRecoveryProfile",
    "Nonce",
    "aesgcm_decrypt_optional",
    "aesgcm_encrypt_optional",
    "ParameterPayload",
    "ProtocolMessage",
    "ProtocolMessageType",
    "Response",
    "blake2b_hex",
    "build_authenticated_message",
    "compare_digest",
    "derive_session_key",
    "build_recovery_profile",
    "fuzzy_enroll",
    "fuzzy_recover",
    "recover_noisy_bits",
    "repetition_decode",
    "repetition_encode",
    "safe_json_dumps",
    "configure_logging",
    "from_json",
    "generate_nonce",
    "get_logger",
    "hmac_sha256_hex",
    "load_config",
    "sha256_hex",
    "to_json",
    "verify_authenticated_message",
]
