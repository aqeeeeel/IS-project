# PUF-based AI Model Protection Prototype

This repository implements a Python prototype that combines Physical Unclonable Functions (PUFs), protocol logic, and cryptographic controls to protect model artifacts and parameter transfer.

## Repository layout

- `src/common`: Shared dataclasses, types, config loading, logging, serialization.
- `src/puf`: PUF challenge-response lifecycle components.
- `src/modeling`: Model metadata and orchestration hooks.
- `src/protocol`: Message and handshake logic.
- `src/encryption`: Encryption adapters and key management stubs.
- `src/server`: Service-side orchestration.
- `src/device`: Device-side logic and attestation stubs.
- `src/ml`: ML-specific integration points.
- `tests`: Unit tests for foundational modules.
- `docs`: Design and architecture notes.
- `diagrams`: Diagram source/export placeholders.
- `scripts`: Utility scripts for setup and testing.
- `docker`: Containerization assets.

## Documentation

The complete documentation set is in `docs/README.md` and includes:

- architecture
- threat model
- protocol steps
- message formats
- security assumptions
- limitations
- deployment guide

Mermaid diagrams are available in `diagrams/architecture.mmd` and `diagrams/protocol_sequence.mmd`.

## Quick start

1. Create and activate a Python 3.11+ virtual environment.
2. Install dependencies:

   ```powershell
   pip install -e .[dev]
   ```

3. Run tests:

   ```powershell
   pytest
   ```

## Single-command project run

After bootstrap, run demo + attack simulation + full tests:

```powershell
.venv/Scripts/python.exe scripts/run_all.py --with-demo --with-attack
```

## Docker simulation

Run server/device/test simulation stack:

```powershell
docker compose -f docker/docker-compose.yml up --build --abort-on-container-exit
```
