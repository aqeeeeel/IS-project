# Limitations

## Prototype boundaries

- In-memory database: No durable state or HA behavior.
- No network API server implementation: Flows are orchestrated in-process scripts/tests.
- Simulator-based PUF only: No direct hardware driver integration in this prototype.

## Security limitations

- No secure enclave key storage for device or server secrets.
- No transport-layer identity binding or certificate lifecycle implementation.
- No formal proof of security or protocol verification.

## Performance limitations

- Python implementation optimized for clarity, not throughput.
- Attack benchmark scenarios are illustrative and not exhaustive.
- Large-scale CRP/model extraction workloads are not optimized for distributed execution.

## Testing limitations

- End-to-end tests run deterministic simulation, not physical devices.
- Container simulation validates orchestration, not true inter-device network protocol endpoints.
