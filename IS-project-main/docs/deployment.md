# Deployment Guide

## Prerequisites

- Python 3.11+
- PowerShell (Windows) or compatible shell
- Optional: Docker and Docker Compose for containerized simulation

## Local setup

1. Bootstrap environment:

```powershell
./scripts/bootstrap.ps1
```

2. Run all validations and simulations from one command:

```powershell
.venv/Scripts/python.exe scripts/run_all.py --with-attack --with-demo
```

## Dockerized simulation

Build and run server/device/test simulation stack:

```powershell
docker compose -f docker/docker-compose.yml up --build --abort-on-container-exit
```

Services:
- puf-server-sim: Runs end-to-end server/device auth + model transfer demo.
- puf-device-sim: Runs attack benchmark simulation from device-role perspective.
- puf-tests: Runs full pytest suite.

## CI-friendly command

Use the same single local command in CI:

```powershell
python scripts/run_all.py --with-attack --with-demo
```

Exit code is non-zero if demo, attack simulation, or tests fail.
