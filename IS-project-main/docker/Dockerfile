FROM python:3.11-slim AS base

WORKDIR /app
COPY pyproject.toml README.md ./
COPY docs ./docs
COPY diagrams ./diagrams
COPY scripts ./scripts
COPY src ./src
COPY tests ./tests

RUN pip install --no-cache-dir -e .[dev]

FROM base AS server-sim
CMD ["python", "scripts/demo_end_to_end.py"]

FROM base AS device-sim
CMD ["python", "scripts/simulate_attack.py", "--challenge-bits", "16", "--trials", "8"]

FROM base AS test-runner
CMD ["python", "-m", "pytest"]
