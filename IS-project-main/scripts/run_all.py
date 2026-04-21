from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def _run_step(label: str, command: list[str]) -> None:
    print(f"[run_all] {label}: {' '.join(command)}")
    completed = subprocess.run(command, check=False)
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run demo, attack simulation, and tests from one command")
    parser.add_argument("--with-demo", action="store_true", help="Run scripts/demo_end_to_end.py")
    parser.add_argument("--with-attack", action="store_true", help="Run scripts/simulate_attack.py")
    parser.add_argument("--skip-tests", action="store_true", help="Skip pytest execution")
    parser.add_argument("--attack-trials", type=int, default=8, help="Trial count for attack simulation")
    parser.add_argument("--attack-challenge-bits", type=int, default=16, help="Challenge bits for attack simulation")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    python = sys.executable

    if args.with_demo:
        _run_step(
            "demo",
            [python, str(repo_root / "scripts" / "demo_end_to_end.py")],
        )

    if args.with_attack:
        _run_step(
            "attack-simulation",
            [
                python,
                str(repo_root / "scripts" / "simulate_attack.py"),
                "--trials",
                str(args.attack_trials),
                "--challenge-bits",
                str(args.attack_challenge_bits),
            ],
        )

    if not args.skip_tests:
        _run_step("pytest", [python, "-m", "pytest"])

    print("[run_all] Completed successfully")


if __name__ == "__main__":
    main()
