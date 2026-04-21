from __future__ import annotations

import argparse

from modeling.attack_benchmarks import run_attack_benchmarks


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the PUF attack simulation suite")
    parser.add_argument("--challenge-bits", type=int, default=16, help="Challenge width used for the benchmark")
    parser.add_argument("--trials", type=int, default=12, help="Number of trials for each simulation")
    args = parser.parse_args()

    result = run_attack_benchmarks(challenge_bits=args.challenge_bits, trials=args.trials)
    print("Attack benchmark results")
    print(f"Surrogate modeling accuracy: {result.modeling_attack_accuracy:.4f}")
    print(f"Replay attack success rate: {result.replay_success_rate:.4f}")
    print(f"MITM tamper detection rate: {result.mitm_tamper_detection_rate:.4f}")
    print(f"Brute-force success rate: {result.brute_force_success_rate:.6f}")
    print(f"Noise-resilience authentication success rate: {result.noise_resilience_success_rate:.4f}")
    print(f"Query-limit block rate: {result.query_limit_block_rate:.4f}")
    print(f"Lockout activation rate: {result.lockout_activation_rate:.4f}")
    print(f"Session-key consistency rate: {result.session_key_consistency_rate:.4f}")


if __name__ == "__main__":
    main()
