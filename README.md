# Phoenix – Post-Quantum Electronic Voting

**Verifiable Voting with Delay-Use Malicious-Ballot-Box Privacy**

## Requirements

- Python 3.9+
- [TenSEAL](https://github.com/OpenMined/TenSEAL) ≥ 0.3.14
- NumPy ≥ 1.24

## Running the Benchmark

The benchmark checks Phoenix efficiency by measuring time (in seconds) to **encrypt + sign + prove** a ballot for k-bit payloads (k = 1, 5, 10, 25).
```bash
python run_benchmark.py
```

WARNING: This is an academic proof-of-concept implementation and has NOT been audited for production use.

| Component | Instantiation | Assumption | Security |
|-----------|--------------|-----------|----------|
| Encryption | BFV (TenSEAL) | RLWE | 128-bit PQ |
| Zero-Knowledge Proof | ABDLOP (Lyubashevsky et al. CRYPTO 2022) | MSIS + MLWE | 128-bit |
| Signature | FHS (leveled, context-hiding) | SIS | 128-bit PQ |
| Hash | SHA-256 | Collision resistance | 128-bit |

All proofs are made non-interactive via the Fiat–Shamir transform in the random oracle model.