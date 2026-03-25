# Phoenix Voting

The core implementation of Phoenix post-quantum verifiable e-voting system with delay-use malicious-ballot-box privacy.

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

| Component Instantiation | Assumption | Security |
|--------------|-----------|----------|
| BFV (TenSEAL) | RLWE | 128-bit |
| ABDLOP (Lyubashevsky et al. CRYPTO 2022) | MSIS + MLWE | 128-bit |
| FHS (leveled, context-hiding) | SIS | 128-bit |
| SHA-256 | Collision resistance | 128-bit |

All proofs are made non-interactive via the Fiat–Shamir transform in the random oracle model.
