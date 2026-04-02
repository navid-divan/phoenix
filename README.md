# Phoenix Voting System

The core implementation of Phoenix post-quantum verifiable e-voting with delay-use malicious-ballot-box privacy built upon standard BFV encryption of [Microsoft SEAL](https://github.com/microsoft/SEAL) via [TenSEAL](https://github.com/OpenMined/TenSEAL) interface and Lattice-based ZKP of IBM Research's [LaZer](https://github.com/lazer-crypto/lazer) libraries.

## Requirements

- Python 3.9+
- TenSEAL ≥ 0.3.14
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

## Machine-checked Privacy Proof

The `/easycrypt` contains the machine-checked EasyCrypt proof that the **Phoenix** voting system satisfies delay-use malicious-ballotbox ballot privacy (du-mb-BPRIV), as defined by [Dragan et al. (CSF 2022)](https://ieeexplore.ieee.org/document/9919663); `PhoenixSecurity.ec` is the entry point to check proof.

```bash
easycrypt PhoenixSecurity.ec
```

Follow the EasyCrypt installation guide at https://github.com/EasyCrypt/easycrypt.
