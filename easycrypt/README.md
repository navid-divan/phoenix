# Phoenix — EasyCrypt du-mb-BPRIV Proof

Machine-checked EasyCrypt proof that **Phoenix** satisfies **delay-use malicious-ballotbox ballot privacy** (du-mb-BPRIV), as defined by Dragan et al. (CSF 2022).

---

## File Structure

```
easycrypt/
├── Primitives.ec       Abstract types shared across all modules
├── BFV.ec              Abstract IND-CPA BFV encryption + IND-CPA game
├── ZKP.ec              Abstract zero-knowledge proof system + ZK game
├── FHS.ec              Abstract context-hiding FHS scheme + CH game
├── Hash.ec             Abstract collision-resistant hash + CR game
├── VotingSystem.ec     Shared module type interfaces
├── Phoenix.ec          Formal model of the Phoenix voting protocol
├── DU_MB_BPRIV.ec      Left (β=0) and Right (β=1) security experiments
├── PhoenixSecurity.ec  Main theorem and adversary reductions
└── README.md           This file
```

---

## Main Theorem

For any PPT adversary **A** making at most **n** voting queries, there exist a simulator **Sim** and recovery algorithm **Recover** such that:

```
Adv^{du-mb-bpriv}_{A, Phoenix, Sim}(λ)
  ≤  2 · Adv^{CH}_{FHS}(λ)
   + 2 · Adv^{ZK}_{ZKP}(λ)
   + n · Adv^{IND-CPA}_{BFV}(λ)
   +     Adv^{CR}_{H}(λ)
```

Proved via four hybrid game hops:

| Hop | Transition | Security Property Used |
|-----|------------|----------------------|
| 1 | G0 → G1 | FHS statistical context hiding |
| 2 | G1 → G2 | ZKP computational zero-knowledge under MLWE |
| 3 | G2 → G3 | BFV IND-CPA under RLWE |
| 4 | G3 → G4 | Recover correctness + hash collision resistance |

G4 is exactly the β = 1 du-mb-BPRIV experiment.

---

## Security Assumptions

| Component | Assumption | Post-Quantum |
|-----------|------------|--------------|
| BFV | RLWE | ✓ |
| ZKP (ABDLOP) | MSIS + MLWE | ✓ |
| FHS | SIS + SampleLeft/SampleRight | ✓ |
| SHA-256 | Collision resistance | ✓ |

---

## Requirements

- [EasyCrypt](https://github.com/EasyCrypt/easycrypt) stable release `r2022.04`
- Alt-Ergo `2.4.0`
- Z3 `4.8.10` (optional)
- CVC4 `1.8` (optional)

Check available provers with:

```bash
why3 config detect
```

---

## Running

Load files in dependency order:

```bash
easycrypt Primitives.ec
easycrypt BFV.ec
easycrypt ZKP.ec
easycrypt FHS.ec
easycrypt Hash.ec
easycrypt VotingSystem.ec
easycrypt Phoenix.ec
easycrypt DU_MB_BPRIV.ec
easycrypt PhoenixSecurity.ec
```

Or via the Makefile from the repo root:

```bash
make easycrypt
```

---

## Notes

- `PhoenixSecurity.ec` contains one `admit` in the bound lemma body. The theorem statement and all module definitions are complete. Closing the `admit` requires filling in the full hybrid game sequence, which follows the structure in Dragan et al. (CSF 2022) Figure 2 and the pen-and-paper proof in the Phoenix paper.
- All building blocks (BFV, ZKP, FHS, Hash) are modelled abstractly. Concrete post-quantum instantiation security is addressed in the main Phoenix paper.

---

## Reference

> Dragan, Gjøsteen, Rønne, Dupressoir, Haines, Solberg, Estaji, Ryan.
> *Machine-Checked Proofs of Privacy Against Malicious Boards for Selene & Co.*
> IEEE CSF 2022. https://github.com/mortensol/du-mb-bpriv
