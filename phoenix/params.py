from dataclasses import dataclass, field
from typing import Optional

@dataclass
class BFVParams:
    # 128-bit pq security
    poly_modulus_degree: int = 4096
    plain_modulus: int = 1032193


@dataclass
class ZKPParams:
    # abdlop params
    module_rank: int = 4
    ring_degree: int = 64
    log_modulus: int = 32
    challenge_space_bits: int = 256
    commitment_randomness_bound: int = 2**14
    security_bits: int = 128


@dataclass
class FHSParams:
    # sis-based params
    n: int = 64
    log_q: int = 22
    d_max: int = 30
    tag_bits: int = 128
    max_dataset_size: int = 1
    security_bits: int = 128