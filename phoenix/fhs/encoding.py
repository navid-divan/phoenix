import numpy as np
from ..params import FHSParams

class VectorEncoder:
    def __init__(self, params: FHSParams = None):
        self.params = params or FHSParams()

    def encode(self, bit: int) -> np.ndarray:
        n = self.params.n
        q = 2**self.params.log_q
        return np.full((n,), bit, dtype=np.int64) % q

    def unpack(self, R: np.ndarray, index: int) -> np.ndarray:
        # index-based unpacking
        return R.copy()