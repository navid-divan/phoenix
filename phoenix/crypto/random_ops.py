# randomness utilities
import os
import numpy as np


def secure_random_bytes(n: int) -> bytes:
    return os.urandom(n)


def discrete_gaussian_sample(sigma: float, size: int) -> np.ndarray:
    samples = np.random.normal(0.0, sigma, size=size)
    return np.round(samples).astype(np.int64)


def uniform_random_matrix(rows: int, cols: int, q: int) -> np.ndarray:
    return np.random.randint(0, q, size=(rows, cols), dtype=np.int64)