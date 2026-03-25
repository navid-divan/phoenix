import time
from typing import Callable, Any, Tuple


def time_function(fn: Callable, *args, **kwargs) -> Tuple[Any, float]:
    start = time.perf_counter()
    result = fn(*args, **kwargs)
    elapsed = time.perf_counter() - start
    return result, elapsed


def average_time(fn: Callable, repetitions: int, *args, **kwargs) -> Tuple[Any, float]:
    times = []
    result = None
    for _ in range(repetitions):
        result, t = time_function(fn, *args, **kwargs)
        times.append(t)
    return result, sum(times) / len(times)