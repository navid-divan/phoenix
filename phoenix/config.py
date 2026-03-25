import os

ENV = os.environ.get("PHOENIX_ENV", "production")

LOG_LEVEL = os.environ.get("PHOENIX_LOG_LEVEL", "INFO")

DEFAULT_POLICY = "last"

MAX_CANDIDATES = 25

SECURITY_LEVEL = 128

BENCHMARK_REPETITIONS = int(os.environ.get("PHOENIX_BENCH_REPS", "1"))

SUPPORTED_POLICIES = ["first", "last"]