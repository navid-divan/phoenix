import hashlib

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def collision_resistant_hash(data: bytes) -> str:
    # sha-256 for 128-bit collision resistance
    return hashlib.sha256(data).hexdigest()