import hashlib

def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_ballot(ballot: dict) -> str:
    raw = (
        ballot.get("ciphertext", b"")
        + str(ballot.get("sigma", "")).encode()
        + str(ballot.get("signature", "")).encode()
    )
    return hashlib.sha256(raw).hexdigest()