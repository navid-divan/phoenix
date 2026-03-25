import tenseal as ts
from typing import List

def create_context(poly_modulus_degree: int = 4096, plain_modulus: int = 1032193) -> ts.Context:
    context = ts.context(
        ts.SCHEME_TYPE.BFV,
        poly_modulus_degree=poly_modulus_degree,
        plain_modulus=plain_modulus,
    )
    context.generate_galois_keys()
    context.generate_relin_keys()
    return context


def encrypt(context: ts.Context, value: int) -> bytes:
    enc = ts.bfv_vector(context, [value])
    return enc.serialize()


def decrypt(context: ts.Context, ciphertext_bytes: bytes) -> int:
    enc = ts.bfv_vector_from(context, ciphertext_bytes)
    return enc.decrypt()[0]


def add_ciphertexts(context: ts.Context, ciphertext_list: List[bytes]) -> bytes:
    if not ciphertext_list:
        raise ValueError("empty ciphertext list")
    result = ts.bfv_vector_from(context, ciphertext_list[0])
    for ct_bytes in ciphertext_list[1:]:
        ct = ts.bfv_vector_from(context, ct_bytes)
        result = result + ct
    return result.serialize()