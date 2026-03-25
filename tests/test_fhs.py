import pytest
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from phoenix.fhs.scheme import FHSScheme
from phoenix.params import FHSParams

def test_fhs_sign_verify():
    params = FHSParams(n=32, log_q=16, d_max=10, tag_bits=64)
    fhs = FHSScheme(params)
    pk, sk = fhs.setup()
    vk = fhs.keygen(pk, "voter1")
    msg = b"test_message"
    sig = fhs.sign(sk, vk, "voter1", msg, 0)
    assert fhs.verify(vk, "voter1", msg, sig)


def test_fhs_different_keys():
    params = FHSParams(n=32, log_q=16, d_max=10, tag_bits=64)
    fhs = FHSScheme(params)
    pk, sk = fhs.setup()
    vk1 = fhs.keygen(pk, "voter1")
    vk2 = fhs.keygen(pk, "voter2")
    assert not (vk1["A_tau"] == vk2["A_tau"]).all()