import pytest
import numpy as np
from GKS23.GKS import GKS
from utils.values import default_values, Q_multiple
from type.classes import Ctx, GksPk


@pytest.fixture(scope="session")
def gks():
    revised = np.random.choice([True, False])
    return GKS(Q_multiple, **default_values, revised=revised)


@pytest.fixture(scope="session", autouse=True)
def participants_KGen(gks):
    return gks.KGen()


@pytest.fixture(scope="session")
def sign(gks):
    m = gks.BGV.get_message()
    U = gks.participants[: gks.t]
    return m, U, gks.sign(m, U)


def equal_arrs(*args):
    return all(len(set(i)) == 1 for i in args)


def split_values(lst):
    l_0, l_1 = [], []
    for ctx in lst:
        l_0.append(ctx[0])
        l_1.append(ctx[1])
    return equal_arrs(l_0, l_1)


def test_same_pk(participants_KGen):
    """
    The way the public key is defined, they should be the same for all
    participants.
    """
    all_pk: list[GksPk] = [u.pk for u in participants_KGen]
    all_a = [i.a[1] for i in all_pk]
    all_y = [i.y for i in all_pk]
    assert equal_arrs(all_a, all_y)


def test_same_sum_ctx_s(participants_KGen):
    """
    In key generation, all individual ciphertexts ctx_s_j are summed
    to create ctx_s. All participants should then arrive at the same
    ctx_s.
    """
    all_sum_ctx_s: list[list[Ctx]] = [u.sum_ctx_s for u in participants_KGen]
    assert split_values(all_sum_ctx_s)


def test_same_z(sign):
    """
    Combining shares should produce the same z
    """
    *_, sign = sign
    z_0 = [s.z[0] for s in sign]
    z_1 = [s.z[1] for s in sign]
    assert equal_arrs(z_0, z_1)


def test_verify_valid_signature(gks, sign):
    """
    Ensure that a signature is valid for the same message.
    """
    m, U, sign = sign
    one_part = next(iter(U))
    one_signature = next(iter(sign))
    assert gks.vrfy(m, one_part, one_signature)


def test_verify_invalid_signature(gks, sign):
    """
    Verify that trying to verify an invalid signature fails.
    """
    _, U, sign = sign
    m_prime = gks.BGV.get_message()
    one_part = next(iter(U))
    one_signature = next(iter(sign))
    assert not gks.vrfy(m_prime, one_part, one_signature)
