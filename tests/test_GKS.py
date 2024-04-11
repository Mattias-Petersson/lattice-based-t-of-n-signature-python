import pytest

from GKS23.GKS import GKS
from Models.values import default_values
from type.classes import Ctx, GksPk


@pytest.fixture(scope="session")
def gks():
    return GKS(**default_values)


@pytest.fixture(scope="session", autouse=True)
def participants_KGen(gks):
    return gks.KGen()


@pytest.fixture(scope="session")
def sign(gks):
    m = gks.BGV.get_message()
    U = gks.participants[: gks.t]
    return gks.sign(m, U)


def test_same_pk(participants_KGen):
    """
    The way the public key is defined, they should be the same for all
    participants.
    """
    all_pk: list[GksPk] = [u.pk for u in participants_KGen]
    all_a = [i.a[1] for i in all_pk]
    all_y = [i.y for i in all_pk]
    assert len(set(all_a)) == 1
    assert len(set(all_y)) == 1


def test_same_sum_ctx_s(participants_KGen):
    """
    In key generation, all individual ciphertexts ctx_s_j are summed
    to create ctx_s. All participants should then arrive at the same
    ctx_s.
    """
    all_sum_ctx_s: list[list[Ctx]] = [u.sum_ctx_s for u in participants_KGen]
    s_1, s_2 = [], []
    for ctx_list in all_sum_ctx_s:
        s_1.append(ctx_list[0])
        s_2.append(ctx_list[1])
    assert len(set(s_1)) == 1
    assert len(set(s_2)) == 1
