import pytest
import numpy as np

from BGV122.BGV import BGV
from type.classes import SecretSharePoly


@pytest.fixture(scope="session")
def bgv():
    return BGV(tn=(3, 5))


@pytest.fixture(scope="session", autouse=True)
def make_Dkgen(bgv):
    return bgv.DKGen()


@pytest.fixture()
def get_t_entries(bgv, make_Dkgen):
    _, sec = make_Dkgen
    indices = np.random.choice(bgv.n, size=bgv.t, replace=False)
    return [sec[i] for i in indices]


def test_all_a_match(bgv):
    """
    Ensure that all sums of a match.
    """
    all_a = [part.sum_a for part in bgv.participants]
    assert len(set(all_a)) == 1


def test_all_b_match(bgv):
    """
    Ensure that all sums of b match.
    """
    all_b = [part.sum_b for part in bgv.participants]
    assert len(set(all_b)) == 1


def test_s(bgv, get_t_entries):
    """
    The summed up s of all s_i from all participants
    should be the same as the reconstructed version of
    t secret keys.
    """

    all_s = bgv.recv_value("s")
    all_s_sum = sum([i.data for i in all_s])
    polynomials = [
        SecretSharePoly(x=sk.x, p=sk.commit.m) for sk in get_t_entries
    ]
    new_s = bgv.secret_share.reconstruct_poly(polynomials)
    assert new_s == all_s_sum


def test_valid_comb(bgv, get_t_entries):
    """
    Test that a valid combination of secret keys always
    decrypt properly.
    """
    m = bgv.get_message()
    u, v = bgv.enc(m)
    d = bgv.t_dec(get_t_entries, u)
    decrypted = bgv.comb(v, d)
    assert decrypted == m


def test_all_participants(bgv, make_Dkgen):
    """
    All participants participating should be able to
    decrypt properly.
    """
    _, sec = make_Dkgen
    m = bgv.get_message()
    u, v = bgv.enc(m)
    d = bgv.t_dec(sec, u)
    assert bgv.comb(v, d) == m


def test_invalid_comb(bgv, make_Dkgen):
    """
    Too few participants attempting to decrypt should
    not succeed.
    """
    _, sec = make_Dkgen
    m = bgv.get_message()
    u, v = bgv.enc(m)
    d = bgv.t_dec([sec[0]], u)
    decrypted = bgv.comb(v, d)
    assert not decrypted == m
