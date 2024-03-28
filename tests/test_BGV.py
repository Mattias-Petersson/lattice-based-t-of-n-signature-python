import pytest

from BGV122.BGV import BGV
from type.classes import SecretSharePoly


@pytest.fixture(scope="session")
def bgv():
    return BGV()


@pytest.fixture(scope="session", autouse=True)
def make_Dkgen(bgv):
    return bgv.DKGen()


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


def test_s(bgv, make_Dkgen):
    """
    The summed up s of all s_i from all participants
    should be the same as the reconstructed version of
    t secret keys.
    """

    _, sec = make_Dkgen
    all_s = bgv._BGV__recv_value("s")
    all_s_sum = sum([i.data for i in all_s])
    p1 = SecretSharePoly(x=sec[0].x, p=sec[0].commit.m)
    p2 = SecretSharePoly(x=sec[1].x, p=sec[1].commit.m)
    new_s = bgv.secret_share.reconstruct_poly([p1, p2])
    assert new_s == all_s_sum


def test_valid_comb(bgv, make_Dkgen):
    """
    Test that a valid combination of secret keys always
    decrypt properly.
    """
    _, sec = make_Dkgen
    m = bgv.get_message()
    u, v = bgv.enc(m)
    d = bgv.t_dec(sec, u)
    decrypted = bgv.comb(v, d)
    assert decrypted == m


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
