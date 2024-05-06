import pytest
import numpy as np

from BGV12.BGV import BGV
from type.classes import SecretSharePoly
from utils.values import default_values


@pytest.fixture(scope="session")
def bgv():
    return BGV(**default_values)


@pytest.fixture(scope="session", autouse=True)
def participants_KGen(bgv):
    return bgv.DKGen()


@pytest.fixture()
def get_t_participants(bgv, participants_KGen):
    indices = np.random.choice(bgv.n, size=bgv.t, replace=False)
    return [participants_KGen[i] for i in indices]


def test_all_a_match(participants_KGen):
    """
    Ensure that all sums of a match.
    """
    all_a = [part.sum_a for part in participants_KGen]
    assert len(set(all_a)) == 1


def test_all_b_match(participants_KGen):
    """
    Ensure that all sums of b match.
    """
    all_b = [part.sum_b for part in participants_KGen]
    assert len(set(all_b)) == 1


def test_s(bgv, get_t_participants):
    """
    The summed up s of all s_i from all participants
    should be the same as the reconstructed version of
    t secret keys.
    """

    all_s = bgv.recv_value("s")
    all_s_sum = sum([i.data for i in all_s])
    polynomials = [
        SecretSharePoly(x=p.x, p=p.sk.commit.m) for p in get_t_participants
    ]
    new_s = bgv.secret_share.reconstruct_poly(polynomials)
    assert new_s == all_s_sum


def test_valid_comb(bgv, get_t_participants):
    """
    Test that a valid combination of secret keys always
    decrypt properly.
    """
    part = next(iter(get_t_participants))
    m = bgv.get_message()
    ctx = bgv.enc(part, m)
    d = bgv.t_dec(get_t_participants, ctx)
    decrypted = bgv.comb(part, ctx, d)
    assert decrypted == m


def test_all_participants(bgv, participants_KGen):
    """
    All participants participating should be able to
    decrypt properly.
    """
    part = next(iter(participants_KGen))
    m = bgv.get_message()
    ctx = bgv.enc(part, m)
    d = bgv.t_dec(participants_KGen, ctx)
    assert bgv.comb(part, ctx, d) == m


def test_invalid_comb(bgv, participants_KGen):
    """
    Too few participants attempting to decrypt should
    not succeed.
    """
    parts = participants_KGen[: bgv.t - 1]
    part = next(iter(parts))
    m = bgv.get_message()
    ctx = bgv.enc(part, m)
    d = bgv.t_dec(parts, ctx)
    decrypted = bgv.comb(part, ctx, d)
    assert not decrypted == m


def test_participant_enc(bgv, get_t_participants):
    part = next(iter(get_t_participants))
    m = bgv.get_message()
    ctx = part.enc(m)
    lagrange = bgv.participant_lagrange(get_t_participants)
    d = [p.t_dec(ctx, x) for p, x in zip(get_t_participants, lagrange)]
    decrypted = part.comb(ctx, d)
    assert decrypted == m


def test_participant_comb(bgv, get_t_participants):
    """
    A participant should be able to combine shares they received, without
    needing to invoke the comb from the parent.
    """
    one_part = next(iter(get_t_participants))
    m = bgv.get_message()
    ctx = bgv.enc(one_part, m)
    d = bgv.t_dec(get_t_participants, ctx)
    decrypted = bgv.comb(one_part, ctx, d)
    decrypted2 = one_part.comb(ctx, d)
    assert decrypted == decrypted2 == m
