import itertools
import pytest
import numpy as np

from SecretSharing.SecretShare import SecretShare
from type.classes import SecretSharePoly


@pytest.fixture
def secret_share(comm_scheme):
    return SecretShare((2, 4), comm_scheme.q)


@pytest.fixture
def p1_r(secret_share, poly):
    p1 = poly.uniform_element()
    r = secret_share.share_poly(p1)
    return p1, r


def test_valid_restructuring(secret_share, poly):
    """
    t-out-of-n participants should get the same polynomial back.
    """
    p1 = poly.uniform_element()
    r = secret_share.share_poly(p1)
    p2 = secret_share.reconstruct_poly(r[: secret_share.t])
    assert p1 == p2


def test_too_many_participants(secret_share, p1_r):
    """
    We should allow more than t participants to contribute without the program
    failing. Regression only allows the exact number of t, but we should account
    for that and slice the array properly to give the developer some leeway.
    """
    p1, r = p1_r
    p2 = secret_share.reconstruct_poly(r[:-1])
    assert p1 == p2


def test_too_few_participants(secret_share, p1_r):
    """
    Fewer than t participants should not return the same polynomial.
    """
    p1, r = p1_r
    p2 = secret_share.reconstruct_poly([r[0]])
    assert not p1 == p2


def test_random_order(secret_share, p1_r):
    """
    We should allow arbitrary ordering of the elements
    sent in to reconstruct the polynomial.
    """
    p1, r = p1_r
    indices = np.random.choice(
        range(secret_share.polynomial.N), size=secret_share.t, replace=False
    )
    r = [r[i] for i in indices]
    p2 = secret_share.reconstruct_poly(r)
    assert p1 == p2


def test_additively_homomorphic(secret_share, p1_r, poly):
    p1, p1_r = p1_r
    p2 = poly.uniform_element()
    p2_r = secret_share.share_poly(p2)
    added = [SecretSharePoly(x=i.x, p=i.p + j.p) for i, j in zip(p1_r, p2_r)]
    reconstructed = secret_share.reconstruct_poly(added)
    assert reconstructed == p1 + p2


def test_invalid_tn(comm_scheme):
    """
    Trying to send in more required participants than the total should throw
    an error.
    """
    with pytest.raises(ValueError):
        SecretShare((5, 4), comm_scheme.q)


def test_not_honest_participant(secret_share, p1_r, poly):
    """
    If one of the participants is not honest and does not have a share of the
    original polynomial, the resulting polynomial should fail.
    """
    p1, r = p1_r
    new_secret = SecretSharePoly(r[0].x, poly.uniform_element())
    p2 = secret_share.reconstruct_poly([new_secret, r[1]])
    assert not p1 == p2


def test_all_combinations(secret_share, p1_r):
    """
    All combinations of t should work when reconstructing the polynomial, as
    long as they are honest.
    """
    p1, r = p1_r
    combs = list(itertools.combinations(r, secret_share.t))
    for c in combs:
        p2 = secret_share.reconstruct_poly(c)
        assert p2 == p1
