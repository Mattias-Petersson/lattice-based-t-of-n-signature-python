import pytest
import numpy as np

from SecretSharing.SecretShare2 import SecretShare


@pytest.fixture
def secret_share(comm_scheme):
    return SecretShare((2, 4), comm_scheme.q)


@pytest.fixture
def p1_r(secret_share, poly):
    p1 = poly.uniform_element()
    r = secret_share.share_poly(p1)
    return p1, r


def test_valid_restructuring(secret_share, poly, cypari):
    """
    t-out-of-n participants should get the same polynomial back.
    """
    p1 = poly.uniform_element()
    r = secret_share.share_poly(p1)
    p2 = secret_share.reconstruct_poly(r[:2])
    assert cypari(p1 == p2)


def test_too_many_participants(secret_share, p1_r, cypari):
    """
    We should allow more than t participants to contribute without the program
    failing. Regression only allows the exact number of t, but we should account
    for that and slice the array properly to give the developer some leeway.
    """
    p1, r = p1_r
    p2 = secret_share.reconstruct_poly(r[:-1])
    assert cypari(p1 == p2)


def test_too_few_participants(secret_share, p1_r, cypari):
    """
    Fewer than t participants should not return the same polynomial.
    """
    p1, r = p1_r
    p2 = secret_share.reconstruct_poly([r[0]])
    assert not cypari(p1 == p2)


def test_random_order(secret_share, p1_r, cypari):
    """
    We should allow arbitrary ordering of the elements
    sent in to reconstruct the polynomial.
    """
    p1, r = p1_r
    indices = np.random.choice(
        range(secret_share.n), size=secret_share.t, replace=False
    )
    r = [r[i] for i in indices]
    p2 = secret_share.reconstruct_poly(r)
    assert cypari(p1 == p2)
