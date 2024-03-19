import numpy as np


def test_challenge(comm_scheme, poly):
    """
    Verify that a challenge has the proper norms.
    """
    challenge = poly.pol_to_arr(poly.challenge(kappa=comm_scheme.kappa))
    assert (
        np.linalg.norm(challenge, np.inf) == 1
        and np.linalg.norm(challenge, 1) == comm_scheme.kappa
    )


def test_small_invertible(comm_scheme, poly):
    """
    The difference of two challenges should have an l_inf norm of at most two.
    """
    f = poly.pol_to_arr(poly.small_invertible(comm_scheme.kappa))
    assert np.linalg.norm(f, np.inf) <= 2


def test_hash_equivalence(comm_scheme, poly):
    """
    Our hash function should output the same polynomial given
    the same hash seed.
    """
    uniform_polynomial = poly.uniform_array(3)
    d1 = poly.hash(comm_scheme.kappa, uniform_polynomial)
    d2 = poly.hash(comm_scheme.kappa, uniform_polynomial)
    assert d1 == d2


def test_hash_non_equivalence(comm_scheme, poly):
    """
    Our hash function should NOT output the same polynomial,
    even with a small difference in hash seed.
    """
    uniform_polynomial1 = poly.uniform_array(3)
    uniform_polynomial2 = uniform_polynomial1[:-1]
    d1 = poly.hash(comm_scheme.kappa, uniform_polynomial1)
    d2 = poly.hash(comm_scheme.kappa, uniform_polynomial2)
    assert not d1 == d2


def test_hash_no_seed(comm_scheme, poly):
    """
    Hashes should be random if no seed is supplied.
    """
    set_of_hashes = dict()
    for _ in range(100):
        pol = poly.hash(comm_scheme.kappa)
        set_of_hashes[pol] = set_of_hashes.get(pol, 0) + 1

    assert len(set_of_hashes) == 1
