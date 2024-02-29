import pytest
import numpy as np

from CommitmentScheme import CommitmentScheme


@pytest.fixture
def message(poly, comm_scheme):
    return poly.uniform_array(comm_scheme.l)


@pytest.fixture
def honest_f(comm_scheme):
    return comm_scheme.honest_func()


@pytest.fixture
def other_f(comm_scheme):
    return comm_scheme.func_open()


@pytest.fixture
def challenge(comm_scheme, poly):
    """
    Returns the challenge as an int array.
    """
    challenge = poly.pol_to_arr(comm_scheme.get_challenge())
    return np.array(
        [i - comm_scheme.q if i == comm_scheme.q - 1 else i for i in challenge]
    )


def test_faulty_kappa():
    with pytest.raises(ValueError) as excinfo:
        CommitmentScheme(N=50, kappa=51)
    assert (
        str(excinfo.value)
        == "Kappa needs to be smaller than N to make a valid challenge."
    )


def test_challenge(challenge, comm_scheme):
    """
    Verify that a challenge has the proper norms.
    """

    assert (
        np.linalg.norm(challenge, np.inf) == 1
        and np.linalg.norm(challenge, 1) == comm_scheme.kappa
    )


def test_commit_r_commit(comm_scheme, message, honest_f):
    """
    A commit with r_commit and a honest verifier should work.
    """
    randomness = comm_scheme.r_commit()
    commit = comm_scheme.commit(message, randomness)
    assert comm_scheme.open(commit, message, randomness, honest_f)


def test_commit_r_open(comm_scheme, message, honest_f):
    """
    A commit with r_open and a honest verifier should work.
    """
    randomness = comm_scheme.r_open()
    commit = comm_scheme.commit(message, randomness)
    assert comm_scheme.open(commit, message, randomness, honest_f)


def test_commit_random_f(comm_scheme, message, other_f):
    """
    A commit where f is not from an honest verifier should fail.
    """
    randomness = comm_scheme.r_commit()
    commit = comm_scheme.commit(message, randomness)
    assert not comm_scheme.open(commit, message, randomness, other_f)
