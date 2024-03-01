import pytest
import numpy as np

from CommitmentScheme import CommitmentScheme
from type.classes import CommitOpen


@pytest.fixture
def honest_f(comm_scheme):
    return comm_scheme.honest_func()


@pytest.fixture
def other_f(comm_scheme):
    return comm_scheme.func_open()


@pytest.fixture
def commit_open_honest(commit, honest_f) -> CommitOpen:
    commit, c = commit
    return CommitOpen(c, honest_f, commit=commit)


@pytest.fixture
def challenge(comm_scheme, poly):
    """
    Returns the challenge, converting q-1 to -1 as these are congruent mod q.
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


def test_func_norm(comm_scheme, poly):
    """
    The function to open is the difference of two small challenges.
    As such this should have an l_inf norm of at most two.
    """
    f = poly.pol_to_arr(comm_scheme.func_open())
    normalized_f = np.array([i - comm_scheme.q if i > 2 else i for i in f])
    assert np.linalg.norm(normalized_f, np.inf) <= 2


def test_commit_r_open(comm_scheme, commit, honest_f):
    """
    A commit with r_open and a honest verifier should work.
    """
    commit, _ = commit
    commit.r = comm_scheme.r_open()
    c = comm_scheme.commit(commit)
    assert comm_scheme.open(CommitOpen(c, honest_f, commit=commit))


def test_commit_r_commit(comm_scheme, commit_open_honest):
    """
    A commit with r_commit and a honest verifier should work.
    """
    assert comm_scheme.open(commit_open_honest)


def test_commit_random_f(comm_scheme, other_f, commit):
    """
    A commit where f is not from an honest verifier should fail.
    """
    commit, c = commit
    assert not comm_scheme.open(CommitOpen(c, other_f, commit=commit))


def test_honest_func(cypari, honest_f):
    assert cypari.type(honest_f) == cypari.type("t_POL")
