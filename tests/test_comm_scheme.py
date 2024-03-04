import pytest
import numpy as np

from BDLOP.CommitmentScheme import CommitmentScheme
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


def test_faulty_kappa():
    with pytest.raises(ValueError) as excinfo:
        CommitmentScheme(N=50, kappa=51)
    assert (
        str(excinfo.value)
        == "Kappa needs to be smaller than N to make a valid challenge."
    )


def test_func_norm(comm_scheme, poly):
    """
    The function to open is the difference of two small challenges.
    As such this should have an l_inf norm of at most two.
    """
    f = poly.pol_to_arr(comm_scheme.func_open())
    assert np.linalg.norm(f, np.inf) <= 2


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
