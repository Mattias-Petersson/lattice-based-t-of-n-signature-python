import pytest

from BDLOP18.BDLOPCommScheme import BDLOPCommScheme
from type.classes import CommitOpen


@pytest.fixture
def honest_f(comm_scheme):
    return comm_scheme.honest_func()


@pytest.fixture
def commit_open_honest(commit, honest_f) -> CommitOpen:
    commit, c = commit
    return CommitOpen(c, commit, honest_f)


def test_faulty_kappa():
    with pytest.raises(ValueError) as excinfo:
        BDLOPCommScheme(N=50, kappa=51)
    assert (
        str(excinfo.value)
        == "Kappa needs to be smaller than N to make a valid challenge."
    )


def test_commit_r_open(comm_scheme, commit, honest_f):
    """
    A commit with r_open and a honest verifier should work.
    """
    commit, _ = commit
    commit.r = comm_scheme.r_open()
    c = comm_scheme.commit(commit)
    assert comm_scheme.open(CommitOpen(c, commit, honest_f))


def test_commit_r_commit(comm_scheme, commit_open_honest):
    """
    A commit with r_commit and a honest verifier should work.
    """
    assert comm_scheme.open(commit_open_honest)


def test_commit_random_f(comm_scheme, commit, poly):
    """
    A commit where f is not from an honest verifier should fail.
    """
    commit, c = commit
    other_f = poly.small_invertible(comm_scheme.kappa)
    assert not comm_scheme.open(CommitOpen(c, commit, other_f))
