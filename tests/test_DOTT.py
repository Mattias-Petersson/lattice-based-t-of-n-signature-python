import pytest

from DOTT21.DOTT import DOTT
from type.classes import CommitOpen


@pytest.fixture
def dott():
    return DOTT()


@pytest.fixture
def commit(dott):
    return dott.make_commit()


def test_valid_com(dott, commit):
    c = dott.com(commit)
    assert dott.open(CommitOpen(c, commit))


def test_invalid_com(dott, commit):
    commit_two = dott.make_commit()
    c = dott.com(commit)
    assert not dott.open(CommitOpen(c, commit_two))


def test_open_with_tc_gen_A(dott, commit):
    """
    The tck Â should behave similarly to the ck Â when it comes to
    opening to a commitment, a randomness and a message.
    """
    dott.Â = dott.tc_gen()[1]
    c = dott.com(commit)
    assert dott.open(CommitOpen(c, commit))
