import pytest

from DOTT21.TDCommitmentScheme import TDCommitmentScheme
from type.classes import CommitOpen


@pytest.fixture
def DOTT():
    return TDCommitmentScheme()


@pytest.fixture
def commit(DOTT):
    return DOTT.make_commit()


def test_valid_com(DOTT, commit):
    c = DOTT.com(commit)
    assert DOTT.open(CommitOpen(c, 0, commit=commit))


def test_invalid_com(DOTT, commit):
    commit_two = DOTT.make_commit()
    c = DOTT.com(commit)
    assert not DOTT.open(CommitOpen(c, 0, commit=commit_two))
