import pytest

from BDLOP.CommitmentScheme import CommitmentScheme
from type.classes import Commit
from utils.Polynomial import Polynomial

pytest.fixture(scope="session")


@pytest.fixture
def comm_scheme():
    return CommitmentScheme()


@pytest.fixture
def cypari(comm_scheme):
    return comm_scheme.cypari


@pytest.fixture
def poly(comm_scheme):
    return Polynomial(comm_scheme.N, comm_scheme.q)


@pytest.fixture
def commit(comm_scheme):
    return comm_scheme.get_commit()


@pytest.fixture
def commit_object(comm_scheme, poly):
    comm: Commit = Commit(
        poly.uniform_array(comm_scheme.l),
        comm_scheme.r_commit(),
    )
    return comm


@pytest.fixture
def commit_to_message(comm_scheme, commit_object):
    return comm_scheme.commit(commit_object)
