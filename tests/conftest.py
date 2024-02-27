import pytest

from CommitmentScheme import CommitmentScheme
from utils.Polynomial import Polynomial

pytest.fixture(scope="session")


@pytest.fixture
def comm_scheme():
    return CommitmentScheme()


@pytest.fixture
def poly():
    return Polynomial()


@pytest.fixture
def commit(comm_scheme, poly):
    m = poly.uniform_array(comm_scheme.l)
    r = comm_scheme.r_commit()
    c = comm_scheme.commit(m, r)
    return c, r
