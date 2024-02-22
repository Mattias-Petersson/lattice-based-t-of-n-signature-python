import pytest
from testPolys2Again import CommitmentScheme
from BDLOPZK2 import BDLOPZK
from utils.PolyHelper import PolyHelper
import numpy as np


@pytest.fixture
def commScheme():
    return CommitmentScheme()


@pytest.fixture
def r(commScheme):
    return commScheme.getRCommit()


@pytest.fixture
def ZK(commScheme):
    return BDLOPZK(commScheme)


@pytest.fixture
def PH(commScheme):
    return PolyHelper(commScheme.N, commScheme.q)


@pytest.fixture(autouse=True)
def proofOfOpening(ZK, r):
    return ZK.proofOfOpening(r)


@pytest.fixture
def dr(r, PH,  proofOfOpening):
    *_, d = proofOfOpening
    return PH.polymul(d, r)


@pytest.fixture
def rd(r, PH, proofOfOpening):
    *_, d = proofOfOpening
    return PH.polymul(d, r)


def test_z(PH, proofOfOpening, dr):
    """
    Verify that z is equal to y + dr.
    """
    y, z, *_ = proofOfOpening
    ydr = PH.add(y, dr)
    assert np.array_equiv(ydr, z)


def test_dr_rd(dr, rd):
    """
    Confirms that multiplication is commutative.
    """
    assert np.array_equiv(dr, rd)


def test_A1dr_A1rd(commScheme, PH, dr, rd):
    """
    Confirm that A1 * dr = A1 * rd. If dr = rd
    this should always hold. 
    """
    A1 = commScheme.A1

    A1dr = PH.matmul(A1, dr)
    A1rd = PH.matmul(A1, rd)
    assert np.array_equiv(A1dr, A1rd)


@pytest.mark.skip(reason="We know this does not work for now.")
def test_A1_distributive(commScheme, proofOfOpening, PH, dr):
    """
    Check that A1 * (y + dr) = A1 * y + A1 * dr.
    """
    A1 = commScheme.A1
    y, *_ = proofOfOpening

    ydr = PH.add(y, dr)
    lhs = PH.matmul(A1, ydr)

    A1y = PH.matmul(A1, y)
    A1dr = PH.matmul(A1, dr)
    rhs = PH.add(A1y, A1dr)

    assert np.array_equiv(lhs, rhs)


def test_A1z(commScheme, proofOfOpening, PH, dr):
    """
    Check that A1 * z = A1 * (y + dr)
    """
    A1 = commScheme.A1
    y, z, *_ = proofOfOpening

    lhs = PH.matmul(A1, z)

    ydr = PH.add(y, dr)
    rhs = PH.matmul(A1, ydr)

    assert np.array_equiv(lhs, rhs)


def test_A1d_dA1(commScheme, proofOfOpening, PH, dr, rd):
    *_, d = proofOfOpening
    A1 = commScheme.A1

    lhs = PH.matmul(A1, np.array(d))
    rhs = PH.matmul(np.array(d), A1)
    print()


def test_t_A1dr_A1rd(commScheme, proofOfOpening, PH, dr, rd):
    """
    t + A1dr = t + A1rd should hold, with rd = dr
    """
    A1 = commScheme.A1
    *_, t, _ = proofOfOpening

    A1dr = PH.matmul(A1, dr)
    lhs = PH.add(t, A1dr)

    A1rd = PH.matmul(A1, rd)
    rhs = PH.add(t, A1rd)

    assert np.array_equiv(lhs, rhs)
