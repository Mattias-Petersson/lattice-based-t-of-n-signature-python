import pytest
from BDLOPZK import BDLOPZK


@pytest.fixture
def r_commit(comm_scheme):
    return comm_scheme.r_commit()


@pytest.fixture
def r_open(comm_scheme):
    return comm_scheme.r_open()


@pytest.fixture
def ZK(comm_scheme):
    return BDLOPZK(comm_scheme)


def test_proof_of_opening(ZK, commit):
    """
    A proof of opening should not throw an exception
    with an r from a commitment scheme.
    """
    _, r = commit
    try:
        ZK.proof_of_opening(r)
    except Exception as e:
        pytest.fail("Unhandled exception: {}".format(e))


def test_verification(ZK, commit):
    """
    Verify that a proof of opening returns True for a valid r.
    """
    c, r = commit
    proof = ZK.proof_of_opening(r)
    assert ZK.verify_proof_of_opening(c[0][0], *proof)


def test_verification_false(ZK, commit, r_open):
    """
    Verify that a proof of opening returns False when sending in a
    different r.
    """
    c, _ = commit
    proof = ZK.proof_of_opening(r_open)
    assert not ZK.verify_proof_of_opening(c[0][0], *proof)
