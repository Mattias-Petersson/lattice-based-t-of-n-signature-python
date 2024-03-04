import pytest
from BDLOP.BDLOPZK import BDLOPZK
from type.classes import Commit, ProofOfOpenLinear


@pytest.fixture
def r_commit(comm_scheme):
    return comm_scheme.r_commit()


@pytest.fixture
def r_open(comm_scheme):
    return comm_scheme.r_open()


@pytest.fixture
def ZK(comm_scheme):
    return BDLOPZK(comm_scheme)


def test_proof_of_opening_r_commit(ZK, r_commit):
    """
    A proof of opening should not throw an exception
    with an r from a commitment scheme's commit.
    """
    try:
        ZK.proof_of_opening(r_commit)
    except Exception as e:
        pytest.fail("Unhandled exception: {}".format(e))


def test_proof_of_opening_r_open(ZK, r_open):
    """
    A proof of opening should not throw an exception
    with an r from a commitment scheme's open.
    """
    try:
        ZK.proof_of_opening(r_open)
    except Exception as e:
        pytest.fail("Unhandled exception: {}".format(e))


def test_proof_of_specific_opening_r_open(ZK, r_open):
    """
    A proof of opening should not throw an exception
    with an r from a commitment scheme's open.
    """
    try:
        ZK.proof_of_specific_opening(r_open)
    except Exception as e:
        pytest.fail("Unhandled exception: {}".format(e))


def test_proof_of_specific_open_valid(ZK, commit):
    """
    Verify that a proof of opening returns True for a valid r.
    """
    commit, c = commit
    proof = ZK.proof_of_specific_opening(commit.r)
    assert ZK.verify_proof_of_specific_opening(
        c[0][0], c[0][1], *proof, commit.m
    )


def test_proof_of_open_valid(ZK, commit):
    """
    Verify that a proof of opening returns True for a valid r.
    """
    commit, c = commit
    proof = ZK.proof_of_opening(commit.r)
    assert ZK.verify_proof_of_opening(c[0][0], *proof)


def test_proof_of_open_invalid(ZK, commit, r_open):
    """
    Verify that a proof of opening returns False when sending in a
    different r.
    """
    commit, c = commit
    proof = ZK.proof_of_opening(r_open)
    assert not ZK.verify_proof_of_opening(c[0][0], *proof)


def test_proof_of_linear(ZK, comm_scheme, poly, cypari):
    num: range = range(2)
    m = poly.uniform_array(comm_scheme.l)
    g = tuple(comm_scheme.get_challenge() for _ in num)
    r = tuple(comm_scheme.r_commit() for _ in num)
    c = tuple(
        comm_scheme.commit(Commit(cypari(g * m), r)) for g, r in zip(g, r)
    )
    *proofs, u, d = ZK.proof_of_linear_relation(*r, *g)
    proofs = tuple[ProofOfOpenLinear, ProofOfOpenLinear](
        ProofOfOpenLinear(c, g, proof=proof)
        for c, g, proof in zip(c, g, proofs)
    )
    assert ZK.verify_proof_of_linear_relation(*proofs, u, d)


def test_proof_of_sum(ZK, comm_scheme, poly, cypari):
    m = tuple(poly.uniform_array(comm_scheme.l) for _ in range(2))
    num: range = range(3)
    g = tuple(comm_scheme.get_challenge() for _ in num)
    r = tuple(comm_scheme.r_commit() for _ in num)
    proof, *rest = ZK.proof_of_sum(*r, *g)
    c1 = comm_scheme.commit(Commit(cypari(g[2] * m[0]), r[0]))
    c2 = comm_scheme.commit(Commit(cypari(g[2] * m[1]), r[1]))
    c3 = comm_scheme.commit(Commit(cypari(g[0] * m[0] + g[1] * m[1]), r[2]))
    proof = tuple[ProofOfOpenLinear, ProofOfOpenLinear, ProofOfOpenLinear](
        ProofOfOpenLinear(c, g, proof=proof)
        for c, g, proof in zip((c1, c2, c3), g, proof)
    )
    assert ZK.verify_proof_of_sum(proof, *rest)
