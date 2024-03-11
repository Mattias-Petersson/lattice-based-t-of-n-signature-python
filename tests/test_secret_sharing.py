import pytest

from SecretSharing.SecretShare import SecretShare


@pytest.fixture
def secret_share(comm_scheme):
    return SecretShare((2, 4), comm_scheme.q)


def test_valid_restructuring(secret_share, poly, cypari):
    p1 = poly.uniform_element()
    r = secret_share.share_poly(p1)
    p2 = secret_share.reconstruct_poly(r[:2], [1, 2])
    assert cypari(p1 == p2)


def test_invalid_restructuring(secret_share, poly, cypari):
    p1 = poly.uniform_element()
    r = secret_share.share_poly(p1)
    p2 = secret_share.reconstruct_poly(r[-1], [1, 2])
    assert not cypari(p1 == p2)
