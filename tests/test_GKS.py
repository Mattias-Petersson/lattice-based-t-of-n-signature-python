import pytest

from GKS23.GKS import GKS
from Models.values import default_values


@pytest.fixture(scope="session")
def bgv():
    return GKS(**default_values)


@pytest.fixture(scope="session", autouse=True)
def participants_KGen(bgv):
    return bgv.KGen()


def test_same_pk(participants_KGen):
    """
    The way the public key is defined, they should be the same for all
    participants.
    """
    all_pk = [u.pk for u in participants_KGen]
    all_a = [i[0][0] for i in all_pk]
    all_y = [i[1] for i in all_pk]
    assert len(set(all_a)) == 1
    assert len(set(all_y)) == 1
