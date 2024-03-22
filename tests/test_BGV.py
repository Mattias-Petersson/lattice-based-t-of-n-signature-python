import pytest

from BGV122.BGV import BGV


@pytest.fixture(scope="session")
def bgv():
    return BGV()


@pytest.fixture(scope="session", autouse=True)
def make_Dkgen(bgv):
    bgv.DKGen()


def test_all_a_match(bgv):
    """
    Ensure that all sums of a match.
    """
    all_a = [part.sum_a for part in bgv.participants]
    assert len(set(all_a)) == 1


def test_all_b_match(bgv):
    """
    Ensure that all sums of b match.
    """
    all_b = [part.sum_b for part in bgv.participants]
    assert len(set(all_b)) == 1
