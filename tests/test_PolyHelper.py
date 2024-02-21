import pytest
from utils.PolyHelper import PolyHelper
import numpy as np
from numpy.polynomial import Polynomial as pol
from numpy.polynomial import polynomial as polMath


@pytest.fixture
def q():
    return 3


@pytest.fixture
def coeff():
    return np.array([1, 2])  # 1 + 2x


@pytest.fixture
def poly(coeff):
    return pol(coeff)


@pytest.fixture
def ph(q):
    return PolyHelper(5, q)


def test_matmul_matrices(poly, coeff, q, ph):
    """
    Multiply a 2x2 matrix with a 2x2 matrix and see if the result is proper.
    """
    expected = pol(2 * polMath.polymul(coeff, coeff) % q)
    matrix_1 = np.array(
        [[poly, poly], [poly, poly]])
    matrix_2 = np.copy(matrix_1)
    prod = ph.matmul(matrix_1, matrix_2)
    for row in prod:
        for col in row:
            assert pol.has_samecoef(col, expected)


def test_matmul_vector_matrix(poly, ph):
    """
    Multiply a vector of length 2 with a 2x2 matrix when all entries are 
    polynomials. 
    """
    arr = np.array([poly, poly])
    matrix = np.array(
        [[poly, poly], [poly, poly]])
    res = ph.matmul(arr, matrix)
    singleRowCol = ph.polymul(poly, poly)
    oneMultiplication = ph.add(singleRowCol, singleRowCol)[0]

    for poly in res:
        assert pol.has_samecoef(oneMultiplication, poly)
