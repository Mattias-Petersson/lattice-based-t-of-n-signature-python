from utils.PolyHelper import PolyHelper
import numpy as np
from numpy.polynomial import Polynomial as pol
from numpy.polynomial import polynomial as polMath
import unittest


class TestMultiplications(unittest.TestCase):
    def setUp(self):
        self.q = 3
        self.coeffs = np.array([1, 2])  # 1 + 2x
        self.poly = pol(self.coeffs)
        self.PH = PolyHelper(5, self.q)

    def test_matmul_matrices(self):
        """
        Multiply a 2x2 matrix with a 2x2 matrix and see if the result is proper.
        """

        expected = pol(2 * polMath.polymul(self.coeffs, self.coeffs) % self.q)
        matrix_1 = np.array(
            [[self.poly, self.poly], [self.poly, self.poly]])
        matrix_2 = np.copy(matrix_1)
        prod = self.PH.matmul(matrix_1, matrix_2)
        for row in prod:
            for col in row:
                self.assertTrue(pol.has_samecoef(col, expected))

    def test_matmul_vector_matrix(self):
        """
        Multiply a vector of length 2 with a 2x2 matrix when all entries are 
        polynomials. 
        """
        arr = np.array([self.poly, self.poly])
        matrix = np.array(
            [[self.poly, self.poly], [self.poly, self.poly]])
        res = self.PH.matmul(arr, matrix)
        singleRowCol = self.PH.polymul(self.poly, self.poly)
        oneMultiplication = self.PH.add(singleRowCol, singleRowCol)[0]

        for poly in res:
            self.assertTrue(pol.has_samecoef(oneMultiplication, poly))


if __name__ == "__main__":
    unittest.main()
