import random

from utils.Polynomial import Polynomial
from cypari2.convert import gen_to_python
import cypari2


class SecretShare:
    def __init__(self, cypari):
        self.cypari = cypari

    def share(self, val, n, t, q):
        PH = Polynomial(t, q)
        aPoly = ""
        for i in range(1, t):
            aPoly += str(random.randint(0, q - 1)) + "*x^" + str(t - i)
            aPoly += "+"
        aPoly += str(val)
        aPoly = PH.in_rq(self.cypari.Pol(aPoly))
        res_arr = []
        for i in range(1, n + 1):
            res_arr.append(self.cypari.centerlift(aPoly)(x=i))
        return res_arr

    def reconstruct(self, res_arr, x_arr):
        sum_arr = []
        for i in x_arr:
            sum = 0
            for j in x_arr:
                if i != j:
                    sum += j / (j - i)
            sum_arr.append(sum)
        resSum = 0
        for i in range(len(x_arr)):
            resSum += int(sum_arr[i]) * res_arr[i]
        return resSum

    def share_poly(self, val, n, t, q):
        temp_arr = []
        for i in self.pol_to_arr(val):
            temp_arr.append(self.share(i, n, t, q))
        ret_arr = []
        for i in range(len(temp_arr[0])):
            internal = []
            for j in range(len(temp_arr)):
                internal.append(temp_arr[j][i])
            ret_arr.append(self.cypari.Pol(internal))
        return ret_arr

    def reconstruct_poly(self, res_arrs, x_arr):
        rec_arr = []
        for i in range(len(res_arrs)):
            rec_arr.append(self.pol_to_arr(res_arrs[i]))
        arr = []
        for i in range(len(rec_arr[0])):
            internal = []
            for j in range(len(rec_arr)):
                internal.append(rec_arr[j][i])
            arr.append(internal)
        ret_arr = []
        for i in range(len(arr)):
            ret_arr.append(self.reconstruct(arr[i], x_arr))
        return self.cypari.Pol(ret_arr)

    def pol_to_arr(self, pol) -> list[int]:
        cypari = cypari2.Pari()
        pariVec = cypari.Vec(cypari.liftall(pol))
        return gen_to_python(pariVec)

    def test(self):
        PH = Polynomial(4, 2**32 - 527)
        ret_arr = self.share_poly(self.cypari.Pol("x^3+x^2+x^1+1"), 4, 2, 2**32 - 527)
        print("hello: ", ret_arr)
        print(ret_arr[:2])
        print(PH.in_rq(self.reconstruct_poly(ret_arr[:2], [1, 2])))
