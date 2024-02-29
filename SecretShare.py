import random

from utils.Polynomial import Polynomial
from cypari2.convert import gen_to_python
import cypari2


def share(val, n, t, q):
    cypari = cypari2.Pari()
    PH = Polynomial(t, q)
    aPoly = ""
    for i in range(1, t):
        aPoly += str(random.randint(0, q - 1)) + "*x^" + str(t - i)
        aPoly += "+"
    aPoly += str(val)
    aPoly = PH.in_rq(cypari.Pol(aPoly))
    res_arr = []
    for i in range(1, n + 1):
        res_arr.append(cypari.centerlift(aPoly)(x=i))
    return res_arr


def share_poly(val, n, t, q):
    ret_arr = []
    for i in pol_to_arr(val):
        ret_arr.append(share(i, n, t, q))
    return ret_arr


def reconstruct_poly(res_arrs, x_arr):
    rec_arr = []
    for i in range(len(res_arrs)):
        internal = []
        for j in range(len(res_arrs[0])):
            internal.append(res_arrs[i][j])
        rec_arr.append(internal)
    ret_arr = []
    for i in range(len(rec_arr)):
        ret_arr.append(reconstruct(rec_arr[i], x_arr))
    return cypari.Pol(ret_arr)


def reconstruct(res_arr, x_arr):
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


def pol_to_arr(pol) -> list[int]:
    cypari = cypari2.Pari()
    pariVec = cypari.Vec(cypari.liftall(pol))
    return gen_to_python(pariVec)


cypari = cypari2.Pari()
res_arr = share(10, 4, 2, 2**32 - 527)
print(res_arr)
print(reconstruct(res_arr[:2], [1, 2]))
ret_arr = share_poly(cypari.Pol("x^2+x^1+1"), 4, 2, 2**32 - 527)
for i in range(len(ret_arr)):
    ret_arr[i] = ret_arr[i][:2]
print(ret_arr)
print(reconstruct_poly(ret_arr, [1, 2]))
