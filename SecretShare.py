import random

from utils.Polynomial import Polynomial
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
    return (res_arr, aPoly)


def reconstruct(x_arr, aPoly):
    cypari = cypari2.Pari()
    sum_arr = []
    print(x_arr)
    for i in x_arr:
        sum = 0
        for j in x_arr:
            if i != j:
                sum += j / (j - i)
        sum_arr.append(sum)
    resSum = 0
    for i in range(len(x_arr)):
        resSum += sum_arr[i] * cypari.centerlift(aPoly)(x=x_arr[i])
    return resSum


res_arr, aPoly = share(10, 4, 2, 2**32 - 527)
print(reconstruct(res_arr[:2], aPoly))
