import numpy as np


class Polynomial:

    def __init__(self, N , q, arr = np.zeros(1024)):
        self.N = N
        self.q = q
        self.arr = arr
    
    def __add__(self, poly2):
        res = np.zeros(self.N)
        for i in range(0, self.N):
            res[i] = (self.arr[i] + poly2.arr[i]) % self.q
        return Polynomial(self.N, self.q, res)
    
    def __mul__(self, poly2):
        temp = np.zeros(self.N)
        for i in range(0, self.N):
            for j in range(0, self.N):
                temp[(i+j) % self.N] = (temp[(i+j) % self.N] + (self.arr[i] * poly2.arr[j])) % self.q
        return Polynomial(self.N, self.q, temp)
    
    def __repr__(self):
        return self.arr.__str__()

    def __str__(self):
        return self.arr.__str__()
    
def convert3dToPoly(x, N, q):
    nodes = [[Polynomial(N, q, x[i][j]) for j in range(len(x[0]))] for i in range(len(x))]
    return np.array(nodes)

def convert2dToPoly(x, N, q):
    nodes = [Polynomial(N, q, x[i])  for i in range(len(x))]
    return np.array(nodes)

