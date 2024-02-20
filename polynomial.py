import math
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
    
    """def __sub__(self, poly2):
        res = np.zeros(self.N)
        for i in range(0, self.N):
            res[i] = (self.arr[i] + poly2.arr[i]) % self.q
        return Polynomial(self.N, self.q, res)"""
    
    def __mul__(self, poly2):
        temp = np.zeros(self.N)
        for i in range(0, self.N):
            for j in range(0, self.N):
                temp[(i+j) % self.N] = (temp[(i+j) % self.N] + (self.arr[i] * poly2.arr[j])) % self.q
        return Polynomial(self.N, self.q, temp)
    
    def __repr__(self):
        return "polynomial:" + self.arr.__str__()

    def __str__(self):
        return  "polynomial:" +  self.arr.__str__()
    
    def isBounded(self, bound):
        sum = 0
        for i in range(self.N):
            temp = self.arr[i]
            if temp > (self.q-1)/2:
                temp = self.q - temp
            sum += temp**2
        sum = math.sqrt(sum)
        return sum < bound
    
    def __eq__(self, b):
        for i in range(self.N):
            if self.arr[i] != b.arr[i]:
                return False
        return True

    def __ne__(self, b):
        return not self.__eq__(b)


    
def convert3dToPoly(x, N, q):
    nodes = [[Polynomial(N, q, x[i][j]) for j in range(len(x[0]))] for i in range(len(x))]
    return np.array(nodes)

def convert2dToPoly(x, N, q):
    nodes = [Polynomial(N, q, x[i])  for i in range(len(x))]
    return np.array(nodes)

p1 = convert3dToPoly([[[0, 1], [0, 2]]], 2, 7)
p2 = convert3dToPoly([[[0, 1]], [[0, 1]]], 2, 7)
p3 = Polynomial(2, 7, np.array([1, 1]))

print("shape: ", np.matmul(p1, p2).shape)
print(p3 * np.matmul(p1, p2)[0][0])
temp = p2
for i in range(len(p2)):
    temp[i] = p3 * temp[i][0]
print(np.matmul(p1, temp))