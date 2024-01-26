from sympy import *
import numpy as np
x, y, z = symbols('x,y,z')
init_printing(use_unicode=False, wrap_line=False)
N = 2048
q = 16801793
p = Poly(x**N + 1, modulus=q)
print(p.domain)
p2 = Poly(x**(N+2) + 1, modulus=q)
r = Poly(p2.rem(p), modulus=q)
print(r)

p3 = (Poly(-12288*x, modulus=q)  * (p - Poly(2*x**N, modulus=q)))
print(p3)
print(p3.rem(p))
import matplotlib.pyplot as plt
mean = np.zeros(N)
cov = np.diag(np.ones(N))
x = np.random.default_rng().multivariate_normal(mean, cov, 5000).T

plt.plot(x[0], x[1], 'x')

plt.axis('equal')

plt.show()