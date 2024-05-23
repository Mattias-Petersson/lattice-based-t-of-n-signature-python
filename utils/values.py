default_values = {
    "q": 2**24 - 879,
    "p": 2**16 - 39,
    "N": 2**10,
    "tn": (3, 5),
    "sigma": 37640,
}

single_use_values = {
    "q": 2**20 - 143,
    "p": 2**16 - 39,
    "N": 2**10,
    "tn": (3, 5),
    "sigma": 2**11,
}
# Q is a large ciphertext modulus.
Q_single = 2**35 - 975
Q_multiple = 2**36 - 527
