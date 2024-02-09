# from __future__ import print_function

import sys
from pysnark.runtime import snark, PrivVal
from pysnark.libsnark.backend import prove_only, verify_only, keygen_only
from pysnark.branching import if_then_else

@snark
def booleans(x, y):
    return x>y

print("The bool of", sys.argv[1], "and", sys.argv[2], "is", booleans(int(sys.argv[1]), int(sys.argv[2])))
keygen_only("pysnark_pk", "pysnark_vk")
prove_only("pysnark_pk", "pysnark_log", "pysnark_pubvals")
verify_only("pysnark_log", "pysnark_pubvals", "pysnark_vk")