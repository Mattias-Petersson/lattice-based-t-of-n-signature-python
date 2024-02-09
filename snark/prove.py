import sys

from pysnark.libsnark.backend import prove_only

print("proof of", prove_only("pysnark_pk", "pysnark_log", "pysnark_pubvals"))