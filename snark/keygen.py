import sys

from pysnark.libsnark.backend import keygen_only

print("keys of cube", keygen_only("pysnark_pk", "pysnark_vk"))