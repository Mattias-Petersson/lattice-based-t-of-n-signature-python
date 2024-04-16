from BDLOP16.BDLOP import BDLOP
from BDLOP16.BDLOPCommScheme import BDLOPCommScheme
from BDLOP16.RelationProofs import RelationProver
from SecretSharing.SecretShare import SecretShare
from type.classes import Commit
from utils.Polynomial import Polynomial

PH = Polynomial()
c = BDLOPCommScheme()
zk = BDLOP(c)
s = SecretShare((2, 4), 2**32 - 527)
r = RelationProver(zk, c, s)

m = PH.gaussian_element(1)
r = c.r_commit()
com = c.commit(Commit(m, r))
proof = zk.proof_of_opening(r)
m2 = PH.gaussian_element(1)
r2 = c.r_commit()
com2 = c.commit(Commit(m, r))
proof2 = zk.proof_of_opening(r2)
proof_add = zk.proof_of_opening(r + r2)

print(zk.verify_proof_of_opening(com[0][0] + com2[0][0], proof + proof2))
