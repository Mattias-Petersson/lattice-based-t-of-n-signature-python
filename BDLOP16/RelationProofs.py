from BDLOP16.BDLOP import BDLOP
from BDLOP16.BDLOPCommScheme import BDLOPCommScheme
from type.classes import Commit, ProofOfOpenLinear
from SecretSharing.SecretShare2 import SecretShare


class RelationProver:
    def __init__(
        self, ZK: BDLOP, comm_scheme: BDLOPCommScheme, SSS: SecretShare
    ):
        self.ZK = ZK
        self.comm_scheme = comm_scheme
        self.SSS = SSS

    # Lacks Proof Of Shortness
    def prove_sk(
        self,
        ps,
        pe,
        psi,
        pei,
        a,
        p,
    ):
        r0 = [
            self.comm_scheme.cypari.Pol("0"),
            self.comm_scheme.cypari.Pol("0"),
            self.comm_scheme.cypari.Pol("0"),
        ]
        proof1 = self.ZK.proof_of_sum(ps, pe, r0, a, p, 1)
        proof2 = self.ZK.proof_of_opening(ps)
        proof3 = self.ZK.proof_of_opening(pe)
        proof4 = self.ZK.proof_of_opening(psi)
        proof5 = self.ZK.proof_of_opening(pei)
        proof6 = self.ZK.proof_of_sum(psi, pei, r0, a, p, 1)
        return (proof1, proof2, proof3, proof4, proof5, proof6)

    def verify_sk(
        self,
        proof1,
        proof2,
        proof3,
        proof4,
        proof5,
        proof6,
        b,
        bi,
        a,
        p,
        coms,
        come,
        comsi,
        comei,
    ):
        r0 = [
            self.comm_scheme.cypari.Pol("0"),
            self.comm_scheme.cypari.Pol("0"),
            self.comm_scheme.cypari.Pol("0"),
        ]

        comb = self.comm_scheme.commit(Commit(b, r0))
        proof, *rest = proof1
        proof = tuple[ProofOfOpenLinear, ProofOfOpenLinear, ProofOfOpenLinear](
            ProofOfOpenLinear(c, g, proof=proof)
            for c, g, proof in [
                [coms, a, proof[0]],
                [come, p, proof[1]],
                [comb, 1, proof[2]],
            ]
        )
        if not self.ZK.verify_proof_of_sum(proof, *rest):
            print("False1")
            return False
        if not self.ZK.verify_proof_of_opening(coms[0][0], proof2):
            print("False2")
            return False
        if not self.ZK.verify_proof_of_opening(come[0][0], proof3):
            print("False3")
            return False
        combi = self.comm_scheme.commit(Commit(bi, r0))
        proof, *rest = proof6
        proof = tuple[ProofOfOpenLinear, ProofOfOpenLinear, ProofOfOpenLinear](
            ProofOfOpenLinear(c, g, proof=proof)
            for c, g, proof in [
                [comsi, a, proof[0]],
                [comei, p, proof[1]],
                [combi, 1, proof[2]],
            ]
        )
        if not self.ZK.verify_proof_of_sum(proof, *rest):
            print("False4")
            return False
        if not self.ZK.verify_proof_of_opening(comsi[0][0], proof4):
            print("False5")
            return False
        if not self.ZK.verify_proof_of_opening(comei[0][0], proof5):
            print("False6")
            return False
        return True

    def prove_enc(self, p_r, p_m, p_eprime, p_ebis, a, b, p):
        r0 = [
            self.comm_scheme.cypari.Pol("0"),
            self.comm_scheme.cypari.Pol("0"),
            self.comm_scheme.cypari.Pol("0"),
        ]
        proof1 = self.ZK.proof_of_sum(p_r, p_eprime, r0, a, p, 1)
        proof2 = self.ZK.proof_of_triple_sum(p_r, p_ebis, p_m, r0, b, p, 1, 1)
        proof3 = self.ZK.proof_of_opening(p_r)
        proof4 = self.ZK.proof_of_opening(p_m)
        proof5 = self.ZK.proof_of_opening(p_eprime)
        proof6 = self.ZK.proof_of_opening(p_ebis)
        return (proof1, proof2, proof3, proof4, proof5, proof6)

    def verify_enc(
        self,
        proof1,
        proof2,
        proof3,
        proof4,
        proof5,
        proof6,
        a,
        b,
        p,
        u,
        v,
        com_r,
        com_m,
        com_eprime,
        com_ebis,
    ):
        r0 = [
            self.comm_scheme.cypari.Pol("0"),
            self.comm_scheme.cypari.Pol("0"),
            self.comm_scheme.cypari.Pol("0"),
        ]

        com_u = self.comm_scheme.commit(Commit(u, r0))
        com_v = self.comm_scheme.commit(Commit(v, r0))
        proof, *rest = proof1
        retVal = True
        proof = tuple[ProofOfOpenLinear, ProofOfOpenLinear, ProofOfOpenLinear](
            ProofOfOpenLinear(c, g, proof=proof)
            for c, g, proof in [
                [com_r, a, proof[0]],
                [com_eprime, p, proof[1]],
                [com_u, 1, proof[2]],
            ]
        )
        if not self.ZK.verify_proof_of_sum(proof, *rest):
            # print("fail1")
            retVal = False
        proof, *rest = proof2
        proof = tuple[
            ProofOfOpenLinear,
            ProofOfOpenLinear,
            ProofOfOpenLinear,
            ProofOfOpenLinear,
        ](
            ProofOfOpenLinear(c, g, proof=proof)
            for c, g, proof in [
                [com_r, b, proof[0]],
                [com_ebis, p, proof[1]],
                [com_m, 1, proof[2]],
                [com_v, 1, proof[3]],
            ]
        )
        if not self.ZK.verify_proof_of_triple_sum(proof, *rest):
            # print("fail2")
            retVal = False
        if not self.ZK.verify_proof_of_opening(com_r[0][0], proof3):
            # print("fail3")
            retVal = False
        if not self.ZK.verify_proof_of_opening(com_m[0][0], proof4):
            # print("fail4")
            retVal = False
        if not self.ZK.verify_proof_of_opening(com_eprime[0][0], proof5):
            # print("fail5")
            retVal = False
        if not self.ZK.verify_proof_of_opening(com_ebis[0][0], proof6):
            # print("fail6")
            retVal = False
        return retVal

    def prove_ds(self, p_si, p_Ei, u, lagrange, p):
        r0 = [
            self.comm_scheme.cypari.Pol("0"),
            self.comm_scheme.cypari.Pol("0"),
            self.comm_scheme.cypari.Pol("0"),
        ]
        proof1 = self.ZK.proof_of_opening(p_si)
        proof2 = self.ZK.proof_of_opening(p_Ei)
        proof3_fac = self.comm_scheme.cypari(lagrange * u)
        proof3 = self.ZK.proof_of_sum(p_si, p_Ei, r0, proof3_fac, p, 1)
        return (proof1, proof2, proof3, proof3_fac)

    def verify_ds(
        self, proof1, proof2, proof3, proof3_fac, p, com_si, com_Ei, ds
    ):
        r0 = [
            self.comm_scheme.cypari.Pol("0"),
            self.comm_scheme.cypari.Pol("0"),
            self.comm_scheme.cypari.Pol("0"),
        ]
        com_ds = self.comm_scheme.commit(Commit(ds, r0))
        if not self.ZK.verify_proof_of_opening(com_si[0][0], proof1):
            return False
        if not self.ZK.verify_proof_of_opening(com_Ei[0][0], proof2):
            return False
        proof, *rest = proof3
        proof = tuple[ProofOfOpenLinear, ProofOfOpenLinear, ProofOfOpenLinear](
            ProofOfOpenLinear(c, g, proof=proof)
            for c, g, proof in [
                [com_si, proof3_fac, proof[0]],
                [com_Ei, p, proof[1]],
                [com_ds, 1, proof[2]],
            ]
        )
        if not self.ZK.verify_proof_of_sum(proof, *rest):
            return False
        return True
