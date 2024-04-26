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
        psis,
        peis,
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
        proofs1 = []
        proofs2 = []
        proofs3 = []
        for i in range(len(psis)):
            proofs1.append(self.ZK.proof_of_opening(psis[i]))
            proofs2.append(self.ZK.proof_of_opening(peis[i]))
            proofs3.append(self.ZK.proof_of_sum(psis[i], peis[i], r0, a, p, 1))
        return (proof1, proof2, proof3, proofs1, proofs2, proofs3)

    def verify_sk(
        self,
        proof1,
        proof2,
        proof3,
        proofs1,
        proofs2,
        proofs3,
        b,
        bis,
        a,
        p,
        coms,
        come,
        comsis,
        comeis,
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
        for i in range(len(bis)):
            combi = self.comm_scheme.commit(Commit(bis[i][1], r0))
            proof, *rest = proofs3[i]
            proof = tuple[
                ProofOfOpenLinear, ProofOfOpenLinear, ProofOfOpenLinear
            ](
                ProofOfOpenLinear(c, g, proof=proof)
                for c, g, proof in [
                    [comsis[i], a, proof[0]],
                    [comeis[i], p, proof[1]],
                    [combi, 1, proof[2]],
                ]
            )
            if not self.ZK.verify_proof_of_sum(proof, *rest):
                print("False4")
                return False
            if not self.ZK.verify_proof_of_opening(comsis[i][0][0], proofs1[i]):
                print("False5")
                return False
            if not self.ZK.verify_proof_of_opening(comeis[i][0][0], proofs2[i]):
                print("False6")
                return False
        return True

    def prove_enc(self, r, m, eprime, ebis, a, b, p):
        r0 = [
            self.comm_scheme.cypari.Pol("0"),
            self.comm_scheme.cypari.Pol("0"),
            self.comm_scheme.cypari.Pol("0"),
        ]
        com_r = Commit(r, self.comm_scheme.r_commit())
        com_m = Commit(m, self.comm_scheme.r_commit())
        com_eprime = Commit(eprime, self.comm_scheme.r_commit())
        com_ebis = Commit(ebis, self.comm_scheme.r_commit())
        proof1 = self.ZK.proof_of_sum(com_r.r, com_eprime.r, r0, a, p, 1)
        proof2 = self.ZK.proof_of_triple_sum(
            com_r.r, com_ebis.r, com_m.r, r0, b, p, 1, 1
        )
        proof3 = self.ZK.proof_of_opening(com_r.r)
        proof4 = self.ZK.proof_of_opening(com_m.r)
        proof5 = self.ZK.proof_of_opening(com_eprime.r)
        proof6 = self.ZK.proof_of_opening(com_ebis.r)
        return (
            proof1,
            proof2,
            proof3,
            proof4,
            proof5,
            proof6,
            self.comm_scheme.commit(com_r),
            self.comm_scheme.commit(com_m),
            self.comm_scheme.commit(com_eprime),
            self.comm_scheme.commit(com_ebis),
        )

    def verify_enc(
        self,
        proof1,
        proof2,
        proof3,
        proof4,
        proof5,
        proof6,
        com_r,
        com_m,
        com_eprime,
        com_ebis,
        a,
        b,
        p,
        u,
        v,
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
            print("fail1")
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
            print("fail2")
            retVal = False
        if not self.ZK.verify_proof_of_opening(com_r[0][0], proof3):
            print("fail3")
            retVal = False
        if not self.ZK.verify_proof_of_opening(com_m[0][0], proof4):
            print("fail4")
            retVal = False
        if not self.ZK.verify_proof_of_opening(com_eprime[0][0], proof5):
            print("fail5")
            retVal = False
        if not self.ZK.verify_proof_of_opening(com_ebis[0][0], proof6):
            print("fail6")
            retVal = False
        return retVal

    def prove_s(self, a_vec, random_vec):
        sum_random = [
            self.comm_scheme.cypari.Pol("0"),
            self.comm_scheme.cypari.Pol("0"),
            self.comm_scheme.cypari.Pol("0"),
        ]
        r0 = Commit(random_vec[0], self.comm_scheme.r_commit())
        r1 = Commit(random_vec[1], self.comm_scheme.r_commit())
        proof = self.ZK.proof_of_sum(
            r0.r, r1.r, sum_random, a_vec[0], a_vec[1], 1
        )
        return proof, self.comm_scheme.commit(r0), self.comm_scheme.commit(r1)

    def verify_s(self, proof, rc0, rc1, a_vec, sum):
        r0 = [
            self.comm_scheme.cypari.Pol("0"),
            self.comm_scheme.cypari.Pol("0"),
            self.comm_scheme.cypari.Pol("0"),
        ]
        com_sum = self.comm_scheme.commit(Commit(sum, r0))
        proof, *rest = proof
        proof = tuple[ProofOfOpenLinear, ProofOfOpenLinear, ProofOfOpenLinear](
            ProofOfOpenLinear(c, g, proof=proof)
            for c, g, proof in [
                [rc0, a_vec[0], proof[0]],
                [rc1, a_vec[1], proof[1]],
                [com_sum, 1, proof[2]],
            ]
        )
        return self.ZK.verify_proof_of_sum(proof, *rest)

    def prove_r(self, a_vec, random_vec, sum_random):
        r0 = Commit(random_vec[0], self.comm_scheme.r_commit())
        r1 = Commit(random_vec[1], self.comm_scheme.r_commit())

        proof1 = self.ZK.proof_of_sum(
            r0.r, r1.r, sum_random, a_vec[0], a_vec[1], 1
        )
        proof2 = self.ZK.proof_of_opening(
            sum_random
        )  # This should be a proof of trapdoor opening
        return (
            proof1,
            proof2,
            self.comm_scheme.commit(r0),
            self.comm_scheme.commit(r1),
        )

    def verify_r(self, proof1, proof2, rc0, rc1, a_vec, c_sum):
        proof, *rest = proof1
        proof = tuple[ProofOfOpenLinear, ProofOfOpenLinear, ProofOfOpenLinear](
            ProofOfOpenLinear(c, g, proof=proof)
            for c, g, proof in [
                [rc0, a_vec[0], proof[0]],
                [rc1, a_vec[1], proof[1]],
                [c_sum, 1, proof[2]],
            ]
        )
        return self.ZK.verify_proof_of_sum(
            proof, *rest
        ) and self.ZK.verify_proof_of_opening(c_sum[0][0], proof2)

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
            print("False1")
            return False
        if not self.ZK.verify_proof_of_opening(com_Ei[0][0], proof2):
            print("False2")
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
            print("False3")
            return False
        return True
