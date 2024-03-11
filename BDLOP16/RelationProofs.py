from BDLOP16.BDLOP import BDLOP
from BDLOP16.CommitmentScheme import CommitmentScheme
from type.classes import Commit, ProofOfOpenLinear
from SecretSharing.SecretShare import SecretShare


class RelationProver:
    def __init__(self, ZK: BDLOP, comm_scheme: CommitmentScheme, SSS: SecretShare):
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
        proofs1 = []
        for i in range(len(psis)):
            proofs1.append(self.ZK.proof_of_sum(psis[i], peis[i], r0, a, p, 1))
        proof2 = self.ZK.proof_of_opening(ps)
        proof3 = self.ZK.proof_of_opening(pe)
        proofs2 = []
        for i in psis:
            proofs2.append(self.ZK.proof_of_opening(i))
        proofs3 = []
        for i in peis:
            proofs3.append(self.ZK.proof_of_opening(i))

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
        for i in range(len(proofs1)):
            combi = self.comm_scheme.commit(Commit(bis[i], r0))
            proof, *rest = proofs1[i]
            proof = tuple[ProofOfOpenLinear, ProofOfOpenLinear, ProofOfOpenLinear](
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
        for i in range(len(proofs2)):
            if not self.ZK.verify_proof_of_opening(comsis[i][0][0], proofs2[i]):
                print("False5")
                return False
        for i in range(len(proofs3)):
            if not self.ZK.verify_proof_of_opening(comeis[i][0][0], proofs3[i]):
                print("False6")
                return False
        if b != self.SSS.reconstruct_poly(bis[:2], range(1, 3)):
            print("False7")
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
        proof4 = self.ZK.proof_of_opening(p_eprime)
        proof5 = self.ZK.proof_of_opening(p_ebis)
        proof6 = self.ZK.proof_of_opening(p_m)
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
        proof = tuple[ProofOfOpenLinear, ProofOfOpenLinear, ProofOfOpenLinear](
            ProofOfOpenLinear(c, g, proof=proof)
            for c, g, proof in [
                [com_r, a, proof[0]],
                [com_eprime, p, proof[1]],
                [com_u, 1, proof[2]],
            ]
        )
        if not self.ZK.verify_proof_of_sum(proof, *rest):
            return False
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
            return False
        if not self.ZK.verify_proof_of_opening(com_r, proof3):
            return False
        if not self.ZK.verify_proof_of_opening(com_m, proof4):
            return False
        if not self.ZK.verify_proof_of_opening(com_eprime, proof5):
            return False
        if not self.ZK.verify_proof_of_opening(com_ebis, proof6):
            return False
        return True

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

    def verify_ds(self, proof1, proof2, proof3, proof3_fac, p, com_si, com_Ei, ds):
        r0 = [
            self.comm_scheme.cypari.Pol("0"),
            self.comm_scheme.cypari.Pol("0"),
            self.comm_scheme.cypari.Pol("0"),
        ]
        com_ds = self.comm_scheme.commit(Commit(ds, r0))
        if not self.ZK.verify_proof_of_opening(com_si, proof1):
            return False
        if not self.ZK.verify_proof_of_opening(com_Ei, proof2):
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
