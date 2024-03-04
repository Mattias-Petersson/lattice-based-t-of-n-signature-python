from BDLOPZK import BDLOPZK
from CommitmentScheme import CommitmentScheme
from type.classes import Commit, ProofOfOpenLinear
import SecretShare


class RelationProver:
    def __init__(self, ZK: BDLOPZK, comm_scheme: CommitmentScheme):
        self.ZK = ZK
        self.comm_scheme = comm_scheme

    def prove_sk(
        self,
        bis,
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
        for i in range(len(bis)):
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
        if not self.ZK.verify_proof_of_opening(coms, *proof2):
            print("False2")
            return False
        if not self.ZK.verify_proof_of_opening(come, *proof3):
            print("False3")
            return False
        for i in range(len(proofs1)):
            combi = self.comm_scheme.commit(Commit(bis[i], r0))
            proof, *rest = proofs1[i]
            proof = tuple[ProofOfOpenLinear, ProofOfOpenLinear, ProofOfOpenLinear](
                ProofOfOpenLinear(c, g, proof=proof)
                for c, g, proof in [
                    [comsis[i], a, proof[0]],
                    [come[i], p, proof[1]],
                    [combi, 1, proof[2]],
                ]
            )
            if not self.ZK.verify_proof_of_sum(proof, *rest):
                print("False4")
                return False
        for i in range(len(proofs2)):
            if not self.ZK.verify_proof_of_opening(comsis[i], *proofs2[i]):
                print("False5")
                return False
        for i in range(len(proofs3)):
            if not self.ZK.verify_proof_of_opening(comeis[i], *proofs3[i]):
                print("False6")
                return False
        if b != SecretShare.reconstruct(bis, range(1, len(bis) + 1)):
            print("False7")
            return False
        return True
