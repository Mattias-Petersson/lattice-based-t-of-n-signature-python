from BDLOPZK import BDLOPZK
from CommitmentScheme import CommitmentScheme
from type.classes import Commit


class RelationProver:
    def __init__(self, ZK: BDLOPZK, comm_scheme: CommitmentScheme):
        self.ZK = ZK
        self.comm_scheme = comm_scheme

    def prove_sk(
        self,
        b,
        bis,
        coms,
        come,
        comsis,
        comeis,
        s,
        ps,
        e,
        pe,
        sis,
        psis,
        eis,
        peis,
        a,
        p,
    ):
        r0 = [
            self.comm_scheme.cypari.Pol("0"),
            self.comm_scheme.cypari.Pol("0"),
            self.comm_scheme.cypari.Pol("0"),
        ]
        comb = self.comm_scheme.commit(Commit(b, r0))
        proof1 = self.ZK.proof_of_sum(ps, pe, r0, a, p, 1)
        proofs1 = []
        for i in range(len(bis)):
            proofs1.append(self.ZK.proof_of_sum(psis[i], peis[i], r0, a, p, 1))
        proof2 = (
            self.ZK.proof_of_specific_opening(ps),
            coms - self.comm_scheme.commit(Commit(s, r0)),
        )
        proof3 = (
            self.ZK.proof_of_specific_opening(pe),
            come - self.comm_scheme.commit(Commit(e, r0)),
        )

        return False
