from BDLOPZK import BDLOPZK


class RelationProver:
    def __init__(self, ZK: BDLOPZK):
        self.ZK = ZK

    def prove_sk(self, b, bis, coms, come, comsis, comeis, s, ps, e, pe, sis, pis, eis, plineis):
        #proof1 = self.ZK.proof_of_sum(ps, pe, )¨
        #proof2 = self.ZK.proof_of_opening()