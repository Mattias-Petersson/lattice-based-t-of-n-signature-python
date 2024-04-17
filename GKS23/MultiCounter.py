class MultiCounter:
    def __init__(self):
        self.q_mult = 0
        self.p_mult = 0

    def inc_q(self, val=1):
        self.q_mult += val

    def inc_p(self, val=1):
        self.p_mult += val
