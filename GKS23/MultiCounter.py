class MultiCounter:
    def __init__(self):
        self.mult = 0
        self.mod = 0

    def inc_mult(self, val=1):
        self.mult += val

    def inc_mod(self, val=1):
        self.mod += val
