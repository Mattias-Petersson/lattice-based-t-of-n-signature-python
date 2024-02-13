
# Temporary types to ensure that typing works (3.12).
type CommitmentKey = int 
type Com = int
type Tck = int
type Td = int

class CommitmentScheme:
    #q for the ring modulus, N for the degree of the irreducible polynomial. 
    def __init__(self, q, N):
        print(q, N)

    def c_gen(self) -> CommitmentKey:
        return 0
    
    def com(self, m, msg) -> Com:
        return 0
    
    def open(self, com, r, msg) -> bool:
        #return 1 if com, r, msg is valid, 0 otherwise
        return 0
    
    def tc_gen(self) -> (Tck, Td):
        return (0, 0)
    
    def t_com(self, td) -> Com:
        # same type of com? Look into. 
        return 0
    
    def eqv(self, td, com, m):
        return 0
