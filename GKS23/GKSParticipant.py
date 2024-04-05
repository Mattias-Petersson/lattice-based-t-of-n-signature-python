from BDLOP16.CommitmentScheme import CommitmentScheme
from BGV122.BGV import BGV
from BGV122.BGVParticipant import BGVParticipant
from SecretSharing.SecretShare2 import SecretShare


class GKSParticipant(BGVParticipant):
    def __init__(
        self, comm_scheme: CommitmentScheme, secret_share: SecretShare, p: int
    ):
        super().__init__(comm_scheme, secret_share, p)
