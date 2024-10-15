
import math
import random

from Abstract.ACrypt import ACrypt

class Rsa(ACrypt):

    def __init__(self, key: bytes) -> None:
        super().__init__(key)
        self.publicKey = None
        self.privateKey = None
        self.qValue = 0
        self.pValue = 0

    def setGenValue(self, p : bytes, q : bytes) -> None:
        self.pValue = int.from_bytes(p, byteorder='big')
        self.qValue = int.from_bytes(q, byteorder='big')

    def generateKeys(self) -> None:
        n = self.pValue * self.qValue
        phi = (self.pValue - 1) * (self.qValue - 1)
        e = random.randint(2, phi - 1)
        while math.gcd(e, phi) != 1:
            e = random.randint(2, phi - 1)
        d = pow(e, -1, phi)
        self.publicKey = (e, n)
        self.privateKey = (d, n)

    def getKeys(self) -> tuple:
        return self.publicKey, self.privateKey

    def getPublicKey(self) -> tuple:
        return self.publicKey

    def getPrivateKey(self) -> tuple:
        return self.privateKey
