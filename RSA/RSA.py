
import math
import random

from Abstract.ACrypt import ACrypt


def mod_inverse(a: int, m: int) -> int:
    # Extended Euclidean Algorithm for modular inverse
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1


class Rsa(ACrypt):
    publicKey : str = None
    privateKey : str = None
    qValue : int = 0
    pValue : int = 0

    def __init__(self, key: bytes) -> None:
        super().__init__(key)

    def setGenValue(self, p : int, q : int) -> None:
        self.pValue = p
        self.qValue = q

    def generateKeys(self) -> None:
        n = self.pValue * self.qValue
        phi = (self.pValue - 1) * (self.qValue - 1)
        e = random.randint(2, phi - 1)
        while math.gcd(e, phi) != 1:
            e = random.randint(2, phi - 1)
        d = mod_inverse(e, phi)
        self.publicKey = f"{e}-{n}"
        self.privateKey = f"{d}-{n}"

    def getKeys(self) -> tuple:
        return self.publicKey, self.privateKey

    def getPublicKey(self) -> str:
        return self.publicKey

    def getPrivateKey(self) -> str:
        return self.privateKey

    def _encrypt(self, message: str) -> str:
        return "rsa e"

    def _decrypt(self, message: str) -> str:
        return "rsa d"

    def displayKeys(self) -> None:
        print(f"Public Key: {self.publicKey}")
        print(f"Private Key: {self.privateKey}")
