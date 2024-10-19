
import math
import random

from Abstract.ACrypt import ACrypt

FERMAT_NUMBERS = [65537, 257, 17, 5, 3]

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
    left = ""
    right = ""

    def __init__(self, key: bytes) -> None:
        super().__init__(key)

    def setGenValue(self, p : int, q : int) -> None:
        self.pValue = p
        self.qValue = q

    def setLeftRightValue(self, left : str, right : str) -> None:
        self.left = left
        self.right = right

    def little_endian(self, n : str) -> str:
        if (len(n) % 2 != 0):
            n = "0" + n
        return "".join([n[i:i+2] for i in range(0, len(n), 2)][::-1])

    def generateKeys(self) -> None:
        n = self.pValue * self.qValue
        phi = (self.pValue - 1) * (self.qValue - 1)
        idx = 0
        e = FERMAT_NUMBERS[idx]
        while e > phi:
            idx += 1
            e = FERMAT_NUMBERS[idx]
        d = mod_inverse(e, phi)

        self.publicKey = f"{self.little_endian(format(e, '0x'))}-{self.little_endian(format(n, '0x'))}"
        self.privateKey = f"{self.little_endian(format(d, '0x'))}-{self.little_endian(format(n, '0x'))}"

    def getKeys(self) -> tuple:
        return self.publicKey, self.privateKey

    def getPublicKey(self) -> str:
        return self.publicKey

    def getPrivateKey(self) -> str:
        return self.privateKey

    def _encrypt(self, message: str) -> str:
        message_bytes: bytes = bytes.fromhex(message.encode().hex())[::-1]
        n : int = int(self.little_endian(self.right).encode(), 16)
        e : int = int(self.little_endian(self.left).encode(), 16)
        compute = pow(int.from_bytes(message_bytes, 'big'), e, n)
        return self.little_endian(format(compute, '0x'))

    def _decrypt(self, message: str) -> str:
        message_bytes: bytes = bytes.fromhex(message)
        n : int = int(self.little_endian(self.right).encode(), 16)
        d : int = int(self.little_endian(self.left).encode(), 16)
        compute = pow(int.from_bytes(message_bytes, 'little'), d, n)
        return bytes.fromhex(format(compute, '0x')).decode()[::-1]

    def displayKeys(self) -> None:
        print(f"public key: {self.publicKey}")
        print(f"private key: {self.privateKey}")
