
from Abstract.ACrypt import ACrypt

from RSA.RSA import Rsa
from Xor.Xor import Xor

class PgpXor(ACrypt):
    left = ""
    right = ""
    isBlockMode = False

    def __init__(self, key: bytes) -> None:
        super().__init__(key)

    def _encrypt(self, message: str) -> str:
        rsa = Rsa("")
        rsa.setLeftRightValue(self.left, self.right)
        print(rsa._encrypt(bytes.fromhex(self.key).decode()))
        xor : Xor = Xor(self.key)
        return xor._encrypt(message)

    def _decrypt(self, message: str) -> str:
        rsa = Rsa("")
        rsa.setLeftRightValue(self.left, self.right)
        xor : Xor = Xor(rsa._decrypt(self.key).encode().hex())
        return xor._decrypt(message)

    def setLeftRightValue(self, left : str, right : str) -> None:
        self.left = left
        self.right = right

    def setIsBlockMode(self, isBlockMode : bool) -> None:
        self.isBlockMode = isBlockMode
