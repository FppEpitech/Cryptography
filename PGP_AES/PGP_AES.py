
from Abstract.ACrypt import ACrypt

from Aes.AES import Aes
from RSA.RSA import Rsa

class PgpAes(ACrypt):
    left = ""
    right = ""
    isBlockMode = False

    def __init__(self, key: bytes) -> None:
        super().__init__(key)

    def _encrypt(self, message: str) -> str:
        rsa = Rsa("")
        rsa.setLeftRightValue(self.left, self.right)
        print(rsa._encrypt(bytes.fromhex(self.key).decode()))
        aes : Aes = Aes(self.key)
        return aes._encrypt(message)

    def _decrypt(self, message: str) -> str:
        rsa = Rsa("")
        rsa.setLeftRightValue(self.left, self.right)
        key : str = rsa._decrypt(self.key).encode().hex()
        if (len(key) != 32):
            print("The key length must be 128 bits (32 characters) for AES")
            exit(84)
        if self.isBlockMode and len(key) != len(message):
            print("The key length must be equal to the message length because the \"-b\" flag is used")
            exit(84)
        aes : Aes = Aes(key)
        return aes._decrypt(message)

    def setLeftRightValue(self, left : str, right : str) -> None:
        self.left = left
        self.right = right

    def setIsBlockMode(self, isBlockMode : bool) -> None:
        self.isBlockMode = isBlockMode
