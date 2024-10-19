
from Abstract.ACrypt import ACrypt

from Aes.AES import Aes
from RSA.RSA import Rsa

class PgpAes(ACrypt):
    def __init__(self, key: bytes) -> None:
        super().__init__(key)

    def _encrypt(self, message: str) -> str:
        rsa = Rsa("")
        rsa.setLeftRightValue("010001", "c9f91a9ff3bd6d84005b9cc8448296330bd23480f8cf8b36fd4edd0a8cd925de139a0076b962f4d57f50d6f9e64e7c41587784488f923dd60136c763fd602fb3")
        print(rsa._encrypt(bytes.fromhex("57696e74657220697320636f6d696e67").decode()))
        aes : Aes = Aes("57696e74657220697320636f6d696e67")
        return aes._encrypt(message)

    def _decrypt(self, message: str) -> str:
        rsa = Rsa("")
        rsa.setLeftRightValue("81b08f4eb6dd8a4dd21728e5194dfc4e349829c9991c8b5e44b31e6ceee1e56a11d66ef23389be92ef7a4178470693f509c90b86d4a1e1831056ca0757f3e209", "c9f91a9ff3bd6d84005b9cc8448296330bd23480f8cf8b36fd4edd0a8cd925de139a0076b962f4d57f50d6f9e64e7c41587784488f923dd60136c763fd602fb3")
        aes : Aes = Aes(rsa._decrypt("97f2af4c1b712008c1e46935f446756443a8a700f20581d138e4e6916afe5c5f9b9d6eaa0a870374b686f1a024f9bbb88c23c766654579339caf55afd149d41d").encode().hex())
        return aes._decrypt("744ce22c385958348f0df26eceb62eef")
