
from Abstract.ACrypt import ACrypt

class Aes(ACrypt):
    def __init__(self, key: bytes) -> None:
        super().__init__(key)

    def _encrypt(self, message: str) -> str:
        return message

    def _decrypt(self, message: str) -> str:
        return message
