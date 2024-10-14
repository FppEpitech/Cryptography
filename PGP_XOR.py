
from Abstract.ACrypt import ACrypt

class PgpXor(ACrypt):
    def __init__(self, key: str) -> None:
        super().__init__(key)

    def _encrypt(self, message: str) -> str:
        return message

    def _decrypt(self, message: str) -> str:
        return message
