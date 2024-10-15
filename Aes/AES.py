
from Abstract.ACrypt import ACrypt
from Aes.KeyExpansion import KeyExpension
from Aes.SBox import sbox

class Aes(ACrypt):
    def __init__(self, key: str) -> None:
        super().__init__("".join(reversed([key[i:i+2] for i in range(0, len(key), 2)])))
        self.keyRound : KeyExpension = KeyExpension("".join(reversed([key[i:i+2] for i in range(0, len(key), 2)])))

    def _encrypt(self, message: str) -> str:
        aes : bytes = self.firstRound(message)
        aes = self.loopRounds(aes)
        aes = self.lastRound(aes)
        return "".join(reversed([aes.hex()[i:i+2] for i in range(0, len(aes.hex()), 2)]))

    def _decrypt(self, message: str) -> str:
        return message

    def firstRound(self, message : str) -> bytes:
        block : bytes = message.encode('utf-8')
        aes : bytes = self.addRoundKey(block, bytes.fromhex(self.key))
        return aes

    def loopRounds(self, block : bytes) -> bytes:
        for i in range(9):
            block = self.subBytes(block)
            block = self.shiftRows(block)
            block = self.mixColumns(block)
            block = self.addRoundKey(block, self.keyRound.getKeyRound(i+1))
        return block

    def lastRound(self, block : bytes) -> bytes:
        block = self.subBytes(block)
        block = self.shiftRows(block)
        block = self.addRoundKey(block, self.keyRound.getKeyRound(10))
        return block

    def addRoundKey(self, block1 : bytes, block2 : bytes) -> bytes:
        newBlock : bytearray = bytearray()
        for i in range(len(block1)):
            newBlock.append(block1[i] ^ block2[i])
        return bytes.fromhex(newBlock.hex())

    def subBytes(self, block : bytes) -> bytes:
        newBlock : bytearray = bytearray()
        for i in range(len(block)):
            newBlock.append(sbox[block[i]])
        return newBlock

    def shiftRows(self, block: bytes) -> bytes:
        shift = list(block)
        shift[1], shift[5], shift[9], shift[13] = shift[5], shift[9], shift[13], shift[1]
        shift[2], shift[6], shift[10], shift[14] = shift[10], shift[14], shift[2], shift[6]
        shift[3], shift[7], shift[11], shift[15] = shift[15], shift[3], shift[7], shift[11]
        return bytes(shift)

    def galoisMult(self, byte: int, power: int) -> int:
        galois : int = 0
        for i in range(8):
            if power & 1:
                galois = galois ^ byte
            shift : int = byte & 0x80
            byte <<= 1
            if shift:
                byte = byte ^ 0x1b
            power >>= 1
        return galois % 256

    def mixSingleColumn(self, column: list) -> list:
        matrix0, matrix1, matrix2, matrix3 = column
        newMatrix0 = self.galoisMult(matrix0, 2) ^ self.galoisMult(matrix1, 3) ^ matrix2 ^ matrix3
        newMatrix1 = matrix0 ^ self.galoisMult(matrix1, 2) ^ self.galoisMult(matrix2, 3) ^ matrix3
        newMatrix2 = matrix0 ^ matrix1 ^ self.galoisMult(matrix2, 2) ^ self.galoisMult(matrix3, 3)
        newMatrix3 = self.galoisMult(matrix0, 3) ^ matrix1 ^ matrix2 ^ self.galoisMult(matrix3, 2)
        return [newMatrix0, newMatrix1, newMatrix2, newMatrix3]

    def mixColumns(self, block: bytes) -> bytes:
        Array = bytearray(16)
        for i in range(4):
            column = [block[i * 4], block[i * 4 + 1], block[i * 4 + 2], block[i * 4+ 3]]
            mixed_column = self.mixSingleColumn(column)
            Array[i * 4], Array[i * 4 + 1], Array[i * 4 + 2], Array[i * 4 + 3] = mixed_column
        return bytes(Array)
