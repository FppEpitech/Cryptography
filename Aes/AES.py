
from Abstract.ACrypt import ACrypt
from Aes.KeyExpansion import KeyExpension
from Aes.SBox import *

class Aes(ACrypt):
    def __init__(self, key: str) -> None:
        super().__init__(key)
        self.keyRound : KeyExpension = KeyExpension(key)


    def createBlocksEncrypt(self, message : bytes):
        blocks : list = []
        for i in range(0, len(message), 16):
            blocks.append(message[i:i+16])
        if len(blocks[-1]) % len(bytes.fromhex(self.key)) != 0:
            padding_length : int = len(bytes.fromhex(self.key)) - (len(blocks[-1])) % len(bytes.fromhex(self.key))
            blocks[-1] += b'\x00' * padding_length
        return blocks

    def createBlocksDecrypt(self, message : bytes):
        blocks : list = []
        for i in range(0, len(message), 16):
            blocks.append(message[i:i+16])
        return blocks

    def _encrypt(self, message: str) -> str:
        cypher : str = ""
        blocks : list = self.createBlocksEncrypt(message.encode(errors='ignore'))
        for block in blocks:
            aes : bytes = self.addRoundKey(block, bytes.fromhex(self.key))
            for i in range(9):
                aes = self.subBytes(aes)
                aes = self.shiftRows(aes)
                aes = self.mixColumns(aes, self.mixSingleColumn)
                aes = self.addRoundKey(aes, self.keyRound.getKeyRound(i+1))
            aes = self.subBytes(aes)
            aes = self.shiftRows(aes)
            aes = self.addRoundKey(aes, self.keyRound.getKeyRound(10))
            cypher += aes.hex()
        return cypher

    def _decrypt(self, message: str) -> str:
        decypher : str = ""
        blocks : list = self.createBlocksDecrypt(bytes.fromhex(message))
        for block in blocks:
            aes : bytes = self.addRoundKey(block, self.keyRound.getKeyRound(10))
            for i in range(9, 0, -1):
                aes = self.invShiftRows(aes)
                aes = self.invSubBytes(aes)
                aes = self.addRoundKey(aes, self.keyRound.getKeyRound(i))
                aes = self.mixColumns(aes, self.invMixSingleColumn)
            aes = self.invShiftRows(aes)
            aes = self.invSubBytes(aes)
            aes = self.addRoundKey(aes, self.keyRound.getKeyRound(0))
            decypher += aes.rstrip(b'\x00').decode(errors='ignore')
        return decypher

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

    def invSubBytes(self, block : bytes) -> bytes:
        newBlock : bytearray = bytearray()
        for i in range(len(block)):
            newBlock.append(sboxInv[block[i]])
        return newBlock

    def shiftRows(self, block: bytes) -> bytes:
        shift = list(block)
        shift[1], shift[5], shift[9], shift[13] = shift[5], shift[9], shift[13], shift[1]
        shift[2], shift[6], shift[10], shift[14] = shift[10], shift[14], shift[2], shift[6]
        shift[3], shift[7], shift[11], shift[15] = shift[15], shift[3], shift[7], shift[11]
        return bytes(shift)

    def invShiftRows(self, block: bytes) -> bytes:
        shift = list(block)
        shift[1], shift[5], shift[9], shift[13] = shift[13], shift[1], shift[5], shift[9]
        shift[2], shift[6], shift[10], shift[14] = shift[10], shift[14], shift[2], shift[6]
        shift[3], shift[7], shift[11], shift[15] = shift[7], shift[11], shift[15], shift[3]
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

    def invMixSingleColumn(self, column: list) -> list:
        matrix0, matrix1, matrix2, matrix3 = column
        newMatrix0 = self.galoisMult(matrix0, 14) ^ self.galoisMult(matrix1, 11) ^ self.galoisMult(matrix2, 13) ^ self.galoisMult(matrix3, 9)
        newMatrix1 = self.galoisMult(matrix0, 9) ^ self.galoisMult(matrix1, 14) ^ self.galoisMult(matrix2, 11) ^ self.galoisMult(matrix3, 13)
        newMatrix2 = self.galoisMult(matrix0, 13) ^ self.galoisMult(matrix1, 9) ^ self.galoisMult(matrix2, 14) ^ self.galoisMult(matrix3, 11)
        newMatrix3 = self.galoisMult(matrix0, 11) ^ self.galoisMult(matrix1, 13) ^ self.galoisMult(matrix2, 9) ^ self.galoisMult(matrix3, 14)
        return [newMatrix0, newMatrix1, newMatrix2, newMatrix3]

    def mixColumns(self, block: bytes, mix) -> bytes:
        Array = bytearray(16)
        for i in range(4):
            column = [block[i * 4], block[i * 4 + 1], block[i * 4 + 2], block[i * 4+ 3]]
            mixed_column = mix(column)
            Array[i * 4], Array[i * 4 + 1], Array[i * 4 + 2], Array[i * 4 + 3] = mixed_column
        return bytes(Array)
