
from Aes.SBox import sbox

rcon : bytearray= [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
]

class KeyExpension:

    def __init__(self, key : str) -> None:
        self.key : str = key
        self.roundKey : bytearray = self.keySchedule()


    def rotWord(self, columnBlock : bytes) -> bytes:
        shift : list = list(columnBlock)
        shift[0], shift[1], shift[2], shift[3] = shift[1], shift[2], shift[3], shift[0]
        return bytes(shift)

    def subWord(self, columnBlock : bytes) -> bytes:
        newColumnBlock : bytearray = bytearray()
        for i in range(len(columnBlock)):
            newColumnBlock.append(sbox[columnBlock[i]])
        return newColumnBlock

    def rCon(self, columnBlock : bytes, wi_4 : bytes, roundKeyIndex : int) -> bytes:
        newColumnBlock : bytearray = bytearray()
        for i in range(4):
            newColumnBlock.append(wi_4[i] ^ columnBlock[i] ^ rcon[i * 10 + roundKeyIndex])
        return newColumnBlock

    def xor(self, wi_1 : bytes, wi_4 : bytes) -> bytes:
        newColumnBlock : bytearray = bytearray()
        for i in range(4):
            newColumnBlock.append(wi_1[i] ^ wi_4[i])
        return newColumnBlock

    def keySchedule(self) -> bytearray:
        newRoundKey : bytearray = bytearray()
        newRoundKey += bytes.fromhex(self.key)
        for i in range(10):
            rot : bytearray = bytearray()
            rot += newRoundKey[i * 16 + 12:i * 16 + 16]
            columnBlock : bytes = self.rotWord(rot)
            columnBlock = self.subWord(columnBlock)
            columnBlock = self.rCon(columnBlock, newRoundKey[i * 16:i * 16 + 4], i)
            newRoundKey += columnBlock
            for j in range(3):
                columnBlock = self.xor(columnBlock, newRoundKey[i * 16 + (j + 1) *4 :i * 16 + (j + 1) * 4 + 4])
                newRoundKey += columnBlock
        return newRoundKey

    def getKeyRound(self, index : int) -> bytes:
        return self.roundKey[index * 16: index * 16 + 16]
