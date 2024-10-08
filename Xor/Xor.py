class Xor:
    def __init__(self, message : str, key : str) -> None:
        self.message = message
        self.key = key

    def cypherMessage(self):
        cypher=""
        hexaXor=""
        for i in range (0, len(self.message)):
            hexaKey = hex(int(self.key[i*2] + self.key[i*2+1], 16))
            hexaLetter = hex(int(self.message[i].encode("utf-8").hex(), 16))
            xor = int(hexaLetter, 16) ^ int(hexaKey, 16)
            if xor == 0:
                hexaXor = "00"
            else:
                hexaXor = hex(xor).removeprefix("0x")
            if (len(hexaXor) == 1):
                hexaXor = "0" + hexaXor
            cypher+=hexaXor
        cypher = "".join(map(str.__add__, cypher[-2::-2] ,cypher[-1::-2]))
        return cypher


    def decypherMessage(self):
        decypher=""
        self.message = "".join(map(str.__add__, self.message[-2::-2] ,self.message[-1::-2]))
        for i in range (0, len(self.message), 2):
            hexaLetter = hex(int(self.message[i] + self.message[i+1], 16))
            hexaKey = hex(int(self.key[i] + self.key[i+1], 16))
            xor = int(hexaLetter, 16) ^ int(hexaKey, 16)
            decypher +=chr(xor)
        return decypher
