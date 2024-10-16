
from enum import Enum

import sys

from Mode import Mode
from Error import Error

class Algorithm(Enum):
    XOR = 0
    AES = 1
    RSA = 2
    PGP_XOR = 3
    PGP_AES = 4

class ARGS(Enum):
    EXE = 0
    SYSTEM = 1
    MODE = 2

def strToBytes(hexStr: str) -> bytes:
    try:
        string = ''.join([hexStr[i:i + 2] for i in range(0, len(hexStr), 2)][::-1])
        bigEndian = bytes.fromhex(string)
    except ValueError:
        raise Error("The string is not in hexadecimal format")
    return bigEndian


def isPrime(number: int) -> bool:
    if number == 2 or number == 3: return True
    if number % 2 == 0 or number < 2: return False
    for i in range(3, int(number ** 0.5) + 1, 2):
        if number % i == 0:
            return False
    return True


class Parser:
    AlgorithmName = [
        "xor",
        "aes",
        "rsa",
        "pgp-xor",
        "pgp-aes"
    ]

    MODE = [
        "-c",
        "-d",
        "-g"
    ]

    args: list = []

    system: str = None

    mode: Mode = None

    pValue: int = None

    qValue: int = None

    message: str = None

    hasOption: bool = False

    key: str = None

    realkey: bytes = None

    """
    Convert a string to bytes
    The string must be in hexadecimal format if not an error is raised
    The string is in little-endian format, so I had to reverse all bytes to get the correct value
    """

    def parse(self) -> None:
        if not (4 <= len(self.args) <= 5):
            raise Error("Invalid number of arguments do \"./my_pgp -h\" for help")

        self.system : str = self.args[ARGS.SYSTEM.value]
        mode : str = self.args[ARGS.MODE.value]
        if self.system not in self.AlgorithmName:
            raise Error(f"Unknown algorithm: {self.system}")
        if mode not in self.MODE:
            raise Error(f"Unknown mode: {mode}")

        if mode == "-g":
            if self.system == self.AlgorithmName[Algorithm.RSA.value]:
                if len(self.args) != 5:
                    raise Error("RSA must be used with 2 prime numbers")
                try:
                    self.mode = Mode(mode)
                    tmpP: str = self.args[3]
                    tmpQ: str = self.args[4]
                    self.pValue = int(''.join([tmpP[i:i + 2] for i in range(0, len(tmpP), 2)][::-1]), 16)
                    self.qValue = int(''.join([tmpQ[i:i + 2] for i in range(0, len(tmpQ), 2)][::-1]), 16)
                except ValueError:
                    raise Error("RSA must be used with 2 prime numbers in hexadecimal format")
                if not isPrime(self.pValue) or not isPrime(self.qValue):
                    raise Error("The numbers must be prime")
                return
            else:
                raise Error("Only RSA can be used with -g mode, use -c or -d mode instead")
        self.mode = Mode(mode)
        keyIndex : int = ARGS.MODE.value + 1
        if len(self.args) == 5:
            self.hasOption = True
            if self.args[keyIndex] != "-b":
                raise Error('The flag has to be "-b"')
            keyIndex += 1
        self.key = self.args[keyIndex]
        if self.system == "aes" and len(self.key) != 32:
            raise Error("The key length must be 128 bits (32 characters) for AES")


    def getMessage(self) -> None:
        self.message = sys.stdin.read().strip()
        if not self.message:
            raise Error("The message is empty")
        if self.system == self.AlgorithmName[Algorithm.AES.value] and self.hasOption and len(self.key) == len(self.message):
            return
        if self.system == self.AlgorithmName[Algorithm.XOR.value] and self.hasOption and len(self.key) == len(self.message):
            return
        elif self.hasOption and len(self.key) != len(self.message) * 2:
            raise Error("The key length must be equal to the message length because the \"-b\" flag is used")

    def printArgs(self) -> None:
        print("System: " + self.system)
        print("Mode: " + self.args[ARGS.MODE.value])
        print("Message: " + self.message)
        print("Has option: " + str(self.hasOption))
        if self.hasOption:
            print("Key: " + self.key)

    def __init__(self, args: list) -> None:
        self.args = args
        try:
            self.parse()
            if self.mode != Mode.GENERATE:
                self.realKey = strToBytes(self.key)
                self.getMessage()
        except Error as e:
            print(e)
            exit(84)
