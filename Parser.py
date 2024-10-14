
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

    def parse(self):
        if not (4 <= len(self.args) <= 5):
            raise Error("Invalid number of arguments do \"./my_pgp -h\" for help")

        self.system : str = self.args[ARGS.SYSTEM.value]
        mode : str = self.args[ARGS.MODE.value]
        if self.system not in self.AlgorithmName:
            raise Error(f"Unknown algorithm: {self.system}")
        if mode not in self.MODE:
            raise Error(f"Unknown mode: {mode}")

        if self.system == self.AlgorithmName[Algorithm.RSA.value]:
            if mode != "-g":
                raise Error("RSA must be used with -g mode")
            if len(self.args) != 5:
                raise Error("RSA must be used with 2 prime numbers")
            try:
                self.mode = Mode(mode)
                self.pValue = int(self.args[3])
                self.qValue = int(self.args[4])
            except ValueError:
                raise Error("RSA must be used with 2 prime numbers")
        else:
            if mode == "-g":
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


    def getMessage(self):
        self.message = sys.stdin.read().strip()
        if not self.message:
            raise Error("The message is empty")
        if self.hasOption and len(self.key) != len(self.message) * 2:
            raise Error("The key length must be equal to the message length because the \"-b\" flag is used")

    def printArgs(self):
        print("System: " + self.system)
        print("Mode: " + self.args[ARGS.MODE.value])
        print("Message: " + self.message)
        print("Has option: " + str(self.hasOption))
        if self.hasOption:
            print("Key: " + self.key)

    def isHex(self, string: str) -> bool:
        try:
            int(string, 16)
            return True
        except ValueError:
            raise Error("The key must be in hexadecimal format")

    def __init__(self, args: list):
        self.args = args
        try:
            self.parse()
            self.getMessage()
            self.isHex(self.key)
        except Error as e:
            print(e)
            return(84)
