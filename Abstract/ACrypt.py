
from Mode import Mode
from abc import ABC

from typing import Dict, Callable

class ACrypt(ABC):
    """
    Abstract Cryptographic class.
    """
    def __init__(self, key : bytes) -> None:
        """
        Initialize the cryptographic object with a key.
        """
        self.key = key
        self.modeArray = {
            Mode.DECRYPT: self._decrypt,
            Mode.ENCRYPT: self._encrypt
        }

    def _encrypt(self, data : str) -> str:
        """
        Encrypt data using key.
        """

    def _decrypt(self, data : str) -> str:
        """
        Decrypt data using key.
        """

    def getModeArray(self) -> Dict[Mode, Callable[[str], str]]:
        """
        Get the array of modes and their functions.
        """
        return self.modeArray

    def getMode(self, mode : Mode) -> Callable[[str], str]:
        """
        Get the function for the mode.
        """
        return self.modeArray[mode]