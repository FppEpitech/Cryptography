class Xor:
    def __init__(self, message : str, key : str) -> None:
        self.message = message
        self.key = key

    def cypherMessage(self) -> str:
        return xor_encrypt(self.message[::-1], self.key)

    def decypherMessage(self) -> str:
        return xor_decrypt(self.message, self.key)[::-1]


def xor_encrypt(message : str, key : str) -> str:
    message_bytes : bytes = message.encode('utf-8')
    key_bytes : bytes = bytes.fromhex(key)

    block_size : int = len(key_bytes)

    if len(message_bytes) % block_size != 0:
        padding_length : int = block_size - (len(message_bytes) % block_size)
        message_bytes += b'\x00' * padding_length

    cipher_bytes : bytearray = bytearray()
    for i in range(len(message_bytes)):
        cipher_bytes.append(message_bytes[i] ^ key_bytes[i % block_size])

    return cipher_bytes.hex()

def xor_decrypt(cipher_hex : str, key : str) ->str:
    cipher_bytes : bytes = bytes.fromhex(cipher_hex)
    key_bytes : bytes = bytes.fromhex(key)

    block_size : int = len(key_bytes)

    decrypted_bytes : bytearray = bytearray()
    for i in range(len(cipher_bytes)):
        decrypted_bytes.append(cipher_bytes[i] ^ key_bytes[i % block_size])

    return decrypted_bytes.rstrip(b'\x00').decode('utf-8')
