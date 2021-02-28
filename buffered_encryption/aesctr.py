"""Encryption that uses AES in CTR mode"""

import os
import io
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from .utils import iter_chunks


class EncryptionIterator:
    """
    Encrypt a file iteratively

    Parameters
    ----------
    plaintext : io.BytesIO
        The file buffer to encrypt
    key : bytes
        The secret key for AES encryption
    nonce : bytes
        16-byte long nonce, okay to store alongside file. Do not re-use for other files!
        This should be generated with os.urandom(16) when you encrypt the original data
    chunk_size : int
        How much data to encrypt per iteration. Default is 64 KiB
    """

    def __init__(
        self,
        plaintext: io.BytesIO,
        key: bytes,
        nonce: bytes,
        chunk_size: int = 64 * 1024,
    ):
        self.file = plaintext
        self.chunk_size = chunk_size
        self.encryptor = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()

    def __iter__(self):
        for chunk in iter_chunks(self.file, chunk_size=self.chunk_size):
            yield self.encryptor.update(chunk)

        yield self.encryptor.finalize()


class ReadOnlyEncryptedFile:
    """
    Read an encrypted file as if it were plain text.
    
    Parameters
    ----------
    encrypted_buffer : io.BytesIO
        The encrypted file handle or buffer to read from
    key : bytes
        32-byte long secret key. Do not share!
    nonce : bytes
        16-byte long nonce, okay to store alongside file. Do not re-use for other files!
        This should be generated with os.urandom(16) when you encrypt the original data
    """

    BLOCK_SIZE = 16

    def __init__(
        self, encrypted_buffer: io.BytesIO, key: bytes, nonce: bytes
    ):
        self.buffer = encrypted_buffer
        self.key = key
        self.nonce = nonce
        self.counter = 0
        self.offset = 0
    
    def __iter__(self):
        while True:
            bts = self.read(16)
            if not bts:
                break
            for byte in bts:
                yield byte

    @classmethod
    def add_int_to_bytes(cls, b, i):
        """Add an integer to a byte string"""
        # OpenSSL uses big-endian for CTR
        MAX = int.from_bytes(b"\xff"*cls.BLOCK_SIZE,byteorder="big") + 1
        # If the counter overflows, it wraps back to zero
        i = (int.from_bytes(b, byteorder="big") + i) % MAX
        return i.to_bytes(cls.BLOCK_SIZE, "big")

    @property
    def cipher(self):
        """We can use this to encrypt/decrypt multiple blocks efficiently."""
        return Cipher(
            algorithms.AES(self.key),
            modes.CTR(self.add_int_to_bytes(self.nonce, self.counter)),
        )

    @property
    def decryptor(self):
        return self.cipher.decryptor()

    def read(self, size: int = -1) -> bytes:
        """Read and decrypt bytes from the buffer"""
        # Ensure we are requesting multiples of 16 bytes, unless we are at the end of the stream
        if size == 0:
            return b""
        elif (size > 0) and (size % self.BLOCK_SIZE != 0):
            full_size = size - (size % self.BLOCK_SIZE) + self.BLOCK_SIZE
        else:
            # Whole file is requested, or multiple of 16
            full_size = size

        encrypted_data = self.buffer.read(full_size)
        decrypted_data = self.decryptor.update(encrypted_data)
        self.counter += len(encrypted_data) // self.BLOCK_SIZE
        if size < 0:
            return decrypted_data[self.offset :]
        else:
            return decrypted_data[self.offset : self.offset + size]

    def seek(self, offset: int, whence: int = 0) -> int:
        """Seek to a position in the decrypted buffer"""
        pos = offset + whence
        # Move the cursor to the start of the block
        # Keep track of how far into the current block we are
        self.offset = pos % self.BLOCK_SIZE
        real_pos = pos - (self.offset)
        self.buffer.seek(real_pos)
        self.counter = real_pos // self.BLOCK_SIZE
        return pos
    
    def write(self, b:bytes):
        raise io.UnsupportedOperation("Encrypted buffer is read-only")
