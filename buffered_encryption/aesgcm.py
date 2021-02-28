"""Encryption that uses AES in GCM mode"""

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
    signature : bytes
        Additional data used to verify the key later
    chunk_size : int
        How much data to encrypt per iteration

    Attributes
    ----------
    iv : bytes
        The 12-byte initialization vector for GCM. You will need this value for decryption.
    tag : bytes
        The tag to verfiy data integrity on decryption
    """

    def __init__(
        self,
        plaintext: io.BytesIO,
        key: bytes,
        signature: bytes,
        chunk_size: int = 64 * 1024,
    ):
        self.iv = os.urandom(12)
        self.file = plaintext
        self.chunk_size = chunk_size
        self.encryptor = Cipher(algorithms.AES(key), modes.GCM(self.iv)).encryptor()
        self.encryptor.authenticate_additional_data(signature)

    @property
    def tag(self):
        return self.encryptor.tag

    def __iter__(self):
        for chunk in iter_chunks(self.file, chunk_size=self.chunk_size):
            yield self.encryptor.update(chunk)

        yield self.encryptor.finalize()


class DecryptionIterator:
    """
    Decrypt a file iteratively

    Parameters
    ----------
    ciphertext : io.BytesIO
        The file buffer to decrypt
    key : bytes
        The secret key for AES decryption
    signature : bytes
        Additional data used to verify the key
    iv : bytes
        The initialization vector from the EncryptionIterator object
    tag : bytes
        The tag used for data integrity from the EncryptionIterator object
    chunk_size : int
        How much data to decrypt per iteration
    """

    def __init__(
        self,
        ciphertext: io.BytesIO,
        key: bytes,
        signature: bytes,
        iv: bytes,
        tag: bytes,
        chunk_size: int = 64 * 1024,
    ):
        self.iv = iv
        self.tag = tag
        self.file = ciphertext
        self.chunk_size = chunk_size
        self.decryptor = Cipher(
            algorithms.AES(key), modes.GCM(self.iv, self.tag)
        ).decryptor()
        self.decryptor.authenticate_additional_data(signature)

    def __iter__(self):
        for chunk in iter_chunks(self.file, chunk_size=self.chunk_size):
            yield self.decryptor.update(chunk)

        yield self.decryptor.finalize()
