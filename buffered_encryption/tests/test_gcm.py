import os
import io
from buffered_encryption.aesgcm import EncryptionIterator, DecryptionIterator
import unittest


class TestSymmetry(unittest.TestCase):
    def setUp(self):
        # Prime number of random bytes greater than the chunk size
        self.plaintext = os.urandom(130399)
        self.key = os.urandom(32)
        self.ad = os.urandom(16)

    def test_buffer(self):
        """Encrypt to a buffer"""
        enc = EncryptionIterator(io.BytesIO(self.plaintext), self.key, self.ad)

        ciphertext = io.BytesIO()
        decrypted = io.BytesIO()

        for chunk in enc:
            ciphertext.write(chunk)
        ciphertext.seek(0)

        dec = DecryptionIterator(ciphertext, self.key, self.ad, enc.iv, enc.tag)
        for chunk in dec:
            decrypted.write(chunk)

        ciphertext.close()

        decrypted.seek(0)
        self.assertEqual(decrypted.read(),self.plaintext)