import os
import io
from buffered_encryption.aesctr import EncryptionIterator, ReadOnlyEncryptedFile
import unittest


class TestSymmetry(unittest.TestCase):
    def setUp(self):
        self.plaintext = os.urandom(130399)
        self.key = os.urandom(32)
        self.nonce = os.urandom(16)
        self.ciphertext = io.BytesIO()
        enc = EncryptionIterator(io.BytesIO(self.plaintext), self.key, self.nonce)
        for chunk in enc:
            self.ciphertext.write(chunk)
        self.ciphertext.seek(0)
        self.decrypted_file = ReadOnlyEncryptedFile(self.ciphertext,self.key,self.nonce)
    
    def test_full_read(self):
        self.assertEqual(self.decrypted_file.read(),self.plaintext)
    
    def test_seek_block_start(self):
        """Seek to the start of a block"""
        self.decrypted_file.seek(32)
        self.assertEqual(self.decrypted_file.read(),self.plaintext[32:])
    
    def test_seek_block_middle(self):
        """Seek to the middle of a block"""
        self.decrypted_file.seek(57)
        self.assertEqual(self.decrypted_file.read(),self.plaintext[57:])
    
    def test_double_seek(self):
        """Seek, then read, then seek, and read again"""
        self.decrypted_file.seek(12)
        first = self.decrypted_file.read()
        first_plain = self.plaintext[12:]
        self.decrypted_file.seek(87)
        second = self.decrypted_file.read(8)
        second_plain = self.plaintext[87:87+8]
        with self.subTest():
            self.assertEqual(first, first_plain)
        with self.subTest():
            self.assertEqual(second,second_plain)

    def test_tell(self):
        """Ensure we tell the correct cursor position"""
        self.decrypted_file.seek(538)
        self.assertEqual(self.decrypted_file.tell(),538)