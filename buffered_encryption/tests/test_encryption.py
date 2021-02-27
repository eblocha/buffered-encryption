from buffered_encryption import EncryptionIterator, DecryptionIterator

import unittest
import os
import io

class TestSymmetry(unittest.TestCase):
    
    def setUp(self):
        self.plain = os.urandom(128*1024)
        self.cipher = io.BytesIO()
        self.key = os.urandom(32)
        self.sig = os.urandom(16)
    
    def test_context(self):
        iterator = EncryptionIterator(io.BytesIO(self.plain),self.key,self.sig)
        for ciphertext in iterator:
            self.cipher.write(ciphertext)

        iv, tag = iterator.iv, iterator.tag
        self.cipher.seek(0)
        plain_dec = b''
        for plaintext in DecryptionIterator(self.cipher,self.key,self.sig,iv,tag):
            plain_dec += plaintext

        self.assertEqual(self.plain,plain_dec)
    
