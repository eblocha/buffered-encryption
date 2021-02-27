Buffered Encryption
===================

Encrypt large data files chunk-by-chunk, securely.

This package uses AES in GCM mode to encrypt and decrypt file streams.

It relies on the cryptography library to perform the encryption.

```
big unencrypted file, verification data --> encrypt and sign --> encrypted file, iv, tag

big unencrypted file <-- decrypt and verify <-- encrypted file, iv, tag, verification data
```

Example
-------
```python
import os
from buffered_encryption import EncryptionIterator, DecryptionIterator

plaintext = open("plain.txt","rb")

key = os.urandom(32)
sig = os.urandom(12)

enc = EncryptionIterator(plaintext,key,sig)
with open("cipher","wb") as ciphertext:
    for chunk in enc:
        ciphertext.write(chunk)

plaintext.close()

ciphertext = open("cipher","rb")

dec = DecryptionIterator(ciphertext,key,sig,enc.iv,enc.tag)
with open("plain.dec.txt","wb") as decrypted:
    for chunk in dec:
        decrypted.write(chunk)

ciphertext.close()
```

Classes
-------
```python

class EncryptionIterator:
    """
    Encrypt a file iteratively

    Parameters
    ----------
    file : io.BytesIO
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
```

```python
class DecryptionIterator:
    """
    Decrypt a file iteratively

    Parameters
    ----------
    file : io.BytesIO
        The file buffer to encrypt
    key : bytes
        The secret key for AES encryption
    signature : bytes
        Additional data used to verify the key later
    iv : bytes
        The initialization vector from the EncryptionIterator object
    tag : bytes
        The tag used for data integrity from the EncryptionIterator object
    chunk_size : int
        How much data to encrypt per iteration
    """
```