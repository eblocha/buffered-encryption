Buffered Encryption
===================

Encrypt large data files chunk-by-chunk, securely.

This package uses AES in GCM mode to encrypt and decrypt file streams.

It relies on the cryptography library to perform the encryption.

```
big unencrypted file, verification data --> encrypt and sign --> encrypted file, iv, tag

big unencrypted file <-- decrypt and verify <-- encrypted file, iv, tag, verification data
```

Examples
--------

### AES in GCM mode

The `aesgcm` module provides a way to encrypt and decrypt entire files without loading the entire thing into memory. It does not provide a file-like interface to the encrypted file.

```python
import os
from buffered_encryption.aesgcm import EncryptionIterator, DecryptionIterator

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

### AES in CTR mode

The `aesctr` module allows you to read and seek an encrypted file as if it was a normal file. This provides a file-like interface while the data on disk stays encrypted.

This will be on the disk:
```python
b"1\xb2<\xcco\xbb\xa5%\xa9\xce\xb0\xac\x12\xc1Cw {\xdd\x0c\xa1\x93\x1b'E=v4L\xb8\xb9\x0e\xd5\x90\x8d\xf3H \xeb\x99iX\xcf\xea\xfc\xac\x92\xe8\xff\xb3\xbbS\xcaM\xb2\xf3?\xdf\xd9\x80\xbf\xef\x06\xa2\xab\x977\xc0\xcc\x0f\xd6\xd6' ,"
```

This will be what you read into python:
```python
b"Hello, World!! This message is longer than the AES block size of 16 bytes!!"
```

Key and nonce used in the above:
```python
key = b'\x0e\x07)\xb8*\xda\x13\x19\xc7`"\x14\xc1i\xe3\xf1$\xa5\xc7w\xda\x1dU\t\x9c\x1f{\xf5tR\xa7b'

nonce = b'6\x03\xf5\xdd\x92\x17\x0cDg\xcc\x1a\x9f\xe1\x08\x98\x7f'

```

To recreate this:
```python
import os, io
from buffered_encryption.aesctr import EncryptionIterator, ReadOnlyEncryptedFile
key = os.urandom(32)
nonce = os.urandom(16)
plaintext = b"Hello, World!! This message is longer than the AES block size of 16 bytes!!"

# Write the ciphertext to a buffer (you can also write to a file)
ciphertext_buf = io.BytesIO()
enc = EncryptionIterator(io.BytesIO(plaintext),key,nonce)
for chunk in enc:
    ciphertext_buf.write(chunk)

ciphertext_buf.seek(0)

# Create our read-only encrypted file
ef = ReadOnlyEncryptedFile(ciphertext_buf,key,nonce)

# Read 12 bytes of data
ef.read(12) # returns b"Hello, World"

# Seekable
ef.seek(7)

# Keep reading
ef.read(18) # returns b"World!! This messa"
```

### Why read-only?

Read-only ensures you do not use the same nonce for different messages. You cannot write different data to a block using the same nonce, and still be cryptographically secure. So if you were to re-write to the encrypted file, you have now defeated your own encryption.