#!/usr/bin/env python
"""
Interfaces to cryptographic utilities.
"""

from __future__ import absolute_import, division, print_function
from Crypto.Cipher import AES
import Crypto.Random

AES_BLOCKSIZE = 16

_random = Crypto.Random.new()

class EncryptedData(object):
    __slots__ = ["iv", "encrypted"]
    def __init__(self, iv, encrypted):
        super(EncryptedData, self).__init__()
        self.iv = iv
        self.encrypted = encrypted
        return

    def __str__(self):
        return self.encrypted

def generate_aes_iv():
    return _random.read(AES_BLOCKSIZE)

def aes_cbc_pkcs5_encrypt(key, plaintext, iv=None):
    if iv is None:
        iv = generate_aes_iv()

    # Pad the data out to the AES blocksize.        
    pad = AES_BLOCKSIZE - len(plaintext) % AES_BLOCKSIZE
    plaintext += chr(pad) * pad

    cipher = AES.new(key, AES.MODE_CBC, iv)
    return EncryptedData(iv, cipher.encrypt(plaintext))

def aes_cbc_pkcs5_decrypt(key, encrypted, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(encrypted)

    # Remove padding from the end
    pad = ord(plaintext[-1])
    return plaintext[:-pad]

# Local variables:
# mode: Python
# tab-width: 8
# indent-tabs-mode: nil
# End:
# vi: set expandtab tabstop=8
