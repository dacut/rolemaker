#!/usr/bin/env python3
"""
Encryption handler for Rolemaker.
"""
from base64 import b64decode, b64encode

class KMSCrypto(object):
    # pylint: disable=too-few-public-methods
    """
    Implement encryption/decryption using AWS Key Management Service.
    """
    enc_context = {"KeyType": "RSAPrivateKey"}

    def __init__(self, kms, key_id):
        """
        KMSCrypto(kms, key_id) -> KMSCrypto

        Create a new KMSCrypto instance.

        kms: A Boto3 KMS client object.
        key_id: The KMS key id to use to encrypt the key.
        """
        super(KMSCrypto, self).__init__()
        self.kms = kms
        self.key_id = key_id
        return

    def encrypt(self, plaintext, enc_context):
        """
        encrypt(plaintext, enc_context) -> bytes

        Encrypt, returning an opaque set of bytes.
        """
        encrypt_response = self.kms.encrypt(
            KeyId=self.key_id, Plaintext=plaintext,
            EncryptionContext=enc_context)
        return b64encode(encrypt_response["CiphertextBlob"])

    def decrypt(self, ciphertext, enc_context):
        """
        decrypt(ciphertext, enc_context) -> bytes

        Decrypt, returning the original plaintext bytes.
        """
        decrypt_response = self.kms.decrypt(
            CiphertextBlob=b64decode(ciphertext),
            EncryptionContext=enc_context)
        return decrypt_response["Plaintext"]
