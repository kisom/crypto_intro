# publickey.py: public key cryptographic functions
"""
Secret-key functions from chapter 1 of "A Working Introduction to
Cryptography with Python".
"""

import Crypto.Hash.SHA384 as SHA384
import pyelliptic
import secretkey
import struct


__CURVE = 'secp521r1'


def generate_key():
    """Generate a new elliptic curve keypair."""
    return pyelliptic.ECC(curve=__CURVE)


def sign(priv, msg):
    """Sign a message with the ECDSA key."""
    return priv.sign(msg)


def verify(pub, msg, sig):
    """
    Verify the public key's signature on the message. pub should
    be a serialised public key.
    """
    return pyelliptic.ECC(curve='secp521r1', pubkey=pub).verify(sig, msg)


def shared_key(priv, pub):
    """Generate a new shared encryption key from a keypair."""
    key = priv.get_ecdh_key(pub)
    key = key[:32] + SHA384.new(key[32:]).digest()
    return key


def encrypt(pub, msg):
    """
    Encrypt the message to the public key using ECIES. The public key
    should be a serialised public key.
    """
    ephemeral = generate_key()
    key = shared_key(ephemeral, pub)
    ephemeral_pub = struct.pack('>H', len(ephemeral.get_pubkey()))
    ephemeral_pub += ephemeral.get_pubkey()
    return ephemeral_pub+secretkey.encrypt(msg, key)


def decrypt(priv, msg):
    """
    Decrypt an ECIES-encrypted message with the private key.
    """
    ephemeral_len = struct.unpack('>H', msg[:2])[0]
    ephemeral_pub = msg[2:2+ephemeral_len]
    key = shared_key(priv, ephemeral_pub)
    return secretkey.decrypt(msg[2+ephemeral_len:], key)
