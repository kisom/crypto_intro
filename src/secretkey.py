# secretkey.py: secret-key cryptographic functions
"""
Secret-key functions from chapter 1 of "A Working Introduction to
Cryptography with Python".
"""

import Crypto.Cipher.AES as AES
import Crypto.Hash.HMAC as HMAC
import Crypto.Hash.SHA384 as SHA384
import Crypto.Random.OSRNG.posix as RNG
import pbkdf2
import streql


__AES_KEYLEN = 32
__TAG_KEYLEN = 48
__TAG_LEN = __TAG_KEYLEN
KEYSIZE = __AES_KEYLEN + __TAG_KEYLEN


def pad_data(data):
    """pad_data pads out the data to an AES block length."""
    # return data if no padding is required
    if len(data) % 16 == 0:
        return data

    # subtract one byte that should be the 0x80
    # if 0 bytes of padding are required, it means only
    # a single \x80 is required.

    padding_required = 15 - (len(data) % 16)

    data = '%s\x80' % data
    data = '%s%s' % (data, '\x00' * padding_required)

    return data


def unpad_data(data):
    """unpad_data removes padding from the data."""
    if not data:
        return data

    data = data.rstrip('\x00')
    if data[-1] == '\x80':
        return data[:-1]
    else:
        return data


def generate_nonce():
    """Generate a random number used once."""
    return RNG.new().read(AES.block_size)


def new_tag(ciphertext, key):
    """Compute a new message tag using HMAC-SHA-384."""
    return HMAC.new(key, msg=ciphertext, digestmod=SHA384).digest()


def verify_tag(ciphertext, key):
    """Verify the tag on a ciphertext."""
    tag_start = len(ciphertext) - __TAG_LEN
    data = ciphertext[:tag_start]
    tag = ciphertext[tag_start:]
    actual_tag = new_tag(data, key)
    return streql.equals(actual_tag, tag)


def decrypt(ciphertext, key):
    """
    Decrypt a ciphertext encrypted with AES in CBC mode; assumes the IV
    has been prepended to the ciphertext.
    """
    if len(ciphertext) <= AES.block_size:
        return None, False
    tag_start = len(ciphertext) - __TAG_LEN
    ivec = ciphertext[:AES.block_size]
    data = ciphertext[AES.block_size:tag_start]
    if not verify_tag(ciphertext, key[__AES_KEYLEN:]):
        return None, False
    aes = AES.new(key[:__AES_KEYLEN], AES.MODE_CBC, ivec)
    data = aes.decrypt(data)
    return unpad_data(data), True


def encrypt(data, key):
    """
    Encrypt data using AES in CBC mode. The IV is prepended to the
    ciphertext.
    """
    data = pad_data(data)
    ivec = generate_nonce()
    aes = AES.new(key[:__AES_KEYLEN], AES.MODE_CBC, ivec)
    ctxt = aes.encrypt(data)
    tag = new_tag(ivec+ctxt, key[__AES_KEYLEN:])
    return ivec + ctxt + tag


def generate_salt(salt_len):
    """Generate a salt for use with PBKDF2."""
    return RNG.new().read(salt_len)


def password_key(passphrase, salt=None):
    """Generate a key from a passphrase. Returns the tuple (salt, key)."""
    if salt is None:
        salt = generate_salt(16)
    passkey = pbkdf2.PBKDF2(passphrase, salt, iterations=16384).read(KEYSIZE)
    return salt, passkey
