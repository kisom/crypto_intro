PUBLIC KEY CRYPTOGRAPHY
=======================

The original version of this document had examples of using RSA
cryptography with Python. However, RSA should be avoided for modern
secure systems, and I haven't been using Python, so I'm not very
familiar with the options for elliptic curve cryptography. Rather
than encouraging the use of a weaker cipher, I've opted to elide
this. A possible starting point is to look at Yann Guibet's
[pyelliptic](https://github.com/yann2192/pyelliptic) package. It
should provide ECDSA for signatures, and ECDH for encryption.
