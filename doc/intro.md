Introduction
============

Recently at work I have been using the
[PyCrypto](https://www.dlitz.net/software/pycrypto/) libraries quite
a bit. The documentation is pretty good, but there are a few areas
that took me a bit to figure out. In this post, I’ll be writing up
a quick overview of the PyCrypto library and cover some general
things to know when writing cryptographic code in general. I’ll go
over symmetric, public-key, hybrid, and message authentication
codes. Keep in mind this is a quick introduction and a lot of gross
simplifications are made. For a more complete introduction to
cryptography, take a look at the references at the end of this
article. This article is just an appetite-whetter - if you have a
real need for information security you should hire an expert. Real
data security goes beyond this quick introduction (you wouldn’t
trust the design and engineering of a bridge to a student with a
quick introduction to civil engineering, would you?)

Some quick terminology: for those unfamiliar, I introduce the following
terms:

* plaintext: the original message

* ciphertext: the message after cryptographic transformations are
applied to obscure the original message.

* encrypt: producing ciphertext by applying cryptographic transformations
to plaintext.

* decrypt: producing plaintext by applying cryptographic transformations
to ciphertext.

* cipher: a particular set of cryptographic transformations providing
means of both encryption and decryption.

* hash: a set of cryptographic transformations that take a large
input and transform it to a unique (typically fixed-size) output.
For hashes to be cryptographically secure, collisions should be
practically nonexistent. It should be practically impossible to
determine the input from the output.

Cryptography is an often misunderstood component of information
security, so an overview of what it is and what role it plays is in
order. There are four major roles that cryptography plays:

* confidentiality: ensuring that only the intended recipients receive
the plaintext of the message.

* data integrity: the plaintext message arrives unaltered.

* entity authentication: the identity of the sender is verified.
An entity may be a person or a machine.

* message authentication: the message is verified as having been
unaltered.

Note that cryptography is used to obscure the contents of a message and
verify its contents and source. It will **not** hide the fact that two
entities are communicating.

There are two basic types of ciphers: symmetric and public-key ciphers.
A symmetric key cipher employs the use of shared secret keys. They also
tend to be much faster than public-key ciphers. A public-key cipher is
so-called because each key consists of a private key which is used to
generate a public key. Like their names imply, the private key is kept
secret while the public key is passed around. First, I’ll take a look at
a specific type of symmetric ciphers: block ciphers.



