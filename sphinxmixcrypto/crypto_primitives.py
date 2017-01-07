# Copyright 2011 Ian Goldberg
# Copyright 2016-2017 David Stainton
#
# This file is part of Sphinx.
#
# Sphinx is free software: you can redistribute it and/or modify
# it under the terms of version 3 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# Sphinx is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with Sphinx.  If not, see
# <http://www.gnu.org/licenses/>.
#

"""
This module is used to parameterize the crypto primitives
used to encrypt/decrypt sphinx mixnet packets.
"""

from functools import reduce
from Crypto.Util.strxor import strxor
from nacl.bindings import crypto_scalarmult
from pyblake2 import blake2b
from Cryptodome.Cipher import ChaCha20
from pylioness import Chacha20_Blake2b_Lioness


# prefixes which are prefixed to data before hashing
BLINDING_HASH_PREFIX = b'\x11'
STREAM_CIPHER_HASH_PREFIX = b'\x22'
HMAC_HASH_PREFIX = b'\x33'
BLOCK_CIPHER_HASH_PREFIX = b'\x44'
REPLAY_HASH_PREFIX = b'\x55'

# curve25519 key is 32 bytes
CURVE25519_SIZE = 32
# Sphinx provides 128 bits of security as does curve25519
SECURITY_PARAMETER = 16


def xor(str1, str2):
    # XOR two strings
    assert len(str1) == len(str2)
    return bytes(strxor(str1, str2))


class GroupCurve25519:
    "Group operations in curve25519"
    size = 32

    def __init__(self):
        self.generator = self.basepoint()

    def basepoint(self):
        curve_bytes = b''
        curve_bytes += b'\x09'
        for i in range(1, 32):
            curve_bytes += b'\x00'
        return curve_bytes

    def makesecret(self, exp):
        """
        makesecret takes a byte string and converts them to a list of one byte integers
        before doing some bit manipulations and then returns the list of one byte ints
        """
        curve_out = []
        for c in exp:
            if isinstance(c, int):
                curve_out.append(c)
            else:
                curve_out.append(ord(c))
        curve_out[0] &= 248
        curve_out[31] &= 127
        curve_out[31] |= 64
        return bytes(bytearray(curve_out))

    def gensecret(self, randReader):
        return self.makesecret(randReader.read(self.size))

    def expon(self, base, exp):
        return crypto_scalarmult(bytes(exp), bytes(base))

    def multiexpon(self, base, exps):
        baseandexps = [base]
        baseandexps.extend(exps)
        return reduce(self.expon, baseandexps)

    def makeexp(self, data):
        assert len(data) == self.size
        return self.makesecret(data)

    def in_group(self, alpha):
        # All strings of length 32 are in the group, says DJB
        return len(alpha) == self.size


class SphinxLioness:
    def __init__(self):
        self.stream_cipher = SphinxStreamCipher()
        self.digest = SphinxDigest()

    def create_block_cipher_key(self, secret):
        """
        Compute a block cipher key using the secret
        """
        assert len(secret) == 32
        stream_cipher_key = self.digest.create_stream_cipher_key(secret)
        nonce = b"\x00" * 8  # it's OK to use zero nonce because we only use it once
        c = ChaCha20.new(key=stream_cipher_key, nonce=nonce)
        key = c.encrypt(b"\x00" * Chacha20_Blake2b_Lioness.KEY_LEN)
        assert len(key) == Chacha20_Blake2b_Lioness.KEY_LEN
        return key

    def encrypt(self, key, block):
        cipher = Chacha20_Blake2b_Lioness(key, len(block))
        return cipher.encrypt(block)

    def decrypt(self, key, block):
        cipher = Chacha20_Blake2b_Lioness(key, len(block))
        return cipher.decrypt(block)


class SphinxStreamCipher:

    def generate_stream(self, key, length):
        """
        The PRG; key is 32 bytes, output is of size length
        """
        assert len(key) == 32
        nonce = b"\x00" * 8  # it's OK to use zero nonce because we only use it once
        c = ChaCha20.new(key=key, nonce=nonce)
        return c.encrypt(b"\x00" * length)


class SphinxDigest:

    def __init__(self):
        self.group = GroupCurve25519()

    def hash(self, data):
        digest = blake2b(digest_size=32)
        digest.update(data)
        return digest.digest()

    def hmac(self, key, data):
        """
        key is of length SECURITY_PARAMETER
        output is of length SECURITY_PARAMETER
        """
        assert len(key) == SECURITY_PARAMETER
        b = blake2b(data=data, key=key, digest_size=SECURITY_PARAMETER)
        return b.digest()

    def hash_blinding(self, alpha, s):
        "Compute a hash of alpha and s to use as a blinding factor"
        assert len(s) == 32
        assert len(alpha) == 32
        return self.group.makeexp(self.hash(BLINDING_HASH_PREFIX + alpha + s))

    def create_stream_cipher_key(self, s):
        assert len(s) == 32
        return self.hash(STREAM_CIPHER_HASH_PREFIX + s)

    def create_hmac_key(self, s):
        "Compute a hash of s to use as a key for the HMAC mu"
        b = blake2b(digest_size=16)
        b.update(HMAC_HASH_PREFIX)
        b.update(s)
        return b.digest()

    def hash_replay(self, s):
        "Compute a hash of s to use to see if we've seen s before"
        return self.hash(REPLAY_HASH_PREFIX + s)
