#!/usr/bin/env python

# Copyright 2011 Ian Goldberg
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

from sphinxmixcrypto.nym_server import Nymserver
from sphinxmixcrypto.node import KeyMismatchError, BlockSizeMismatchError


BLINDING_HASH_PREFIX = b'\x11'
RHO_HASH_PREFIX = b'\x22'
MU_HASH_PREFIX = b'\x33'
PI_HASH_PREFIX = b'\x44'
TAU_HASH_PREFIX = b'\x55'


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


def Blake2_hash(data):
    b = blake2b(data=bytes(data), digest_size=32)
    return b.digest()


def Blake2_hash_mac(key, data, digest_size=16):
    b = blake2b(data=data, key=key, digest_size=digest_size)
    return b.digest()


def Chacha20_stream_cipher(key):
    assert len(key) == 32
    nonce = b"\x00" * 8  # it's OK to use zero nonce because we only use it once
    return ChaCha20.new(key=key, nonce=nonce)


class Chacha_Lioness:
    def __init__(self, key, block_size):
        assert len(key) == Chacha20_Blake2b_Lioness.KEY_LEN
        self.cipher = Chacha20_Blake2b_Lioness(key, block_size)

    def encrypt(self, block):
        return self.cipher.encrypt(block)

    def decrypt(self, block):
        return self.cipher.decrypt(block)


class SphinxParams:
    k = 16  # in bytes, == 128 bits
    m = 1024  # size of message body, in bytes
    clients = {}  # mapping of destinations to clients

    def __init__(self, path_len=5, group_class=None, lioness_class=None,
                 hash_func=None, hash_mac_func=None, stream_cipher=None):
        self.r = path_len
        assert group_class is not None
        self.group = group_class()
        self.lioness_class = lioness_class
        self.hash_func = hash_func
        self.hash_mac_func = hash_mac_func
        self.stream_cipher = stream_cipher
        self.nymserver = Nymserver(self)

    def get_dimensions(self):
        """
        header overhead = p + (2r + 2)s
        where p is the asymmetric element,
        s is the symmetric element and
        r is the max route length
        alpha 32 beta 176 gamma 16 delta 1024
        """
        alpha = self.group.size
        beta = (2 * self.r + 1) * self.k
        gamma = self.k
        delta = self.m
        return alpha, beta, gamma, delta

    def lioness_encrypt(self, key, data):
        c = self.lioness_class(key, len(data))
        return c.encrypt(data)

    def lioness_decrypt(self, key, data):
        c = self.lioness_class(key, len(data))
        return c.decrypt(data)

    def xor(self, str1, str2):
        # XOR two strings
        assert len(str1) == len(str2)
        return bytes(strxor(str1, str2))

    # The PRG; key is 32 bytes, output is of length (2r+3)k
    def rho(self, key):
        assert len(key) == 32
        c = self.stream_cipher(key)
        return c.encrypt(b"\x00" * ((2 * self.r + 3) * self.k))

    # The HMAC; key is of length k, output is of length k
    def mu(self, key, data):
        assert len(key) == self.k
        m = self.hash_mac_func(key, data)
        return m

    # The PRP; key is of length k, data is of length m
    def pi(self, key, data):
        if len(key) != Chacha20_Blake2b_Lioness.KEY_LEN:
            raise KeyMismatchError()
        if len(data) != self.m:
            raise BlockSizeMismatchError()
        return self.lioness_encrypt(key, data)

    # The inverse PRP; key is of length k, data is of length m
    def pii(self, key, data):
        if len(key) != Chacha20_Blake2b_Lioness.KEY_LEN:
            raise KeyMismatchError()
        if len(data) != self.m:
            raise BlockSizeMismatchError()
        return self.lioness_decrypt(key, data)

    def hb(self, alpha, s):
        "Compute a hash of alpha and s to use as a blinding factor"
        assert len(s) == 32
        assert len(alpha) == 32
        return self.group.makeexp(self.hash_func(BLINDING_HASH_PREFIX + alpha + s))

    def create_stream_cipher_key(self, s):
        assert len(s) == 32
        return self.hash_func(RHO_HASH_PREFIX + s)

    def hmu(self, s):
        "Compute a hash of s to use as a key for the HMAC mu"
        b = blake2b(digest_size=16)
        b.update(MU_HASH_PREFIX)
        b.update(s)
        return b.digest()

    def create_block_cipher_key(self, secret):
        """
        Compute a key cipher key using the secret
        """
        assert len(secret) == 32
        stream_cipher_key = self.create_stream_cipher_key(secret)
        c = self.stream_cipher(stream_cipher_key)
        key = c.encrypt(b"\x00" * Chacha20_Blake2b_Lioness.KEY_LEN)
        assert len(key) == Chacha20_Blake2b_Lioness.KEY_LEN
        return key

    def htau(self, s):
        "Compute a hash of s to use to see if we've seen s before"
        return self.hash_func(TAU_HASH_PREFIX + s)
