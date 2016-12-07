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

import os
from functools import reduce

from Crypto.Util.strxor import strxor
from nacl.bindings import crypto_scalarmult
from pyblake2 import blake2b
from Cryptodome.Cipher import ChaCha20

from pylioness import Chacha20_Blake2b_Lioness

from sphinxmixcrypto.nym_server import Nymserver
from sphinxmixcrypto.node import KeyMismatchError, BlockSizeMismatchError


BLINDING_HASH_PREFIX = b'\0x11'
RHO_HASH_PREFIX = b'\0x22'
MU_HASH_PREFIX = b'\0x33'
PI_HASH_PREFIX = b'\0x44'
TAU_HASH_PREFIX = b'\0x55'


class GroupECC:
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

    def gensecret(self):
        return self.makesecret(os.urandom(self.size))

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
    b = blake2b(data=bytes(data))
    h = b.digest()
    return h[:32]


def Blake2_hash_mac(key, data, digest_size=16):
    b = blake2b(data=data, key=key, digest_size=digest_size)
    return b.digest()


def Chacha20_stream_cipher(key):
    b = blake2b(data=key)
    new_key = b.digest()
    return ChaCha20.new(key=new_key[8:40], nonce=new_key[0:8])


class Chacha_Lioness:
    def __init__(self, key, block_size):
        c = Chacha20_stream_cipher(key)
        lioness_key = c.encrypt(b'\x00' * 208)
        self.cipher = Chacha20_Blake2b_Lioness(lioness_key, block_size)

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

    # The PRG; key is of length k, output is of length (2r+3)k
    def rho(self, key):
        assert len(key) == self.k
        c = self.stream_cipher(key)
        return c.encrypt(b"\x00" * ((2 * self.r + 3) * self.k))

    # The HMAC; key is of length k, output is of length k
    def mu(self, key, data):
        m = self.hash_mac_func(key, data)
        return m

    # The PRP; key is of length k, data is of length m
    def pi(self, key, data):
        assert len(key) == self.k
        assert len(data) == self.m
        return self.lioness_encrypt(key, data)

    # The inverse PRP; key is of length k, data is of length m
    def pii(self, key, data):
        if len(key) != self.k:
            raise KeyMismatchError()
        if len(data) != self.m:
            raise BlockSizeMismatchError()

        return self.lioness_decrypt(key, data)

    def hb(self, alpha, s):
        "Compute a hash of alpha and s to use as a blinding factor"
        return self.group.makeexp(self.hash_func(BLINDING_HASH_PREFIX + alpha + s))

    def hrho(self, s):
        "Compute a hash of s to use as a key for the PRG rho"
        return (self.hash_func(RHO_HASH_PREFIX + s))[:self.k]

    def hmu(self, s):
        "Compute a hash of s to use as a key for the HMAC mu"
        return (self.hash_func(MU_HASH_PREFIX + s))[:self.k]

    def hpi(self, s):
        "Compute a hash of s to use as a key for the PRP pi"
        return self.hash_func(PI_HASH_PREFIX + s)[:self.k]

    def htau(self, s):
        "Compute a hash of s to use to see if we've seen s before"
        return self.hash_func(TAU_HASH_PREFIX + s)
