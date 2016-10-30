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

import os

from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Util import number
from Crypto.Util.strxor import strxor
from nacl.bindings import crypto_scalarmult
from pyblake2 import blake2b
from Cryptodome.Cipher import ChaCha20

from pylioness import Chacha20_Blake2b_Lioness, AES_SHA256_Lioness

from SphinxNymserver import Nymserver


class Group_p:
    "Group operations mod p"

    def __init__(self):
        # A 2048-bit prime
        self.__p = 19134104382515471340121383082934308828788465164876922483018046665189568608385336521385528455852870226729419515782445769946311524543401780679763787388729547181989737060289407062479214017446428251157469940819568673215805731815521523529008837868909929585628774673216239536406270201585439559139691697966359990510412034461369768357756615060575177060679433618196595458284826534928911045879135540240765445688036648761768417624100416438042808407759355983611319236017991473072964105392335897160201662655194201702312372678481213560443558381777521284259428911914008097936688649209670009892790669991823472515537714171774700422727L

        # A 256-bit prime.  q | p-1, and (p-1)/(2q) is also prime
        self.__q = 106732665057690615308701680462846682779480968671143352109289849544853387479559L

        # A generator of the 256-bit subgroup of order q
        self.g = 4841394417863494412227539373591815072221868474834407003108964621656948087607533132014406209384264001860614005413470474998618595063750798301826341774223008476018405743602814857378470614748174056572493655989586557587396511347276474665778845699406935799833636365083206218330593315513720711460353255243954204178057633122609221947354829869069875474221603457407347332029203573680170785191212685833773827500371044142146648183369300927714600114538209692069873794191715382617278768149594654315895296485533292574866819385073141870483659577707892565451842181763727355979252885729688362656338077037492411991956527093735651034592L

    def gensecret(self):
        return number.bytes_to_long(os.urandom(256)) % self.__q

    def expon(self, base, exp):
        return pow(base, exp, self.__p)

    def multiexpon(self, base, exps):
        return pow(base, reduce(lambda x,y: x*y % self.__q, exps), self.__p)

    def makeexp(self, data):
        return number.bytes_to_long(data) % self.__q

    def in_group(self, alpha):
        return alpha > 1 and alpha < (self.__p - 1) and \
            pow(alpha, self.__q, self.__p) == 1

    def printable(self, alpha):
        return str(alpha)


class Group_ECC:
    "Group operations in ECC"

    def __init__(self):

        self.g = self.basepoint()

    def basepoint(self):
        curve_bytes = []
        curve_bytes.append(b'\x09')
        for i in range(1,32):
            curve_bytes.append(b'\x00')
        return str(bytearray(curve_bytes))

    def makesecret(self, exp):
        """
        makesecret takes a byte string and converts them to a list of one byte integers
        before doing some bit manipulations and then returns the list of one byte ints
        """
        curve_out = []
        for c in exp:
            curve_out.append(ord(c))
        curve_out[0] &= 248
        curve_out[31] &= 127
        curve_out[31] |= 64
        return str(bytearray(curve_out))

    def gensecret(self):
        return self.makesecret(os.urandom(32))

    def expon(self, base, exp):
        return crypto_scalarmult(exp, base)

    def multiexpon(self, base, exps):
        baseandexps = [base]
        baseandexps.extend(exps)
        return reduce(self.expon, baseandexps)

    def makeexp(self, data):
        assert len(data) == 32
        return self.makesecret(data)

    def in_group(self, alpha):
        # All strings of length 32 are in the group, says DJB
        return len(alpha) == 32

    def printable(self, alpha):
        return alpha.encode("hex")


class xcounter:
    # Implements a string counter to do AES-CTR mode
    i = 0
    def __init__(self, size):
        self.size = size

    def __call__(self):
        ii = number.long_to_bytes(self.i)
        ii = '\x00' * (self.size-len(ii)) + ii
        self.i += 1
        return ii


def AES_stream_cipher(key):
    return AES.new(key, AES.MODE_CTR, counter=xcounter(16))

def Chacha20_stream_cipher(key):
    b = blake2b(data=key)
    new_key = b.digest()
    return ChaCha20.new(key=new_key[8:40], nonce=new_key[0:8])

class AES_Lioness:
    def __init__(self, key, block_size):
        self.cipher = AES_SHA256_Lioness(key, block_size)

    def encrypt(self, block):
        return self.cipher.encrypt(block)

    def decrypt(self, block):
        return self.cipher.decrypt(block)


class Chacha_Lioness:
    def __init__(self, key, block_size):
        b = blake2b(data=key)
        new_key = b.digest()
        c = ChaCha20.new(key=new_key[8:40], nonce=new_key[:8])
        lioness_key = c.encrypt(b'\x00' * 208)
        self.cipher = Chacha20_Blake2b_Lioness(lioness_key, block_size)

    def encrypt(self, block):
        return self.cipher.encrypt(block)

    def decrypt(self, block):
        return self.cipher.decrypt(block)


class SphinxParams:
    k = 16 # in bytes, == 128 bits
    m = 1024 # size of message body, in bytes
    clients = {} # mapping of destinations to clients

    def __init__(self, r=5, group_class=None, lioness_class=None,
                 lioness_key_len=None, stream_cipher=None):
        self.r = r
        assert group_class is not None
        self.group = group_class()
        self.lioness_class = lioness_class
        self.stream_cipher = stream_cipher
        self.nymserver = Nymserver(self)

    def lioness_encrypt(self, key, data):
        c = self.lioness_class(key, len(data))
        return c.encrypt(data)

    def lioness_decrypt(self, key, data):
        c = self.lioness_class(key, len(data))
        return c.decrypt(data)

    def xor(self, str1, str2):
        # XOR two strings
        assert len(str1) == len(str2)
        return strxor(str1, str2)

    # The PRG; key is of length k, output is of length (2r+3)k
    def rho(self, key):
        assert len(key) == self.k
        c = self.stream_cipher(key)
        return c.encrypt("\x00" * ( (2 * self.r + 3) * self.k ))

    # The HMAC; key is of length k, output is of length k
    def mu(self, key, data):
        m = HMAC.new(key, msg=data, digestmod=SHA256)
        return m.digest()[:self.k]

    # The PRP; key is of length k, data is of length m
    def pi(self, key, data):
        assert len(key) == self.k
        assert len(data) == self.m
        return self.lioness_encrypt(key, data)

    # The inverse PRP; key is of length k, data is of length m
    def pii(self, key, data):
        assert len(key) == self.k
        assert len(data) == self.m

        return self.lioness_decrypt(key, data)

    def hash(self, data):
        h = SHA256.new()
        h.update(data)
        return h.digest()

    def hb(self, alpha, s):
        "Compute a hash of alpha and s to use as a blinding factor"
        group = self.group
        return group.makeexp(self.hash("hb:" + group.printable(alpha)
            + " , " + group.printable(s)))

    def hrho(self, s):
        "Compute a hash of s to use as a key for the PRG rho"
        group = self.group
        return (self.hash("hrho:" + group.printable(s)))[:self.k]

    def hmu(self, s):
        "Compute a hash of s to use as a key for the HMAC mu"
        group = self.group
        return (self.hash("hmu:" + group.printable(s)))[:self.k]

    def hpi(self, s):
        "Compute a hash of s to use as a key for the PRP pi"
        group = self.group
        return (self.hash("hpi:" + group.printable(s)))[:self.k]

    def htau(self, s):
        "Compute a hash of s to use to see if we've seen s before"
        group = self.group
        return (self.hash("htau:" + group.printable(s)))
