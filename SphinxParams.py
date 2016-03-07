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
# The LIONESS implementation and the xcounter CTR mode class are adapted
# from "Experimental implementation of the sphinx cryptographic mix
# packet format by George Danezis".

import os
from SphinxNymserver import Nymserver

try:
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256, HMAC
    from Crypto.Util import number
except:
    print "\n\n*** You need to install the Python Cryptography Toolkit. ***\n\n"
    raise

try:
    from curvedh import *
except:
    pass

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

        self.g = basepoint()

    def gensecret(self):
        return makesecret(os.urandom(32))

    def expon(self, base, exp):
        return curvedh(exp, base)

    def multiexpon(self, base, exps):
	baseandexps = [base]
	baseandexps.extend(exps)
	return reduce(self.expon, baseandexps)

    def makeexp(self, data):
        assert len(data) == 32
        return makesecret(data)

    def in_group(self, alpha):
	# All strings of length 32 are in the group, says DJB
	return len(alpha) == 32

    def printable(self, alpha):
	return alpha.encode("hex")

class SphinxParams:
    k = 16 # in bytes, == 128 bits
    m = 1024 # size of message body, in bytes
    pki = {} # mapping of node id to node
    clients = {} # mapping of destinations to clients

    def __init__(self, r=5, ecc=False):
	self.r = r
	if ecc:
	    self.group = Group_ECC()
	else:
	    self.group = Group_p()

	self.nymserver = Nymserver(self)

    def xor(self, str1, str2):
	# XOR two strings
	assert len(str1) == len(str2)
	return HMAC._strxor(str1,str2)

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

    # The LIONESS PRP

    def lioness_enc(self, key, message):
	assert len(key) == self.k
	assert len(message) >= self.k * 2
	# Round 1
	r1 = self.xor(self.hash(message[self.k:]+key+'1')[:self.k],
			message[:self.k]) + message[self.k:]

	# Round 2
	k2 = self.xor(r1[:self.k], key)
	c = AES.new(k2, AES.MODE_CTR, counter=self.xcounter(self.k))
	r2 = r1[:self.k] + c.encrypt(r1[self.k:])

	# Round 3
	r3 = self.xor(self.hash(r2[self.k:]+key+'3')[:self.k], r2[:self.k]) + r2[self.k:]

	# Round 4
	k4 = self.xor(r3[:self.k], key)
	c = AES.new(k4, AES.MODE_CTR, counter=self.xcounter(self.k))
	r4 = r3[:self.k] + c.encrypt(r3[self.k:])

	return r4

    def lioness_dec(self, key, message):
	assert len(key) == self.k
	assert len(message) >= self.k * 2

	r4 = message

	# Round 4
	k4 = self.xor(r4[:self.k], key)
	c = AES.new(k4, AES.MODE_CTR, counter=self.xcounter(self.k))
	r3 = r4[:self.k] + c.encrypt(r4[self.k:])

	# Round 3
	r2 = self.xor(self.hash(r3[self.k:]+key+'3')[:self.k], r3[:self.k]) + r3[self.k:]

	# Round 2
	k2 = self.xor(r2[:self.k], key)
	c = AES.new(k2, AES.MODE_CTR, counter=self.xcounter(self.k))
	r1 = r2[:self.k] + c.encrypt(r2[self.k:])

	# Round 1
	r0 = self.xor(self.hash(r1[self.k:]+key+'1')[:self.k], r1[:self.k]) + r1[self.k:]

	return r0

    # The PRG; key is of length k, output is of length (2r+3)k
    def rho(self, key):
	assert len(key) == self.k
	c = AES.new(key, AES.MODE_CTR, counter=self.xcounter(self.k))
	return c.encrypt("\x00" * ( (2 * self.r + 3) * self.k ))

    # The HMAC; key is of length k, output is of length k
    def mu(self, key, data):
	m = HMAC.new(key, msg=data, digestmod=SHA256)
	return m.digest()[:self.k]

    # The PRP; key is of length k, data is of length m
    def pi(self, key, data):
	assert len(key) == self.k
	assert len(data) == self.m

	return self.lioness_enc(key, data)

    # The inverse PRP; key is of length k, data is of length m
    def pii(self, key, data):
	assert len(key) == self.k
	assert len(data) == self.m

	return self.lioness_dec(key, data)

    # The various hashes

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

if __name__ == '__main__':
    p = SphinxParams(5, True)
    print p.hb(p.group.g, p.group.g).encode("hex")
    print p.rho("1234" * 4).encode("hex")
