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

import os
import re
from binascii import hexlify, unhexlify

# Padding/unpadding of message bodies: a 0 bit, followed by as many 1
# bits as it takes to fill it up

def pad_body(msgtotalsize, body):
    body = body + b"\x7f"
    body = body + (b"\xff" * (msgtotalsize - len(body)))
    return body

def unpad_body(body):
    return re.compile(b"\x7f\xff*$").sub(b'', body)

# Prefix-free encoding/decoding of node names and destinations

# The special destination
Dspec = b"\x00"

# Any other destination.  Must be between 1 and 127 bytes in length
def Denc(dest):
    assert len(dest) >= 1 and len(dest) <= 127
    return bytes([len(dest)]) + dest

# Sphinx nodes

class SphinxNode:
    def __Nenc(self, idnum):
        id = b"\xff" + idnum + (b"\x00" * (self.p.k - len(idnum) - 1))
        assert len(id) == self.p.k
        return id

    # Decode the prefix-free encoding.  Return the type, value, and the
    # remainder of the input string
    def __PFdecode(self, s):
        if s == b"": return None, None, None
        if s[0] == 0x00: return b'Dspec', None, s[1:]
        if s[0] == 0xff: return b'node', s[:self.p.k], s[self.p.k:]
        l = int(s[0])
        if l < 128: return b'dest', s[1:l+1], s[l+1:]
        return None, None, None

    def __init__(self, params):
        self.p = params
        group = self.p.group
        self.__x = group.gensecret()
        self.y = group.expon(group.g, self.__x)
        idnum = os.urandom(4)
        self.id = self.__Nenc(idnum)
        self.name = "Node {}".format(hexlify(idnum).decode())
        self.seen = {}
        params.pki[self.id] = self

    def process(self, header, delta):
        print("Processing at {}".format(self.name))
        p = self.p
        pki = p.pki
        group = p.group
        alpha, beta, gamma = header

        # Check that alpha is in the group
        if not group.in_group(alpha):
            return

        # Compute the shared secret
        s = group.expon(alpha, self.__x)

        # Have we seen it already?
        tag = p.htau(s)

        if tag in self.seen:
            return

        if gamma != p.mu(p.hmu(s), beta):
            print("MAC mismatch!")
            print("alpha =", group.printable(alpha))
            print("s =", group.printable(s))
            print("beta =", hexlify(beta))
            print("gamma =", hexlify(gamma))
            return

        self.seen[tag] = 1

        B = p.xor(beta + (b"\x00" * (2 * p.k)), p.rho(p.hrho(s)))

        type, val, rest = self.__PFdecode(B)

        if type == b"node":
            print("Next hop is {}".format(pki[val].name))
            b = p.hb(alpha, s)
            alpha = group.expon(alpha, b)
            gamma = B[p.k:p.k*2]
            beta = B[p.k*2:]
            delta = p.pii(p.hpi(s), delta)
            return pki[val].process((alpha, beta, gamma), delta)

        if type == b"Dspec":
            # Uncomment the following to see what the exit node sees
            # print(' '.join(["%02x" % byte([x]) for x in B]))
            delta = p.pii(p.hpi(s), delta)
            if delta[:p.k] == (b"\x00" * p.k):
                type, val, rest = self.__PFdecode(delta[p.k:])
                if type == b"dest":
                    # We're to deliver rest (unpadded) to val
                    body = unpad_body(rest)
                    print("Deliver [{}] to [{}]".format(body.decode(), val.decode()))
                    return

        if type == b"dest":
            id = rest[:p.k]
            delta = p.pii(p.hpi(s), delta)
            print("Deliver reply message to [{}]".format(val.decode()))
            if val in p.clients:
                return p.clients[val].process(id, delta)
            else:
                print("No such client [{}]".format(val.decode()))
                return

if __name__ == '__main__':

    from SphinxParams import SphinxParams

    p = SphinxParams()
    n = SphinxNode(p)

    print("name = {}".format(n.name))
    print("y = {}".format(n.y))
