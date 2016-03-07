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

# Padding/unpadding of message bodies: a 0 bit, followed by as many 1
# bits as it takes to fill it up

def pad_body(msgtotalsize, body):
    body = body + "\x7f"
    body = body + ("\xff" * (msgtotalsize - len(body)))
    return body

def unpad_body(body):
    return re.compile("\x7f\xff*$").sub('',body)

# Prefix-free encoding/decoding of node names and destinations

# The special destination
Dspec = "\x00"

# Any other destination.  Must be between 1 and 127 bytes in length
def Denc(dest):
    assert len(dest) >= 1 and len(dest) <= 127
    return chr(len(dest)) + dest

# Sphinx nodes

class SphinxNode:
    def __Nenc(self, idnum):
	id = "\xff" + idnum + ("\x00" * (self.p.k - len(idnum) - 1))
	assert len(id) == self.p.k
	return id

    # Decode the prefix-free encoding.  Return the type, value, and the
    # remainder of the input string
    def __PFdecode(self, s):
	if s == "": return None, None, None
	if s[0] == '\x00': return 'Dspec', None, s[1:]
	if s[0] == '\xff': return 'node', s[:self.p.k], s[self.p.k:]
	l = ord(s[0])
	if l < 128: return 'dest', s[1:l+1], s[l+1:]
	return None, None, None

    def __init__(self, params):
	self.p = params
	group = self.p.group
	self.__x = group.gensecret()
	self.y = group.expon(group.g, self.__x)
	idnum = os.urandom(4)
	self.id = self.__Nenc(idnum)
	self.name = "Node " + idnum.encode("hex")
	self.seen = {}
	params.pki[self.id] = self

    def process(self, header, delta):
	print "Processing at", self.name
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
	    print "MAC mismatch!"
	    print "alpha =", group.printable(alpha)
	    print "s =", group.printable(s)
	    print "beta =", beta.encode("hex")
	    print "gamma =", gamma.encode("hex")
	    return

	self.seen[tag] = 1

	B = p.xor(beta + ("\x00" * (2 * p.k)), p.rho(p.hrho(s)))

	type, val, rest = self.__PFdecode(B)

	if type == "node":
	    print "Next hop is", pki[val].name
	    b = p.hb(alpha, s)
	    alpha = group.expon(alpha, b)
	    gamma = B[p.k:p.k*2]
	    beta = B[p.k*2:]
	    delta = p.pii(p.hpi(s), delta)
	    return pki[val].process((alpha, beta, gamma), delta)

	if type == "Dspec":
	    # Uncomment the following to see what the exit node sees
	    # print ' '.join(["%02x"%ord(x) for x in B])
	    delta = p.pii(p.hpi(s), delta)
	    if delta[:p.k] == ("\x00" * p.k):
		type, val, rest = self.__PFdecode(delta[p.k:])
		if type == "dest":
		    # We're to deliver rest (unpadded) to val
		    body = unpad_body(rest)
		    print "Deliver [%s] to [%s]" % (body, val)
		    return

	if type == "dest":
	    id = rest[:p.k]
	    delta = p.pii(p.hpi(s), delta)
	    print "Deliver reply message to [%s]" % val
	    if val in p.clients:
		return p.clients[val].process(id, delta)
	    else:
		print "No such client [%s]" % val
		return

if __name__ == '__main__':

    from SphinxParams import SphinxParams

    p = SphinxParams()
    n = SphinxNode(p)

    print "name =", n.name
    print "y =", n.y
