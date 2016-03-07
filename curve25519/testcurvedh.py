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
from curvedh import *

g = basepoint()

print "g:", g.encode("hex")

# Make a secret key from 32 random bytes
x = makesecret(os.urandom(32))
y = makesecret(os.urandom(32))

print "x:", x.encode("hex")
print "y:", y.encode("hex")

# Do the exponentiation operation.  Note: first exponent, then base
X = curvedh(x,g)
Y = curvedh(y,g)

print "X:", X.encode("hex")
print "Y:", Y.encode("hex")

s1 = curvedh(x,Y)
s2 = curvedh(y,X)

print "s:", s1.encode("hex")
print "s:", s2.encode("hex")

assert s1 == s2

print "DH Success!"
