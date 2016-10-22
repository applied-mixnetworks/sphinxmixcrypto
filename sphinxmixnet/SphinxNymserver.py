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

from SphinxNode import pad_body

class Nymserver:
    def __init__(self, params):
	self.params = params
	self.database = {}

    def add_surb(self, nym, nymtuple):
	db = self.database
	if nym in db:
	    db[nym].append(nymtuple)
	else:
	    db[nym] = [nymtuple]

    def send_to_nym(self, nym, message):
	p = self.params
	pki = p.pki
	db = self.database
	print "Nymserver received message for [%s]" % nym
	if nym in db and len(db[nym]) > 0:
	    n0, header0, ktilde = db[nym].pop(0)
	    body = p.pi(ktilde, pad_body(p.m, ("\x00" * p.k) + message))
	    pki[n0].process(header0, body)
	else:
	    print "No SURBs available for nym [%s]" % nym
