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

from sphinxmixcrypto.node import pad_body, UnwrappedMessage

class SphinxNoSURBSAvailableError(Exception):
    pass

class NymResult:
    def __init__(self):
        self.message_result = None

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

    def process(self, nym, message):
        result = NymResult()
        p = self.params
        db = self.database
        if nym in db and len(db[nym]) > 0:
            n0, header0, ktilde = db[nym].pop(0)
            body = p.pi(ktilde, pad_body(p.m, (b"\x00" * p.k) + message))
            unwrapped_message = UnwrappedMessage()
            unwrapped_message.tuple_next_hop = (n0, header0, body)
            result.message_result = unwrapped_message
        else:
            raise SphinxNoSURBSAvailableError
        return result
