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

"""
This SphinxNode module includes cryptographic algorithms for mix net nodes
"""

import os
import re

# Padding/unpadding of message bodies: a 0 bit, followed by as many 1
# bits as it takes to fill it up

def pad_body(msgtotalsize, body):
    """
    pad_body appends padding to the body of a message.
    Given the total size and the message data a new
    padded message is returned.
    """
    body = body + "\x7f"
    body = body + ("\xff" * (msgtotalsize - len(body)))
    return body

def unpad_body(body):
    """
    unpad_body performs the inverse of pad_body
    """
    return re.compile("\x7f\xff*$").sub('', body)

# Prefix-free encoding/decoding of node names and destinations

# The special destination
DSPEC = "\x00"

# Any other destination.  Must be between 1 and 127 bytes in length
def destination_encode(dest):
    """
    encode destination
    """
    assert len(dest) >= 1 and len(dest) <= 127
    return chr(len(dest)) + dest


class MessageResult:
    def __init__(self):
        self.error_invalid_message_type = False
        self.error_invalid_dspec = False
        self.error_no_such_client = False
        self.error_not_in_alpha_group = False
        self.error_tag_seen_already = False
        self.error_mac_mismatch = False
        self.tuple_next_hop = ()
        self.tuple_exit_hop = ()
        self.tuple_client_hop = ()

    def has_error(self):
        for err in filter(lambda x: x.startswith('error'), dir(self)):
            if getattr(self, err):
                #raise Exception("err %s is %s" % (err, getattr(self, err)))
                print "err %s is %s" % (err, getattr(self, err))
                return True
        return False

class SphinxNode:
    def __init__(self, params):
        self.received = []
        self.p = params
        group = self.p.group
        self.__x = group.gensecret()
        self.y = group.expon(group.g, self.__x)
        idnum = os.urandom(4)
        self.id = self.__Nenc(idnum)
        self.name = "Node " + idnum.encode("hex")
        self.seen = {}
        params.pki[self.id] = self

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


    def process(self, header, payload):
        """
        process returns a MessageResult given a header and payload
        """
        result = MessageResult()
        p = self.p
        pki = p.pki
        group = p.group
        alpha, beta, gamma = header

        if not group.in_group(alpha):
            result.error_not_in_alpha_group = True
            return result
        s = group.expon(alpha, self.__x)
        tag = p.htau(s)

        if tag in self.seen:
            result.error_tag_seen_already = True
            return result
        if gamma != p.mu(p.hmu(s), beta):
            result.error_mac_mismatch = True
            return result

        self.seen[tag] = 1
        B = p.xor(beta + ("\x00" * (2 * p.k)), p.rho(p.hrho(s)))
        type, val, rest = self.__PFdecode(B)

        if type == "node":
            b = p.hb(alpha, s)
            alpha = group.expon(alpha, b)
            gamma = B[p.k:p.k*2]
            beta = B[p.k*2:]
            payload = p.pii(p.hpi(s), payload)
            result.tuple_next_hop = (val, (alpha, beta, gamma), payload)
            return result
        elif type == "Dspec":
            payload = p.pii(p.hpi(s), payload)
            if payload[:p.k] == ("\x00" * p.k):
                type, val, rest = self.__PFdecode(payload[p.k:])
                if type == "dest":
                    # We're to deliver rest (unpadded) to val
                    body = unpad_body(rest)
                    self.received.append(body)
                    result.tuple_exit_hop = (val, body)
                    return result
            result.error_invalid_dspec = True
            return result
        elif type == "dest":
            id = rest[:p.k]
            payload = p.pii(p.hpi(s), payload)
            if val in p.clients:
                result.tuple_client_hop = (val, id, payload)
                return result
            else:
                result.error_no_such_client = True
                return result

        result.error_invalid_message_type = True
        return result
