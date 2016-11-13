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
import binascii
from sphinxmixcrypto.node import destination_encode, DSPEC, pad_body, unpad_body

def rand_subset(lst, nu):
    """
    Return a list of nu random elements of the given list (without
    replacement).
    """
    # Randomize the order of the list by sorting on a random key
    nodeids = [(os.urandom(8),x) for x in lst]
    nodeids.sort(key=lambda x:x[0])
    # Return the first nu elements of the randomized list
    return [x[1] for x in nodeids[:nu]]

def create_header(params, route, node_map, dest, id):
    p = params
    route_len = len(route)
    assert route_len <= p.r
    assert len(id) == p.k
    assert len(dest) <= 2 * (p.r - route_len + 1) * p.k
    group = p.group
    x = group.gensecret()
    # Compute the (alpha, s, b) tuples
    blinds = [x]
    asbtuples = []
    for node in route:
        alpha = group.multiexpon(group.generator, blinds)
        s = group.multiexpon(node_map[node].y, blinds)
        b = p.hb(alpha, s)
        blinds.append(b)
        asbtuples.append({'alpha': alpha, 's': s, 'b': b})
    # Compute the filler strings
    phi = b''
    for i in range(1,route_len):
        min = (2*(p.r-i)+3)*p.k
        phi = p.xor(phi + (b"\x00" * (2*p.k)),
            p.rho(p.hrho(asbtuples[i-1]['s']))[min:])
    # Compute the (beta, gamma) tuples
    beta = dest + id + os.urandom(((2 * (p.r - route_len) + 2)*p.k - len(dest)))
    beta = p.xor(beta,
        p.rho(p.hrho(asbtuples[route_len-1]['s']))[:(2*(p.r-route_len)+3)*p.k]) + phi
    gamma = p.mu(p.hmu(asbtuples[route_len-1]['s']), beta)
    for i in range(route_len-2, -1, -1):
        id = route[i+1]
        assert len(id) == p.k
        beta = p.xor(id + gamma + beta[:(2*p.r-1)*p.k],
            p.rho(p.hrho(asbtuples[i]['s']))[:(2*p.r+1)*p.k])
        gamma = p.mu(p.hmu(asbtuples[i]['s']), beta)
    return (asbtuples[0]['alpha'], beta, gamma), [y['s'] for y in asbtuples]

def create_forward_message(params, route, node_map, dest, msg):
    p = params
    route_len = len(route)
    assert len(dest) < 128 and len(dest) > 0
    assert p.k + 1 + len(dest) + len(msg) < p.m
    # Compute the header and the secrets
    header, secrets = create_header(params, route, node_map, DSPEC, b"\x00" * p.k)
    body = pad_body(p.m, (b"\x00" * p.k) + bytes(destination_encode(dest)) + bytes(msg))
    # Compute the delta values
    delta = p.pi(p.hpi(secrets[route_len-1]), body)
    for i in range(route_len-2, -1, -1):
        delta = p.pi(p.hpi(secrets[i]), delta)
    return header, delta

def create_surb(params, route, node_map, dest):
    p = params
    id = os.urandom(p.k)

    # Compute the header and the secrets
    header, secrets = create_header(params, route, node_map, destination_encode(dest), id)

    ktilde = os.urandom(p.k)
    keytuple = [ktilde]
    keytuple.extend([p.hpi(x) for x in secrets])
    return id, keytuple, (route[0], header, ktilde)


class ClientMessage:
    def __init__(self):
        self.payload = None
        self.error_nym_key_not_found = False
        self.error_corrupt_message = False
    def has_error(self):
        if self.error_nym_key_not_found or self.error_corrupt_message:
            return True
        return False


class SphinxClient:
    def __init__(self, params):
        self.id = b"Client " + bytes(str(binascii.hexlify(os.urandom(4))).encode("utf-8"))
        self.params = params
        params.clients[self.id] = self
        self.keytable = {}

    def create_nym(self, nym, route, node_map):
        """Create a SURB for the given nym (passing through nllength
        nodes), and send it to the nymserver."""

        id, keytuple, nymtuple = create_surb(self.params, route, node_map, self.id)
        self.keytable[id] = keytuple
        return nymtuple

    def process(self, id, delta):
        """
        Process a (still-encrypted) reply message
        """
        message = ClientMessage()
        p = self.params
        keytuple = self.keytable.pop(id, None)

        if keytuple == None:
            message.error_nym_key_not_found = True
            return message

        ktilde = keytuple.pop(0)
        route_len = len(keytuple)
        for i in range(route_len-1, -1, -1):
            delta = p.pi(keytuple[i], delta)
        delta = p.pii(ktilde, delta)

        if delta[:p.k] == (b"\x00" * p.k):
            msg = unpad_body(delta[p.k:])
            message.tuple_message = (self.id, msg)
            return message

        message.error_corrupt_message = True
        return message
