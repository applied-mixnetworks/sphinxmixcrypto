# -*- coding: utf-8 -*-

import py.test
import attr
from hypothesis import given, assume
from hypothesis.strategies import binary
import zope
import zope.interface

from sphinxmixcrypto import IKeyState, SphinxPacket, SphinxHeader, SphinxBody, sphinx_packet_unwrap
from sphinxmixcrypto import PacketReplayCacheDict, SphinxParams
from sphinxmixcrypto import SphinxBodySizeMismatchError, GroupCurve25519, IncorrectMACError


@zope.interface.implementer(IKeyState)
@attr.s
class SphinxNodeKeyState(object):

    private_key = attr.ib(validator=attr.validators.instance_of(bytes))

    def get_private_key(self):
        return self.private_key

    def get_public_key(self):
        pass

@given(
    binary(),
    binary(),
    binary(),
    binary(max_size=1023),
    binary(),
)
def test_hypothesis_toosmall_body_size(alpha, beta, gamma, delta, private_key):
    sphinx_header = SphinxHeader(alpha, beta, gamma)
    sphinx_body = SphinxBody(delta)
    packet = SphinxPacket(sphinx_header, sphinx_body)
    params = SphinxParams(max_hops=5, payload_size=1024)
    replay_cache = PacketReplayCacheDict()
    key_state = SphinxNodeKeyState(private_key=private_key)
    py.test.raises(SphinxBodySizeMismatchError, sphinx_packet_unwrap, params, replay_cache, key_state, packet)

@given(
    binary(),
    binary(),
    binary(),
    binary(min_size=1025),
    binary(),
)
def test_hypothesis_toobig_body_size(alpha, beta, gamma, delta, private_key):
    sphinx_header = SphinxHeader(alpha, beta, gamma)
    sphinx_body = SphinxBody(delta)
    packet = SphinxPacket(sphinx_header, sphinx_body)
    params = SphinxParams(max_hops=5, payload_size=1024)
    replay_cache = PacketReplayCacheDict()
    key_state = SphinxNodeKeyState(private_key=private_key)
    py.test.raises(SphinxBodySizeMismatchError, sphinx_packet_unwrap, params, replay_cache, key_state, packet)


@given(
    binary(min_size=32, max_size=32),
    binary(min_size=176),
    binary(min_size=16),
    binary(min_size=1024, max_size=1024),
    binary(min_size=32, max_size=32),
)
def test_hypothesis_scalarmult_error(alpha, beta, gamma, delta, private_key):
    sphinx_header = SphinxHeader(alpha, beta, gamma)
    sphinx_body = SphinxBody(delta)
    packet = SphinxPacket(sphinx_header, sphinx_body)
    params = SphinxParams(max_hops=5, payload_size=1024)
    replay_cache = PacketReplayCacheDict()
    key_state = SphinxNodeKeyState(private_key=private_key)
    def assumptions_wrap():
        try:
            _ = sphinx_packet_unwrap(params, replay_cache, key_state, packet)
            raise Exception("wtf")
        except IncorrectMACError, _:
            assume(False)
        except AssertionError, _:
            return

    assumptions_wrap()


@given(
    binary(min_size=32, max_size=32),
    binary(min_size=176),
    binary(min_size=16),
    binary(min_size=1024, max_size=1024),
    binary(min_size=32, max_size=32),
)
def no_test_hypothesis_incorrect_mac(alpha, beta, gamma, delta, private_key):
    group = GroupCurve25519()
    sphinx_header = SphinxHeader(alpha, beta, gamma)
    sphinx_body = SphinxBody(delta)
    packet = SphinxPacket(sphinx_header, sphinx_body)
    params = SphinxParams(max_hops=5, payload_size=1024)
    replay_cache = PacketReplayCacheDict()
    key_state = SphinxNodeKeyState(private_key=private_key)
    py.test.raises(IncorrectMACError, sphinx_packet_unwrap, params, replay_cache, key_state, packet)
