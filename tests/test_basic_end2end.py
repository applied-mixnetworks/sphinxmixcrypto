
import unittest

from sphinxmixcrypto.params import SphinxParams, GroupECC, Chacha_Lioness, Chacha20_stream_cipher, Blake2_hash
from sphinxmixcrypto import SphinxNode
from sphinxmixcrypto.node import unpad_body, pad_body
from sphinxmixcrypto.client import SphinxClient, rand_subset, create_forward_message


class TestNodeUtils(unittest.TestCase):
    def test_pad_unpad(self):
        message = b"hello world"
        paded = pad_body(200, message)
        self.failUnlessEqual(len(paded), 200)
        orig = unpad_body(paded)
        self.failUnlessEqual(message, orig)

    def test_prefix_free_decode(self):
        self.r = 5
        self.params = SphinxParams(
            self.r, group_class = GroupECC,
            hash_func = Blake2_hash,
            lioness_class = Chacha_Lioness,
            stream_cipher = Chacha20_stream_cipher,
        )
        node = SphinxNode(self.params)
        s = b""
        message_type, val, rest = node._prefix_free_decode(s)
        self.failUnless(message_type is None)
        self.failUnless(val is None)
        self.failUnless(rest is None)

        s = b"\x00" * 200
        message_type, val, rest = node._prefix_free_decode(s)
        self.failUnless(message_type == "Dspec")
        self.failUnless(val is None)
        self.failUnless(rest == s[1:])

        s = b"\xFF" * 200
        message_type, val, rest = node._prefix_free_decode(s)
        self.failUnless(message_type == "node")
        self.failUnless(val == s[:node.p.k])
        self.failUnless(rest == s[node.p.k:])

        s = b"\x03" + b"\xFF" * 200
        message_type, val, rest = node._prefix_free_decode(s)
        self.failUnless(message_type == "dest")
        self.failUnless(val == s[1:ord(s[0:1])+1])
        self.failUnless(rest == s[ord(s[0:1])+1:])

        s = b"\xFE" + b"\xFF" * 200
        message_type, val, rest = node._prefix_free_decode(s)
        self.failUnless(message_type is None)
        self.failUnless(val is None)
        self.failUnless(rest is None)

        
class TestSphinxECCGroup(unittest.TestCase):

    def setUp(self):
        self.r = 5
        self.params = SphinxParams(
            self.r, group_class = GroupECC,
            hash_func = Blake2_hash,
            lioness_class = Chacha_Lioness,
            stream_cipher = Chacha20_stream_cipher,
        )

        self.node_map = {}
        # Create some nodes
        for i in range(2*self.r):
            node = SphinxNode(self.params)
            self.node_map[node.get_id()] = node

        # Create a client
        self.client = SphinxClient(self.params)
        # Pick a list of nodes to use
        self.route = rand_subset(self.node_map.keys(), self.r)

    def test_end_to_end(self):
        message = b"this is a test"
        header, delta = create_forward_message(self.params, self.route, self.node_map, b"dest", message)
        # Send it to the first node for processing

        def send_to_client(client_id, message_id, delta):
            print("send_to_client")
            return self.params.clients[client_id].process(message_id, delta)

        def send_to_mix(destination, header, payload):
            print("send_to_mix")
            return self.node_map[destination].process(header, payload)

        result = self.node_map[self.route[0]].process(header, delta)
        def mixnet_test_state_machine(result):
            while True:
                #result.print_error()
                self.failIf(result.has_error())
                if result.tuple_next_hop:
                    print("result.tuple_next_hop")
                    result = send_to_mix(result.tuple_next_hop[0], result.tuple_next_hop[1], result.tuple_next_hop[2])
                elif result.tuple_exit_hop:
                    print("Deliver [%s] to [%s]" % (result.tuple_exit_hop[1], result.tuple_exit_hop[0]))
                    break
                elif result.tuple_client_hop:
                    result = send_to_client(*result.tuple_client_hop)
                    self.failIf(result.has_error())
                    print("[%s] received by [%s]" % (result.tuple_message[1], result.tuple_message[0]))
                    break

        mixnet_test_state_machine(result)
        self.failUnlessEqual(self.node_map[self.route[-1]].received[0], message)

        # Create a reply block for the client
        reply_route = rand_subset(self.node_map.keys(), self.r)
        nym = b"cypherpunk"
        nym_tuple = self.client.create_nym(nym, reply_route, self.node_map)
        self.params.nymserver.add_surb(nym, nym_tuple)
        # Send a message to it
        reply_message = b"this is a reply"
        nym_id = b"cypherpunk"

        print("Nymserver received message for [%s]" % nym_id)
        nym_result = self.params.nymserver.process(nym_id, reply_message)

        print("Nymserver received message for [%s]" % nym_id)
        if nym_result.has_error():
            print("No SURBs available for nym [%s]" % nym_id)
        self.failIf(nym_result.has_error())

        mixnet_test_state_machine(nym_result.message_result)
