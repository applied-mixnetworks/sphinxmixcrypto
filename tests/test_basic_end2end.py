
import unittest

from sphinxmixcrypto.params import SphinxParams, GroupECC, Chacha_Lioness, Chacha20_stream_cipher, Blake2_hash, Blake2_hash_mac
from sphinxmixcrypto import SphinxNode
from sphinxmixcrypto.node import unpad_body, pad_body, ReplayError, BlockSizeMismatchError
from sphinxmixcrypto.client import SphinxClient, rand_subset, create_forward_message


class TestSphinxCorrectness(unittest.TestCase):

    def newTestRoute(self, numHops):
        self.r = numHops
        self.params = SphinxParams(
            self.r, group_class = GroupECC,
            hash_func = Blake2_hash,
            hash_mac_func = Blake2_hash_mac,
            lioness_class = Chacha_Lioness,
            stream_cipher = Chacha20_stream_cipher,
        )
        self.node_map = {}
        self.consensus = {}
        for i in range(numHops):
            node = SphinxNode(self.params)
            self.node_map[node.get_id()] = node
            self.consensus[node.get_id()] = node.public_key
        route = rand_subset(self.node_map.keys(), self.r)
        return route

    def test_sphinx_single_hop(self):
        route = self.newTestRoute(1)
        destination = b"dest"
        message = b"this is a test"
        alpha, beta, gamma, delta = create_forward_message(self.params, route, self.consensus, destination, message)
        header = alpha, beta, gamma
        payload = delta
        print("after create forward message")
        result = self.node_map[route[0]].unwrap(header, payload)
        self.failIf(len(result.tuple_exit_hop) == 0)
        self.failIf(len(result.tuple_next_hop) != 0)
        self.failIf(len(result.tuple_client_hop) != 0)
        received_dest, received_message = result.tuple_exit_hop
        self.failUnless(received_dest, destination)
        self.failUnless(received_message, message)

    def test_sphinx_replay(self):
        route = self.newTestRoute(5)
        destination = b"dest"
        message = b"this is a test"
        alpha, beta, gamma, delta = create_forward_message(self.params, route, self.consensus, destination, message)
        header = alpha, beta, gamma
        payload = delta
        result = self.node_map[route[0]].unwrap(header, payload)
        with self.assertRaises(ReplayError):
            result = self.node_map[route[0]].unwrap(header, payload)

    def test_sphinx_assoc_data(self):
        route = self.newTestRoute(5)
        destination = b"dest"
        message = b"this is a test"
        alpha, beta, gamma, delta = create_forward_message(self.params, route, self.consensus, destination, message)
        header = alpha, beta, gamma
        payload = delta
        with self.assertRaises(BlockSizeMismatchError):
            result = self.node_map[route[0]].unwrap(header, b"somethingelse!!!!!!!!!!!!!!")

class TestSphinxECCGroup(unittest.TestCase):

    def setUp(self):
        self.r = 5
        self.params = SphinxParams(
            self.r, group_class = GroupECC,
            hash_func = Blake2_hash,
            hash_mac_func = Blake2_hash_mac,
            lioness_class = Chacha_Lioness,
            stream_cipher = Chacha20_stream_cipher,
        )

        self.node_map = {}
        self.consensus = {}
        # Create some nodes
        for i in range(2*self.r):
            node = SphinxNode(self.params)
            self.node_map[node.get_id()] = node
            self.consensus[node.get_id()] = node.public_key

        # Create a client
        self.client = SphinxClient(self.params)
        # Pick a list of nodes to use
        self.route = rand_subset(self.node_map.keys(), self.r)

    def test_end_to_end(self):
        message = b"this is a test"
        alpha, beta, gamma, delta = create_forward_message(self.params, self.route, self.consensus, self.route[-1], message)
        header = alpha, beta, gamma
        payload = delta

        def send_to_client(client_id, message_id, delta):
            print("send_to_client")
            return self.params.clients[client_id].decrypt(message_id, delta)

        def send_to_mix(destination, header, payload):
            print("send_to_mix")
            return self.node_map[destination].unwrap(header, payload)

        # Send it to the first node for processing
        result = self.node_map[self.route[0]].unwrap(header, delta)
        def mixnet_test_state_machine(result):
            while True:
                if result.tuple_next_hop:
                    print("result.tuple_next_hop")
                    result = send_to_mix(result.tuple_next_hop[0], result.tuple_next_hop[1], result.tuple_next_hop[2])
                elif result.tuple_exit_hop:
                    print("Deliver [%s] to [%s]" % (result.tuple_exit_hop[1], result.tuple_exit_hop[0]))
                    break
                elif result.tuple_client_hop:
                    result = send_to_client(*result.tuple_client_hop)
                    print("[%s] received by [%s]" % (result.tuple_message[1], result.tuple_message[0]))
                    break

        mixnet_test_state_machine(result)
        self.failUnlessEqual(self.node_map[self.route[-1]].received[0], message)

        # Create a reply block for the client
        reply_route = rand_subset(self.node_map.keys(), self.r)
        nym = b"cypherpunk"
        nym_tuple = self.client.create_nym(nym, reply_route, self.consensus)
        self.params.nymserver.add_surb(nym, nym_tuple)
        # Send a message to it
        reply_message = b"this is a reply"
        nym_id = b"cypherpunk"

        print("Nymserver received message for [%s]" % nym_id)
        nym_result = self.params.nymserver.process(nym_id, reply_message)

        print("Nymserver received message for [%s]" % nym_id)
        mixnet_test_state_machine(nym_result.message_result)
