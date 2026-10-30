import io
import unittest
import urllib.error
import urllib.request
from unittest import mock

import eip7702_auth_audit as audit


# Real case 1: Ethereum mainnet (chain 1), block 26161043 (0x18f2f93), tx index 0x76.
# Raw bytes returned by eth_getRawTransactionByHash from ethereum-rpc.publicnode.com.
# The authority re-delegates itself (sender == authority == tx.to).
ETH_RAW = "0x04f9010f01824b6a8303a9808407ff1da4830186a09479555a5519f10d7815c995aae4fbd5a0c9b999c880b8445b5823de00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000c0f85cf85a019498a6f5d46001e10c0a36fc3a14d79752026b2d000580a099bd38dd21faa8476dcff3d48de79af7bc5094f6d570398b1899e7761c2fa5e7a02c09a286965f0a99f9c469e81c48ada1c611a77876f8914ab1f1c009ad68cda301a0315405652ad71c97a77edc17ed7408907b7d0f01663a35e9483ca028a981b4daa034041c91b46003fddd60694a8970ffddf18c410b1c641ab2735476dad3c7f2fb"
ETH_TX_HASH = "0x808b5dec1abcabbd8b7c77f2894298ff52570244182a98d4daca8dbee875c7b8"
ETH_SENDER = "0x000b300b0eb3d6cd66b53aa6fa557a6cd8c6ce99"
ETH_AUTHORITY = "0x79555a5519f10d7815c995aae4fbd5a0c9b999c8"

# Real case 2: Base mainnet (chain 8453), block 52430029 (0x32004cd), tx index 0x3c.
# Raw bytes returned by eth_getRawTransactionByHash from base-rpc.publicnode.com.
# Sponsored authorization: the sender differs from the authority. The signed
# payload is 951 bytes, i.e. exactly one byte short of a Keccak block boundary,
# which exercises the 0x81 padding case.
BASE_RAW = "0x04f903b38221058203b880843b9aca0083043da694639c4aeeb6976c43b69e0cf86bf3b10b777b8da880b902e4cb3fe3e6000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000d4c450ace519d33beaddf24e4c7e197f5d9c9409000000000000000000000000940a319b75861014a220d9c6c144d108552b089b00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000000a45897ef1b0000000000000000000000005cbf5dfaa5336ce0456e24217e7911365100879a000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000240c11dedd000000000000000000000000d4c450ace519d33beaddf24e4c7e197f5d9c940900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044a9059cbb0000000000000000000000009ec36a980dcde1db82453922ad2c5bcfdf6905920000000000000000000000000000000000000000000000000186cc6acd4b000000000000000000000000000000000000000000000000000000000000c0f860f85e82210594ac9a3c7c64e865d3b547aea2aeeb436cfddb7c7b821cee80a021ff67c660f01260e1a255e1bdf1e04efe0c7c741e6ccd93eb0a0ecb4eb7f270a05bda5fe1c31f120cf512bc71f264e143cbe3a8a18c1bf741eff1f52b360354fb01a0d90d040ef2fb7abb12252b695399506fd8bce97c5246a4bfe9b8561f687aecfba04e3da46a4155c7afc6fd9a8396aa38053c5f9cc633cfa821949031f1768da475"
BASE_TX_HASH = "0x300136493848b07d64d0ae67695a879f97d60fe24164c52004b8bb52e21d89cd"
BASE_SENDER = "0x9ec36a980dcde1db82453922ad2c5bcfdf690592"
BASE_AUTHORITY = "0x639c4aeeb6976c43b69e0cf86bf3b10b777b8da8"
BASE_DELEGATE = "0xac9a3c7c64e865d3b547aea2aeeb436cfddb7c7b"


class KeccakTests(unittest.TestCase):
    def test_known_vectors(self):
        self.assertEqual(
            audit.keccak256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )
        self.assertEqual(
            audit.keccak256(b"abc").hex(),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
        )

    def test_padding_at_block_boundary_uses_real_base_transaction(self):
        encoded = bytes.fromhex(BASE_RAW[2:])
        self.assertEqual(len(encoded) % 136, 135)
        self.assertEqual("0x" + audit.keccak256(encoded).hex(), BASE_TX_HASH)

    def test_constant_tables(self):
        self.assertEqual(len(audit._ROT), 5)
        self.assertEqual(sum(len(row) for row in audit._ROT), 25)
        self.assertEqual(len(audit._RC), 24)


class Eip7702AuditTests(unittest.TestCase):
    def test_real_ethereum_mainnet_transaction(self):
        result = audit.parse_eip7702(ETH_RAW)
        self.assertEqual(result["chain_id"], 1)
        self.assertEqual(result["nonce"], 19306)
        self.assertEqual(result["tx_hash"], ETH_TX_HASH)
        self.assertEqual(result["sender"], ETH_SENDER)
        auth = result["authorization_list"][0]
        self.assertEqual(auth["authority"], ETH_AUTHORITY)
        self.assertEqual(auth["chain_id"], 1)
        self.assertEqual(auth["nonce"], 5)
        self.assertEqual(auth["address"], "0x98a6f5d46001e10c0a36fc3a14d79752026b2d00")

    def test_real_base_sponsored_transaction(self):
        result = audit.parse_eip7702(BASE_RAW)
        self.assertEqual(result["chain_id"], 8453)
        self.assertEqual(result["nonce"], 952)
        self.assertEqual(result["tx_hash"], BASE_TX_HASH)
        self.assertEqual(result["sender"], BASE_SENDER)
        self.assertEqual(result["to"], BASE_AUTHORITY)
        auth = result["authorization_list"][0]
        self.assertEqual(auth["authority"], BASE_AUTHORITY)
        self.assertNotEqual(auth["authority"], result["sender"])
        self.assertEqual(auth["chain_id"], 8453)
        self.assertEqual(auth["nonce"], 7406)
        self.assertEqual(auth["address"], BASE_DELEGATE)

    def test_rpc_checks_are_injected_without_network(self):
        # Values observed on Ethereum mainnet at block 0x18f2f93 (post-inclusion).
        calls = []

        def fake_rpc(_url, method, params):
            calls.append((method, params))
            if method == "eth_chainId":
                return "0x1"
            if method == "eth_getTransactionCount":
                return "0x6"
            if method == "eth_getCode":
                return "0xef010098a6f5d46001e10c0a36fc3a14d79752026b2d00"
            raise AssertionError(method)

        result = audit.audit_document(ETH_RAW, "https://rpc.invalid", block_tag="0x18f2f93", rpc_fn=fake_rpc)
        live = result["live"]
        self.assertTrue(live["tx_chain_matches_rpc"])
        check = live["authorizations"][0]
        self.assertEqual(check["rpc_nonce"], 6)
        self.assertFalse(check["authorization_nonce_matches_rpc"])
        self.assertTrue(check["delegation_code_matches"])
        self.assertEqual(calls[0][0], "eth_chainId")
        self.assertEqual(calls[1], ("eth_getTransactionCount", [ETH_AUTHORITY, "0x18f2f93"]))

    def test_pre_state_check_uses_parent_block_values(self):
        # Values observed on Base mainnet at block 0x32004cc (parent of inclusion).
        def fake_rpc(_url, method, params):
            if method == "eth_chainId":
                return "0x2105"
            if method == "eth_getTransactionCount":
                return "0x1cee"
            if method == "eth_getCode":
                return "0xef0100b886419d18f11b9da33925b166cac3b4b6a671c1"
            raise AssertionError(method)

        result = audit.audit_document(BASE_RAW, "https://rpc.invalid", block_tag="0x32004cc", rpc_fn=fake_rpc)
        check = result["live"]["authorizations"][0]
        self.assertTrue(check["authorization_nonce_matches_rpc"])
        self.assertFalse(check["delegation_code_matches"])

    def test_http_error_body_is_surfaced(self):
        body = b'{"jsonrpc":"2.0","error":{"code":-32602,"message":"Archive requests require a personal token"},"id":1}'

        def fake_urlopen(request, timeout=0):
            self.assertEqual(request.get_header("User-agent"), "eip7702-auth-audit/1.0")
            raise urllib.error.HTTPError(request.full_url, 403, "Forbidden", {}, io.BytesIO(body))

        with mock.patch.object(urllib.request, "urlopen", fake_urlopen):
            with self.assertRaisesRegex(RuntimeError, "HTTP 403: Archive requests"):
                audit.rpc_call("https://rpc.invalid", "eth_getCode", ["0x" + "00" * 20, "0x1"])

    def test_rejects_non_type4_and_truncated_rlp(self):
        with self.assertRaises(ValueError):
            audit.parse_eip7702("0x02c0")
        with self.assertRaises(ValueError):
            audit.parse_eip7702("0x04f8")

    def test_rlp_round_trip_for_nested_values(self):
        value = [b"cat", [b"", b"dog"], b"\x80"]
        self.assertEqual(audit.rlp_decode(audit.rlp_encode(value)), value)


if __name__ == "__main__":
    unittest.main()
