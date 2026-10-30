# eip7702-auth-audit

This small command-line tool checks an EIP-7702 type-4 transaction before broadcast. It decodes the authorization list, recovers the authority and transaction sender from secp256k1 signatures, and can compare each authorization with the chain ID, account nonce, and delegation designator returned by a JSON-RPC node.

## Examples

Both examples are real transactions. The raw bytes come from `eth_getRawTransactionByHash`, and the live checks were run against public JSON-RPC endpoints at the parent block of the inclusion block (pre-state) and at the inclusion block itself (post-state). Outputs are pasted unchanged.

### Example 1: Ethereum mainnet, self re-delegation

Transaction `0x808b5dec1abcabbd8b7c77f2894298ff52570244182a98d4daca8dbee875c7b8`, included in block `26161043` (`0x18f2f93`, block hash `0x02de8142c8eefde34b6820f2ae05a6b833440ba4da417d084c46f0207ca52ac6`). The sender, the `to` address and the authority are the same account, and the authority already carried a different delegation before this transaction.

```text
$ python eip7702_auth_audit.py --rpc https://eth.drpc.org --block-tag 0x18f2f92 --raw 0x04f9010f01824b6a8303a9808407ff1da4830186a09479555a5519f10d7815c995aae4fbd5a0c9b999c880b8445b5823de00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000c0f85cf85a019498a6f5d46001e10c0a36fc3a14d79752026b2d000580a099bd38dd21faa8476dcff3d48de79af7bc5094f6d570398b1899e7761c2fa5e7a02c09a286965f0a99f9c469e81c48ada1c611a77876f8914ab1f1c009ad68cda301a0315405652ad71c97a77edc17ed7408907b7d0f01663a35e9483ca028a981b4daa034041c91b46003fddd60694a8970ffddf18c410b1c641ab2735476dad3c7f2fb
{
  "access_list": [],
  "authorization_list": [
    {
      "address": "0x98a6f5d46001e10c0a36fc3a14d79752026b2d00",
      "authority": "0x79555a5519f10d7815c995aae4fbd5a0c9b999c8",
      "chain_id": 1,
      "nonce": 5,
      "r": "0x99bd38dd21faa8476dcff3d48de79af7bc5094f6d570398b1899e7761c2fa5e7",
      "s": "0x2c09a286965f0a99f9c469e81c48ada1c611a77876f8914ab1f1c009ad68cda3",
      "signing_hash": "0x1e7aa0accc77582ea7f11cb8527ba19433c32c969e0f21c2cd7f3d29dced90d3",
      "y_parity": 0
    }
  ],
  "chain_id": 1,
  "data": "0x5b5823de00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000",
  "gas_limit": 100000,
  "live": {
    "authorizations": [
      {
        "authority": "0x79555a5519f10d7815c995aae4fbd5a0c9b999c8",
        "authorization_chain_matches_rpc": true,
        "authorization_nonce": 5,
        "authorization_nonce_matches_rpc": true,
        "delegation_code_matches": false,
        "delegation_target": "0x98a6f5d46001e10c0a36fc3a14d79752026b2d00",
        "rpc_code": "0xef0100554f172451c282b88ddc1828f5f990f4a7519d06",
        "rpc_nonce": 5
      }
    ],
    "block_tag": "0x18f2f92",
    "rpc_chain_id": 1,
    "tx_chain_matches_rpc": true
  },
  "max_fee_per_gas": 134159780,
  "max_priority_fee_per_gas": 240000,
  "nonce": 19306,
  "r": "0x315405652ad71c97a77edc17ed7408907b7d0f01663a35e9483ca028a981b4da",
  "s": "0x34041c91b46003fddd60694a8970ffddf18c410b1c641ab2735476dad3c7f2fb",
  "sender": "0x000b300b0eb3d6cd66b53aa6fa557a6cd8c6ce99",
  "signing_hash": "0x4ab746eef0a501f5780ca30d219d96e2a240cbb5401925bb4f3fe2a53cd0574c",
  "to": "0x79555a5519f10d7815c995aae4fbd5a0c9b999c8",
  "tx_hash": "0x808b5dec1abcabbd8b7c77f2894298ff52570244182a98d4daca8dbee875c7b8",
  "type": 4,
  "value": 0,
  "y_parity": 1
}
```

At the parent block the authorization nonce `5` matches the account nonce and the existing delegation points elsewhere (`0x554f...`). Re-running with `--block-tag 0x18f2f93` (the inclusion block) shows the post-state: the nonce moved to `6` and the delegation designator now equals `0xef0100` + the authorized address.

```text
$ python eip7702_auth_audit.py --rpc https://eth.drpc.org --block-tag 0x18f2f93 --raw 0x04f9010f...  # same raw as above; "live" section only
{
  "authorizations": [
    {
      "authority": "0x79555a5519f10d7815c995aae4fbd5a0c9b999c8",
      "authorization_chain_matches_rpc": true,
      "authorization_nonce": 5,
      "authorization_nonce_matches_rpc": false,
      "delegation_code_matches": true,
      "delegation_target": "0x98a6f5d46001e10c0a36fc3a14d79752026b2d00",
      "rpc_code": "0xef010098a6f5d46001e10c0a36fc3a14d79752026b2d00",
      "rpc_nonce": 6
    }
  ],
  "block_tag": "0x18f2f93",
  "rpc_chain_id": 1,
  "tx_chain_matches_rpc": true
}
```

### Example 2: Base mainnet, sponsored authorization

Transaction `0x300136493848b07d64d0ae67695a879f97d60fe24164c52004b8bb52e21d89cd`, included in Base block `52430029` (`0x32004cd`, block hash `0xa5fd1d25214646f6b420d7d4f616cc1e310bbe76984e37e06fde80f183c2baf6`). The transaction sender (`0x9ec3...`) is not the authority (`0x639c...`), i.e. the authorization is relayed by a third party. The signed payload is 951 bytes, one byte short of a Keccak block boundary.

```text
$ python eip7702_auth_audit.py --rpc https://mainnet.base.org --block-tag 0x32004cc --raw 0x04f903b38221058203b880843b9aca0083043da694639c4aeeb6976c43b69e0cf86bf3b10b777b8da880b902e4cb3fe3e6000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000d4c450ace519d33beaddf24e4c7e197f5d9c9409000000000000000000000000940a319b75861014a220d9c6c144d108552b089b00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000000a45897ef1b0000000000000000000000005cbf5dfaa5336ce0456e24217e7911365100879a000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000240c11dedd000000000000000000000000d4c450ace519d33beaddf24e4c7e197f5d9c940900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044a9059cbb0000000000000000000000009ec36a980dcde1db82453922ad2c5bcfdf6905920000000000000000000000000000000000000000000000000186cc6acd4b000000000000000000000000000000000000000000000000000000000000c0f860f85e82210594ac9a3c7c64e865d3b547aea2aeeb436cfddb7c7b821cee80a021ff67c660f01260e1a255e1bdf1e04efe0c7c741e6ccd93eb0a0ecb4eb7f270a05bda5fe1c31f120cf512bc71f264e143cbe3a8a18c1bf741eff1f52b360354fb01a0d90d040ef2fb7abb12252b695399506fd8bce97c5246a4bfe9b8561f687aecfba04e3da46a4155c7afc6fd9a8396aa38053c5f9cc633cfa821949031f1768da475
{
  "access_list": [],
  "authorization_list": [
    {
      "address": "0xac9a3c7c64e865d3b547aea2aeeb436cfddb7c7b",
      "authority": "0x639c4aeeb6976c43b69e0cf86bf3b10b777b8da8",
      "chain_id": 8453,
      "nonce": 7406,
      "r": "0x21ff67c660f01260e1a255e1bdf1e04efe0c7c741e6ccd93eb0a0ecb4eb7f270",
      "s": "0x5bda5fe1c31f120cf512bc71f264e143cbe3a8a18c1bf741eff1f52b360354fb",
      "signing_hash": "0xc9af98be449eeb5881560c1ef0d8d72a79c3083e751f1260b5836cdc254f32e8",
      "y_parity": 0
    }
  ],
  "chain_id": 8453,
  "data": "0xcb3fe3e6000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000d4c450ace519d33beaddf24e4c7e197f5d9c9409000000000000000000000000940a319b75861014a220d9c6c144d108552b089b00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000000a45897ef1b0000000000000000000000005cbf5dfaa5336ce0456e24217e7911365100879a000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000240c11dedd000000000000000000000000d4c450ace519d33beaddf24e4c7e197f5d9c940900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044a9059cbb0000000000000000000000009ec36a980dcde1db82453922ad2c5bcfdf6905920000000000000000000000000000000000000000000000000186cc6acd4b000000000000000000000000000000000000000000000000000000000000",
  "gas_limit": 277926,
  "live": {
    "authorizations": [
      {
        "authority": "0x639c4aeeb6976c43b69e0cf86bf3b10b777b8da8",
        "authorization_chain_matches_rpc": true,
        "authorization_nonce": 7406,
        "authorization_nonce_matches_rpc": true,
        "delegation_code_matches": false,
        "delegation_target": "0xac9a3c7c64e865d3b547aea2aeeb436cfddb7c7b",
        "rpc_code": "0xef0100b886419d18f11b9da33925b166cac3b4b6a671c1",
        "rpc_nonce": 7406
      }
    ],
    "block_tag": "0x32004cc",
    "rpc_chain_id": 8453,
    "tx_chain_matches_rpc": true
  },
  "max_fee_per_gas": 1000000000,
  "max_priority_fee_per_gas": 0,
  "nonce": 952,
  "r": "0xd90d040ef2fb7abb12252b695399506fd8bce97c5246a4bfe9b8561f687aecfb",
  "s": "0x4e3da46a4155c7afc6fd9a8396aa38053c5f9cc633cfa821949031f1768da475",
  "sender": "0x9ec36a980dcde1db82453922ad2c5bcfdf690592",
  "signing_hash": "0x0066bf06ec90d7cb5444499358389cae133ab5a10227b50a7243d7522151dc60",
  "to": "0x639c4aeeb6976c43b69e0cf86bf3b10b777b8da8",
  "tx_hash": "0x300136493848b07d64d0ae67695a879f97d60fe24164c52004b8bb52e21d89cd",
  "type": 4,
  "value": 0,
  "y_parity": 1
}
```

Post-state at the inclusion block (`--block-tag 0x32004cd`), `live` section only:

```text
{
  "authorizations": [
    {
      "authority": "0x639c4aeeb6976c43b69e0cf86bf3b10b777b8da8",
      "authorization_chain_matches_rpc": true,
      "authorization_nonce": 7406,
      "authorization_nonce_matches_rpc": false,
      "delegation_code_matches": true,
      "delegation_target": "0xac9a3c7c64e865d3b547aea2aeeb436cfddb7c7b",
      "rpc_code": "0xef0100ac9a3c7c64e865d3b547aea2aeeb436cfddb7c7b",
      "rpc_nonce": 7407
    }
  ],
  "block_tag": "0x32004cd",
  "rpc_chain_id": 8453,
  "tx_chain_matches_rpc": true
}
```

## Usage

```text
python eip7702_auth_audit.py --raw 0xSIGNED_TYPE4_TRANSACTION
python eip7702_auth_audit.py --raw 0xSIGNED_TYPE4_TRANSACTION --rpc RPC_URL
python eip7702_auth_audit.py --raw 0xSIGNED_TYPE4_TRANSACTION --rpc RPC_URL --block-tag latest
```

`--raw` is a signed EIP-7702 transaction. `--rpc` enables `eth_chainId`, `eth_getTransactionCount`, and `eth_getCode` checks. `--block-tag` is passed to the account-state calls and defaults to `latest`. Use the parent block tag when checking the pre-state of an already included transaction; historical tags need an archive-capable endpoint (for example `https://ethereum-rpc.publicnode.com` rejects them with `Archive requests require a personal token`, which the tool reports verbatim). The tool does not send transactions.

## How it works

The transaction payload is RLP-decoded after the type byte `0x04`. The transaction sender is recovered from `keccak256(0x04 || rlp(unsigned type-4 fields))`. Each authorization is checked with `keccak256(0x05 || rlp(chain_id, address, nonce))`. The implementation includes Ethereum Keccak-256, RLP, secp256k1 point arithmetic, and JSON-RPC calls using only the Python standard library. Every HTTP request carries a `User-Agent` header.

## Tests

```text
python -m unittest -v
```

The fixtures are the two transactions above; expected values (hash, sender, authority, nonces, delegation codes) were taken from the chain, not computed by the tool.
