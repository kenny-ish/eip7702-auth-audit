#!/usr/bin/env python3
"""Audit EIP-7702 authorization tuples in a signed transaction."""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from typing import Any, Callable

# secp256k1 parameters
FIELD_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
CURVE_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
CURVE_G = (
    55066263022277343669578718895168534326250603453777594175500187360389116729240,
    32670510020758816978083085130507043184471273380659243275938904335757337482424,
)
Point = tuple[int, int] | None

# Keccak-f[1600], with the Ethereum Keccak padding (not hashlib.sha3_256).
_MASK64 = (1 << 64) - 1
_ROT = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)
_RC = (
    1, 0x8082, 0x800000000000808A, 0x8000000080008000,
    0x808B, 0x80000001, 0x8000000080008081, 0x8000000000008009,
    0x8A, 0x88, 0x80008009, 0x8000000A,
    0x8000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x80000001, 0x8000000080008008,
)


def _rol64(value: int, shift: int) -> int:
    if shift == 0:
        return value & _MASK64
    return ((value << shift) | (value >> (64 - shift))) & _MASK64


def _keccak_f(state: list[int]) -> None:
    for rc in _RC:
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        rotated = [0] * 25
        for x in range(5):
            for y in range(5):
                rotated[y + 5 * ((2 * x + 3 * y) % 5)] = _rol64(state[x + 5 * y], _ROT[x][y])
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = rotated[x + 5 * y] ^ ((~rotated[(x + 1) % 5 + 5 * y]) & rotated[(x + 2) % 5 + 5 * y])
                state[x + 5 * y] &= _MASK64
        state[0] ^= rc


def keccak256(data: bytes) -> bytes:
    rate = 136
    # Multi-rate padding 0x01 ... 0x80. When the message ends one byte short of
    # a block boundary the two markers share a single byte (0x81).
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != 0:
        padded.append(0)
    padded[-1] |= 0x80
    state = [0] * 25
    for offset in range(0, len(padded), rate):
        block = padded[offset:offset + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[i * 8:i * 8 + 8], "little")
        _keccak_f(state)
    out = bytearray()
    while len(out) < 32:
        for i in range(rate // 8):
            out.extend(state[i].to_bytes(8, "little"))
        if len(out) >= 32:
            break
        _keccak_f(state)
    return bytes(out[:32])


def _point_add(p: Point, q: Point) -> Point:
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2:
        if (y1 + y2) % FIELD_P == 0:
            return None
        slope = (3 * x1 * x1) * pow(2 * y1, -1, FIELD_P) % FIELD_P
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, FIELD_P) % FIELD_P
    x3 = (slope * slope - x1 - x2) % FIELD_P
    return x3, (slope * (x1 - x3) - y1) % FIELD_P


def _point_mul(k: int, point: Point = CURVE_G) -> Point:
    result: Point = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def recover_address(digest: bytes, r: int, s: int, y_parity: int) -> str:
    """Recover an Ethereum address from a typed transaction signature."""
    if len(digest) != 32 or not (1 <= r < CURVE_N) or not (1 <= s < CURVE_N):
        raise ValueError("invalid ECDSA signature scalar")
    if y_parity not in (0, 1):
        raise ValueError("typed transaction parity must be 0 or 1")
    z = int.from_bytes(digest, "big")
    for j in (0, 1):
        x = r + j * CURVE_N
        if x >= FIELD_P:
            continue
        alpha = (pow(x, 3, FIELD_P) + 7) % FIELD_P
        beta = pow(alpha, (FIELD_P + 1) // 4, FIELD_P)
        if (beta * beta - alpha) % FIELD_P:
            continue
        y = beta if beta % 2 == y_parity else FIELD_P - beta
        point_r = (x, y)
        if _point_mul(CURVE_N, point_r) is not None:
            continue
        r_inv = pow(r, -1, CURVE_N)
        public_key = _point_mul((s * r_inv) % CURVE_N, point_r)
        public_key = _point_add(public_key, _point_mul((-z * r_inv) % CURVE_N))
        if public_key is None:
            continue
        raw_key = public_key[0].to_bytes(32, "big") + public_key[1].to_bytes(32, "big")
        return "0x" + keccak256(raw_key)[-20:].hex()
    raise ValueError("could not recover a secp256k1 public key")


def rlp_encode(item: bytes | list[Any]) -> bytes:
    if isinstance(item, bytes):
        if len(item) == 1 and item[0] < 0x80:
            return item
        if len(item) <= 55:
            return bytes([0x80 + len(item)]) + item
        length = len(item).to_bytes((len(item).bit_length() + 7) // 8, "big")
        return bytes([0xB7 + len(length)]) + length + item
    encoded = b"".join(rlp_encode(part) for part in item)
    if len(encoded) <= 55:
        return bytes([0xC0 + len(encoded)]) + encoded
    length = len(encoded).to_bytes((len(encoded).bit_length() + 7) // 8, "big")
    return bytes([0xF7 + len(length)]) + length + encoded


def rlp_decode(data: bytes) -> bytes | list[Any]:
    def read(pos: int) -> tuple[bytes | list[Any], int]:
        if pos >= len(data):
            raise ValueError("truncated RLP")
        prefix = data[pos]
        if prefix <= 0x7F:
            return bytes([prefix]), pos + 1
        if prefix <= 0xB7:
            length = prefix - 0x80
            end = pos + 1 + length
            if end > len(data):
                raise ValueError("truncated RLP string")
            return data[pos + 1:end], end
        if prefix <= 0xBF:
            length_len = prefix - 0xB7
            start = pos + 1
            end_len = start + length_len
            if end_len > len(data):
                raise ValueError("truncated RLP length")
            length = int.from_bytes(data[start:end_len], "big")
            end = end_len + length
            if end > len(data):
                raise ValueError("truncated long RLP string")
            return data[end_len:end], end
        if prefix <= 0xF7:
            length = prefix - 0xC0
            end = pos + 1 + length
            if end > len(data):
                raise ValueError("truncated RLP list")
            items: list[Any] = []
            cursor = pos + 1
            while cursor < end:
                value, cursor = read(cursor)
                items.append(value)
            if cursor != end:
                raise ValueError("invalid RLP list length")
            return items, end
        length_len = prefix - 0xF7
        start = pos + 1
        end_len = start + length_len
        if end_len > len(data):
            raise ValueError("truncated long RLP length")
        length = int.from_bytes(data[start:end_len], "big")
        end = end_len + length
        if end > len(data):
            raise ValueError("truncated long RLP list")
        items = []
        cursor = end_len
        while cursor < end:
            value, cursor = read(cursor)
            items.append(value)
        if cursor != end:
            raise ValueError("invalid long RLP list length")
        return items, end

    result, end = read(0)
    if end != len(data):
        raise ValueError("trailing bytes after RLP")
    return result


def _as_uint(value: bytes, name: str) -> int:
    if value != value.lstrip(b"\x00") and value:
        # Non-canonical integer encodings are rejected by typed transaction rules.
        raise ValueError(f"non-canonical integer in {name}")
    return int.from_bytes(value, "big") if value else 0


def _hex(data: bytes) -> str:
    return "0x" + data.hex()


def _address(data: bytes) -> str:
    if len(data) != 20:
        raise ValueError("address must be 20 bytes")
    return _hex(data)


def _parse_access_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError("access list must be an RLP list")
    result = []
    for entry in value:
        if not isinstance(entry, list) or len(entry) != 2:
            raise ValueError("invalid access-list entry")
        address, storage = entry
        if not isinstance(address, bytes) or len(address) != 20 or not isinstance(storage, list):
            raise ValueError("invalid access-list entry fields")
        keys = []
        for key in storage:
            if not isinstance(key, bytes) or len(key) != 32:
                raise ValueError("storage key must be 32 bytes")
            keys.append(_hex(key))
        result.append({"address": _address(address), "storage_keys": keys})
    return result


def parse_eip7702(raw: str) -> dict[str, Any]:
    if not re.fullmatch(r"0x[0-9a-fA-F]+", raw or ""):
        raise ValueError("raw transaction must be 0x-prefixed hex")
    encoded = bytes.fromhex(raw[2:])
    if not encoded or encoded[0] != 0x04:
        raise ValueError("expected an EIP-7702 type-4 transaction")
    decoded = rlp_decode(encoded[1:])
    if not isinstance(decoded, list) or len(decoded) != 13:
        raise ValueError("type-4 transaction must contain 13 fields")
    if any(not isinstance(x, (bytes, list)) for x in decoded):
        raise ValueError("invalid type-4 field")
    chain_id = _as_uint(decoded[0], "chain_id")
    nonce = _as_uint(decoded[1], "nonce")
    max_priority = _as_uint(decoded[2], "max_priority_fee_per_gas")
    max_fee = _as_uint(decoded[3], "max_fee_per_gas")
    gas_limit = _as_uint(decoded[4], "gas_limit")
    to = decoded[5]
    if not isinstance(to, bytes) or len(to) not in (0, 20):
        raise ValueError("to must be empty or 20 bytes")
    value = _as_uint(decoded[6], "value")
    data = decoded[7]
    if not isinstance(data, bytes):
        raise ValueError("data must be bytes")
    access_list = _parse_access_list(decoded[8])
    auths_raw = decoded[9]
    if not isinstance(auths_raw, list):
        raise ValueError("authorization list must be a list")
    auths = []
    for auth in auths_raw:
        if not isinstance(auth, list) or len(auth) != 6:
            raise ValueError("authorization tuple must contain 6 fields")
        auth_chain = _as_uint(auth[0], "authorization chain_id")
        auth_address = auth[1]
        if not isinstance(auth_address, bytes) or len(auth_address) != 20:
            raise ValueError("authorization address must be 20 bytes")
        auth_nonce = _as_uint(auth[2], "authorization nonce")
        parity = _as_uint(auth[3], "authorization y_parity")
        if parity not in (0, 1):
            raise ValueError("authorization y_parity must be 0 or 1")
        r = _as_uint(auth[4], "authorization r")
        s = _as_uint(auth[5], "authorization s")
        digest = keccak256(b"\x05" + rlp_encode([auth[0], auth[1], auth[2]]))
        authority = recover_address(digest, r, s, parity)
        auths.append({
            "chain_id": auth_chain,
            "address": _address(auth_address),
            "nonce": auth_nonce,
            "y_parity": parity,
            "r": _hex(auth[4]),
            "s": _hex(auth[5]),
            "signing_hash": _hex(digest),
            "authority": authority,
        })
    tx_digest = keccak256(b"\x04" + rlp_encode(decoded[:10]))
    y_parity = _as_uint(decoded[10], "transaction y_parity")
    if y_parity not in (0, 1):
        raise ValueError("transaction y_parity must be 0 or 1")
    r = _as_uint(decoded[11], "transaction r")
    s = _as_uint(decoded[12], "transaction s")
    return {
        "type": 4,
        "chain_id": chain_id,
        "nonce": nonce,
        "max_priority_fee_per_gas": max_priority,
        "max_fee_per_gas": max_fee,
        "gas_limit": gas_limit,
        "to": _address(to) if to else None,
        "value": value,
        "data": _hex(data),
        "access_list": access_list,
        "authorization_list": auths,
        "y_parity": y_parity,
        "r": _hex(decoded[11]),
        "s": _hex(decoded[12]),
        "signing_hash": _hex(tx_digest),
        "tx_hash": _hex(keccak256(encoded)),
        "sender": recover_address(tx_digest, r, s, y_parity),
    }


def rpc_call(url: str, method: str, params: list[Any]) -> Any:
    request = urllib.request.Request(
        url,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "eip7702-auth-audit/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        # Some providers answer with an HTTP error status but still carry a
        # JSON-RPC error object (for example archive-state restrictions).
        detail = exc.read().decode(errors="replace")
        try:
            message = json.loads(detail)["error"]["message"]
        except (ValueError, KeyError, TypeError):
            message = detail.strip()[:200]
        raise RuntimeError(f"{method}: HTTP {exc.code}: {message or exc.reason}") from None
    if body.get("error"):
        raise RuntimeError(f"{method}: {body['error'].get('message', 'JSON-RPC error')}")
    return body.get("result")


def audit_document(raw: str, rpc_url: str | None = None, block_tag: str = "latest", rpc_fn: Callable[..., Any] = rpc_call) -> dict[str, Any]:
    parsed = parse_eip7702(raw)
    if rpc_url is None:
        parsed["live"] = None
        return parsed
    network_chain_id = int(rpc_fn(rpc_url, "eth_chainId", []), 16)
    checks = []
    for auth in parsed["authorization_list"]:
        address = auth["authority"]
        nonce_hex = rpc_fn(rpc_url, "eth_getTransactionCount", [address, block_tag])
        code = rpc_fn(rpc_url, "eth_getCode", [address, block_tag]).lower()
        expected = "0xef0100" + auth["address"][2:]
        checks.append({
            "authority": address,
            "authorization_chain_matches_rpc": auth["chain_id"] in (0, network_chain_id),
            "authorization_nonce": auth["nonce"],
            "rpc_nonce": int(nonce_hex, 16),
            "authorization_nonce_matches_rpc": auth["nonce"] == int(nonce_hex, 16),
            "delegation_target": auth["address"],
            "rpc_code": code,
            "delegation_code_matches": code == expected,
        })
    parsed["live"] = {
        "rpc_chain_id": network_chain_id,
        "tx_chain_matches_rpc": parsed["chain_id"] in (0, network_chain_id),
        "block_tag": block_tag,
        "authorizations": checks,
    }
    return parsed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit an EIP-7702 signed transaction and its authorization tuples.")
    parser.add_argument("--raw", required=True, help="0x-prefixed signed type-4 transaction")
    parser.add_argument("--rpc", help="JSON-RPC URL for chain, nonce, and delegation-code checks")
    parser.add_argument("--block-tag", default="latest", help="eth_getTransactionCount/eth_getCode block tag")
    args = parser.parse_args(argv)
    try:
        result = audit_document(args.raw, args.rpc, args.block_tag)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
