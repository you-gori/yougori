"""Address, token and transaction id checks for the payment networks. Standard library only.

Nothing here contacts a network: it checks that what the admin or a buyer typed has the shape
and checksum of a real address on the chosen network, so a typo is caught before anyone sends
money to it. It cannot tell whether an address belongs to the person who typed it.
"""
import hashlib
import re

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
INDEX = {character: value for value, character in enumerate(ALPHABET)}

# ---- Keccak-256, as Ethereum uses it (not the padded SHA3-256 in hashlib) ----

_ROUNDS = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROTATIONS = [
    [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
]
_MASK = (1 << 64) - 1


def _rotate(value, shift):
    return ((value << shift) | (value >> (64 - shift))) & _MASK if shift else value


def _permute(state):
    for constant in _ROUNDS:
        column = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
        mix = [column[(x - 1) % 5] ^ _rotate(column[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x][y] ^= mix[x]
        moved = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                moved[y][(2 * x + 3 * y) % 5] = _rotate(state[x][y], _ROTATIONS[x][y])
        for x in range(5):
            for y in range(5):
                state[x][y] = moved[x][y] ^ (~moved[(x + 1) % 5][y] & moved[(x + 2) % 5][y])
        state[0][0] ^= constant


def keccak256(data):
    """The Keccak-256 digest of `data` (bytes), as Ethereum computes it."""
    rate = 136
    padded = bytearray(data) + b"\x01"
    padded += b"\x00" * (-len(padded) % rate)
    padded[-1] |= 0x80
    state = [[0] * 5 for _ in range(5)]
    for start in range(0, len(padded), rate):
        block = padded[start:start + rate]
        for index in range(rate // 8):
            x, y = index % 5, index // 5
            state[x][y] ^= int.from_bytes(block[index * 8:index * 8 + 8], "little")
        _permute(state)
    out = b"".join(state[index % 5][index // 5].to_bytes(8, "little") for index in range(25))
    return out[:32]


# ---- Base58 ----

def base58_decode(text):
    """The bytes a base58 string encodes, or None when it is not base58."""
    if not isinstance(text, str) or not text or any(character not in INDEX for character in text):
        return None
    number = 0
    for character in text:
        number = number * 58 + INDEX[character]
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\x00" * (len(text) - len(text.lstrip("1"))) + body


def base58_encode(data):
    """The base58 string of `data` (bytes); used by the tests and for display."""
    number = int.from_bytes(data, "big")
    text = ""
    while number:
        number, rest = divmod(number, 58)
        text = ALPHABET[rest] + text
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + text


# ---- Addresses ----

def evm_address(text):
    """An Ethereum-style address: 0x and 40 hex digits. A mixed-case address must carry a valid
    EIP-55 checksum; an all-lower or all-upper one has none to check."""
    if not isinstance(text, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", text):
        return False
    digits = text[2:]
    if digits == digits.lower() or digits == digits.upper():
        return True
    hashed = keccak256(digits.lower().encode()).hex()
    return all((character.upper() if int(hashed[index], 16) >= 8 else character.lower()) == character
               for index, character in enumerate(digits))


def tron_address(text):
    """A Tron address: Base58Check of 0x41 and 20 bytes, with its four-byte checksum."""
    if not isinstance(text, str) or len(text) != 34 or not text.startswith("T"):
        return False
    raw = base58_decode(text)
    if raw is None or len(raw) != 25 or raw[0] != 0x41:
        return False
    return hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4] == raw[21:]


def solana_address(text):
    """A Solana address: base58 of exactly 32 bytes."""
    if not isinstance(text, str) or not 32 <= len(text) <= 44:
        return False
    raw = base58_decode(text)
    return raw is not None and len(raw) == 32


# Network to (address check, transaction id pattern, transaction id words).
CHECKS = {
    "base": (evm_address, r"0x[0-9a-fA-F]{64}", "0x and 64 hex characters"),
    "tron": (tron_address, r"(0x)?[0-9a-fA-F]{64}", "64 hex characters"),
    "ethereum": (evm_address, r"0x[0-9a-fA-F]{64}", "0x and 64 hex characters"),
    "bsc": (evm_address, r"0x[0-9a-fA-F]{64}", "0x and 64 hex characters"),
    "polygon": (evm_address, r"0x[0-9a-fA-F]{64}", "0x and 64 hex characters"),
    "arbitrum": (evm_address, r"0x[0-9a-fA-F]{64}", "0x and 64 hex characters"),
    "solana": (solana_address, None, "a base58 signature of 64 bytes"),
}


def address(network, text):
    """Whether `text` is a well-formed address (with a valid checksum where it has one)."""
    check = CHECKS.get(network)
    return bool(check) and check[0](text)


def transaction(network, text):
    """The transaction id in the form it is stored, or None when it does not fit the network."""
    check = CHECKS.get(network)
    if not check or not isinstance(text, str):
        return None
    text = text.strip()
    if network == "solana":
        if not 64 <= len(text) <= 88:
            return None
        raw = base58_decode(text)
        return text if raw is not None and len(raw) == 64 else None
    if not re.fullmatch(check[1], text):
        return None
    # One spelling per transaction, so the same transfer cannot be entered twice in two cases.
    return text.lower() if network != "tron" else text.lower().removeprefix("0x")


def transaction_words(network):
    return CHECKS.get(network, (None, None, "a transaction id"))[2]
