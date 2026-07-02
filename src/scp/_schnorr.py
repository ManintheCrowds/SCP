# PURPOSE: Self-contained BIP-340 Schnorr (secp256k1) sign/verify for antigen manifest signatures.
# DEPENDENCIES: none (pure Python). Used as fallback when `coincurve` is not installed.
# MODIFICATION NOTES: This is the public-domain BIP-340 reference implementation
#   (https://github.com/bitcoin/bips/blob/master/bip-0340/reference.py), lightly trimmed.
#   It is correct but NOT constant-time; production signing should prefer libsecp256k1
#   (via `coincurve`). Antigen P0 only verifies small manifests locally, so this is adequate.

import hashlib

_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def _tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()


def _is_infinite(point):
    return point is None


def _x(point):
    assert not _is_infinite(point)
    return point[0]


def _y(point):
    assert not _is_infinite(point)
    return point[1]


def _point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if _x(p1) == _x(p2) and _y(p1) != _y(p2):
        return None
    if p1 == p2:
        lam = (3 * _x(p1) * _x(p1) * pow(2 * _y(p1), _p - 2, _p)) % _p
    else:
        lam = ((_y(p2) - _y(p1)) * pow(_x(p2) - _x(p1), _p - 2, _p)) % _p
    x3 = (lam * lam - _x(p1) - _x(p2)) % _p
    return (x3, (lam * (_x(p1) - x3) - _y(p1)) % _p)


def _point_mul(point, n):
    r = None
    for i in range(256):
        if (n >> i) & 1:
            r = _point_add(r, point)
        point = _point_add(point, point)
    return r


def _bytes_from_int(x: int) -> bytes:
    return x.to_bytes(32, byteorder="big")


def _lift_x(x: int):
    if x >= _p:
        return None
    y_sq = (pow(x, 3, _p) + 7) % _p
    y = pow(y_sq, (_p + 1) // 4, _p)
    if pow(y, 2, _p) != y_sq:
        return None
    return (x, y if y & 1 == 0 else _p - y)


def _int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")


def _has_even_y(point) -> bool:
    assert not _is_infinite(point)
    return _y(point) % 2 == 0


def pubkey_gen(seckey: bytes) -> bytes:
    """Derive the 32-byte x-only public key for a 32-byte secret key."""
    d0 = _int_from_bytes(seckey)
    if not (1 <= d0 <= _n - 1):
        raise ValueError("secret key must be an integer in range 1..n-1")
    point = _point_mul(_G, d0)
    assert point is not None
    return _bytes_from_int(_x(point))


def schnorr_sign(msg: bytes, seckey: bytes, aux_rand: bytes = b"\x00" * 32) -> bytes:
    """BIP-340 sign. Returns 64-byte signature. msg may be any length (hashed in challenge)."""
    d0 = _int_from_bytes(seckey)
    if not (1 <= d0 <= _n - 1):
        raise ValueError("secret key must be an integer in range 1..n-1")
    if len(aux_rand) != 32:
        raise ValueError("aux_rand must be 32 bytes")
    point = _point_mul(_G, d0)
    assert point is not None
    d = d0 if _has_even_y(point) else _n - d0
    t = (d ^ _int_from_bytes(_tagged_hash("BIP0340/aux", aux_rand))).to_bytes(32, "big")
    k0 = _int_from_bytes(_tagged_hash("BIP0340/nonce", t + _bytes_from_int(_x(point)) + msg)) % _n
    if k0 == 0:
        raise RuntimeError("failure: nonce k0 == 0")
    r = _point_mul(_G, k0)
    assert r is not None
    k = k0 if _has_even_y(r) else _n - k0
    e = (
        _int_from_bytes(
            _tagged_hash(
                "BIP0340/challenge",
                _bytes_from_int(_x(r)) + _bytes_from_int(_x(point)) + msg,
            )
        )
        % _n
    )
    sig = _bytes_from_int(_x(r)) + _bytes_from_int((k + e * d) % _n)
    if not schnorr_verify(msg, _bytes_from_int(_x(point)), sig):
        raise RuntimeError("sign produced an invalid signature")
    return sig


def schnorr_verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool:
    """BIP-340 verify. pubkey is 32-byte x-only; sig is 64 bytes."""
    if len(pubkey) != 32 or len(sig) != 64:
        return False
    p_x = _int_from_bytes(pubkey)
    point = _lift_x(p_x)
    if point is None:
        return False
    r = _int_from_bytes(sig[0:32])
    s = _int_from_bytes(sig[32:64])
    if r >= _p or s >= _n:
        return False
    e = (
        _int_from_bytes(
            _tagged_hash("BIP0340/challenge", sig[0:32] + pubkey + msg)
        )
        % _n
    )
    big_r = _point_add(_point_mul(_G, s), _point_mul(point, _n - e))
    if big_r is None or not _has_even_y(big_r) or _x(big_r) != r:
        return False
    return True
