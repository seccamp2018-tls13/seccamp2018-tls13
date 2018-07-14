
import hmac
import hashlib

def divceil(divident, divisor):
    """Integer division with rounding up"""
    quot, r = divmod(divident, divisor)
    return quot + int(bool(r))

def secureHash(data, algorithm):
    """Return a digest of `data` using `algorithm`"""
    hashInstance = hashlib.new(algorithm)
    hashInstance.update(data)
    return bytearray(hashInstance.digest())

def secureHMAC(k, b, algorithm):
    """Return a HMAC using `b` and `k` using `algorithm`"""
    return bytearray(hmac.new(k, b, getattr(hashlib, algorithm)).digest())

def HMAC_SHA256(k, b):
    return secureHMAC(k, b, 'sha256')

def HMAC_SHA384(k, b):
    return secureHMAC(k, b, 'sha384')

def HKDF_expand(PRK, info, L, algorithm):
    N = divceil(L, getattr(hashlib, algorithm)().digest_size)
    T = bytearray()
    Titer = bytearray()
    for x in range(1, N+2):
        T += Titer
        Titer = secureHMAC(PRK, Titer + info + bytearray([x]), algorithm)
    return T[:L]

def HKDF_expand_label(secret, label, hashValue, length, algorithm):
    """
    TLS1.3 key derivation function (HKDF-Expand-Label).
    :param bytearray secret: the key from which to derive the keying material
    :param bytearray label: label used to differentiate the keying materials
    :param bytearray hashValue: bytes used to "salt" the produced keying
        material
    :param int length: number of bytes to produce
    :param str algorithm: name of the secure hash algorithm used as the
        basis of the HKDF
    :rtype: bytearray
    """
    # TODO: Uint16 などを使ってバイト列を作る処理
    #
    # hkdfLabel = Writer()
    # hkdfLabel.addTwo(length)
    # hkdfLabel.addVarSeq(bytearray(b"tls13 ") + label, 1, 1)
    # hkdfLabel.addVarSeq(hashValue, 1, 1)
    #
    # return HKDF_expand(secret, hkdfLabel.bytes, length, algorithm)

def derive_secret(secret, label, handshake_hashes, algorithm):
    """
    TLS1.3 key derivation function (Derive-Secret).
    :param bytearray secret: secret key used to derive the keying material
    :param bytearray label: label used to differentiate they keying materials
    :param HandshakeHashes handshake_hashes: hashes of the handshake messages
        or `None` if no handshake transcript is to be used for derivation of
        keying material
    :param str algorithm: name of the secure hash algorithm used as the
        basis of the HKDF algorithm - governs how much keying material will
        be generated
    :rtype: bytearray
    """
    if handshake_hashes is None:
        hs_hash = secureHash(bytearray(b''), algorithm)
    else:
        hs_hash = handshake_hashes.digest(algorithm)
    return HKDF_expand_label(secret, label, hs_hash,
                             getattr(hashlib, algorithm)().digest_size,
                             algorithm)
