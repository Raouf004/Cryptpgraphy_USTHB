"""
Twofish Block Cipher — Implémentation Python complète
======================================================
Algorithme : Twofish (finaliste AES, Bruce Schneier et al., 1998)
Taille de bloc : 128 bits
Tailles de clé  : 128, 192, 256 bits
Nombre de tours : 16 tours de réseau de Feistel
Auteur de l'implémentation : TP Cryptographie Appliquée — Ing 3 Cybersécurité
"""

import os
import struct
import time

# ---------------------------------------------------------------------------
# Constantes MDS, RS et q-boîtes
# ---------------------------------------------------------------------------

# Polynôme primitif de GF(2^8) utilisé par MDS : x^8 + x^6 + x^3 + x^2 + 1 = 0x169
MDS_POLY = 0x169
# Polynôme primitif de GF(2^8) utilisé par RS   : x^8 + x^6 + x^3 + x^2 + 1 = 0x14D
RS_POLY  = 0x14D

# Matrice RS (4×8) sur GF(2^8) — transforme 8 octets en 4 mots
RS = [
    [0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E],
    [0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5],
    [0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19],
    [0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03],
]

# Matrice MDS (4×4) sur GF(2^8)
MDS = [
    [0x01, 0xEF, 0x5B, 0x5B],
    [0x5B, 0xEF, 0xEF, 0x01],
    [0xEF, 0x5B, 0x01, 0xEF],
    [0xEF, 0x01, 0xEF, 0x5B],
]

# q0 — permutation fixe (256 entrées)
Q0 = [
    0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76,
    0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38,
    0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C,
    0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48,
    0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23,
    0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82,
    0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C,
    0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61,
    0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B,
    0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1,
    0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66,
    0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7,
    0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA,
    0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71,
    0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8,
    0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7,
    0xA1, 0x1D, 0xAA, 0xED, 0x06, 0x70, 0xB2, 0xD2,
    0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90,
    0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB,
    0x9E, 0x9C, 0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF,
    0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B,
    0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64,
    0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A,
    0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A,
    0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02,
    0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D,
    0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72,
    0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
    0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8,
    0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4,
    0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00,
    0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0,
]

# q1 — permutation fixe (256 entrées)
Q1 = [
    0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8,
    0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B,
    0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1,
    0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F,
    0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D,
    0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5,
    0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3,
    0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51,
    0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96,
    0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C,
    0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70,
    0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8,
    0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC,
    0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7, 0x2B, 0xE2,
    0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9,
    0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17,
    0x66, 0x94, 0xA1, 0x1D, 0x3D, 0xF0, 0xDE, 0xB3,
    0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E,
    0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49,
    0x81, 0x88, 0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9,
    0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01,
    0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48,
    0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19,
    0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64,
    0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5,
    0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69,
    0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E,
    0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC,
    0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB,
    0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9,
    0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2,
    0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91,
]


# ---------------------------------------------------------------------------
# Fonctions de champ de Galois
# ---------------------------------------------------------------------------

def _gf_mul(a: int, b: int, poly: int) -> int:
    """Multiplication dans GF(2^8) avec polynôme primitif `poly`."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        hi_bit = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit:
            a ^= (poly & 0xFF)
        b >>= 1
    return result


def _mds_mul(v: int) -> int:
    """Applique la colonne MDS à un octet et retourne un mot 32 bits."""
    word = 0
    for row in MDS:
        byte = 0
        for col_val in row:
            byte ^= _gf_mul(col_val, v, MDS_POLY)
        word = (word >> 8) | (byte << 24)
    return word


def _rs_mul(m: list) -> int:
    """Multiplie 8 octets par la matrice RS, retourne un mot 32 bits."""
    result = 0
    for i in range(4):
        byte = 0
        for j in range(8):
            byte ^= _gf_mul(RS[i][j], m[j], RS_POLY)
        result |= (byte << (8 * i))
    return result


# ---------------------------------------------------------------------------
# Sous-clés et table de substitution S-box
# ---------------------------------------------------------------------------

def _q(x: int, which: int) -> int:
    return (Q0 if which == 0 else Q1)[x & 0xFF]


def _h(x: int, L: list) -> int:
    """Fonction h de Twofish (dépendante de la clé, 4 couches de q-boîtes + MDS)."""
    k = len(L)
    b = [(x >> (8 * i)) & 0xFF for i in range(4)]

    if k >= 4:
        b = [_q(b[i] ^ ((L[3] >> (8 * i)) & 0xFF), [1, 0, 1, 0][i]) for i in range(4)]
    if k >= 3:
        b = [_q(b[i] ^ ((L[2] >> (8 * i)) & 0xFF), [1, 1, 0, 0][i]) for i in range(4)]

    b = [_q(b[i] ^ ((L[1] >> (8 * i)) & 0xFF), [0, 1, 0, 1][i]) for i in range(4)]
    b = [_q(b[i] ^ ((L[0] >> (8 * i)) & 0xFF), [0, 0, 1, 1][i]) for i in range(4)]

    # Multiplication MDS
    result = 0
    for i in range(4):
        col = b[i]
        for row_idx in range(4):
            byte = _gf_mul(MDS[row_idx][i], col, MDS_POLY)
            result ^= (byte << (8 * row_idx))
    return result & 0xFFFFFFFF


def _rol32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _ror32(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Classe principale Twofish
# ---------------------------------------------------------------------------

class Twofish:
    """
    Implémentation du chiffrement par blocs Twofish.

    Paramètres
    ----------
    key : bytes
        Clé de 16, 24 ou 32 octets (128, 192 ou 256 bits).

    Utilisation
    -----------
    >>> tf = Twofish(key)
    >>> ct = tf.encrypt_block(pt)   # pt et ct sont des bytes de 16 octets
    >>> pt2 = tf.decrypt_block(ct)
    """

    BLOCK_SIZE = 16  # octets

    def __init__(self, key: bytes):
        key_len = len(key)
        if key_len not in (16, 24, 32):
            raise ValueError("La clé doit faire 16, 24 ou 32 octets (128/192/256 bits).")
        self._key_schedule(key)

    # ------------------------------------------------------------------
    # Expansion de clé
    # ------------------------------------------------------------------

    def _key_schedule(self, key: bytes):
        key_len = len(key)
        N = key_len // 8   # nombre de mots 64 bits (k = N dans la spec)

        # Découper la clé en mots 32 bits
        words = list(struct.unpack_from(f"<{key_len // 4}I", key))
        # Me et Mo : mots pairs et impairs
        Me = words[0::2]   # indices pairs
        Mo = words[1::2]   # indices impairs

        # Vecteur S : 1 mot 32 bits par 8 octets de clé, via matrice RS
        S = []
        for i in range(N):
            chunk = list(key[8 * i: 8 * i + 8])
            S.append(_rs_mul(chunk))
        S.reverse()  # ordre inversé comme dans la spec

        # Sous-clés K[0..39] (20 paires)
        rho = 0x01010101
        K = []
        for i in range(20):
            A = _h(2 * i * rho, Me)
            B = _ror32(_h((2 * i + 1) * rho, Mo), 8)
            K.append(_rol32((A + B) & 0xFFFFFFFF, 1))
            K.append(_ror32((A + 2 * B) & 0xFFFFFFFF, 9))

        self._K = K
        self._S = S

    # ------------------------------------------------------------------
    # Chiffrement d'un bloc de 16 octets
    # ------------------------------------------------------------------

    def encrypt_block(self, plaintext: bytes) -> bytes:
        if len(plaintext) != 16:
            raise ValueError("Le bloc doit faire exactement 16 octets.")

        # Déballage little-endian
        R = list(struct.unpack_from("<4I", plaintext))

        # Blanchiment d'entrée (input whitening)
        R = [R[i] ^ self._K[i] for i in range(4)]

        # 16 tours de Feistel
        for r in range(16):
            T0 = _h(R[0], self._S)
            T1 = _h(_rol32(R[1], 8), self._S)
            F0 = (T0 + T1 + self._K[2 * r + 8]) & 0xFFFFFFFF
            F1 = (T0 + 2 * T1 + self._K[2 * r + 9]) & 0xFFFFFFFF
            R[2] = _ror32(R[2] ^ F0, 1)
            R[3] = _rol32(R[3], 1) ^ F1
            # Échange des demi-blocs
            R[0], R[1], R[2], R[3] = R[2], R[3], R[0], R[1]

        # Annuler le dernier échange
        R[0], R[1], R[2], R[3] = R[2], R[3], R[0], R[1]

        # Blanchiment de sortie (output whitening)
        R = [R[i] ^ self._K[i + 4] for i in range(4)]

        return struct.pack("<4I", *R)

    # ------------------------------------------------------------------
    # Déchiffrement d'un bloc de 16 octets
    # ------------------------------------------------------------------

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) != 16:
            raise ValueError("Le bloc doit faire exactement 16 octets.")

        R = list(struct.unpack_from("<4I", ciphertext))

        # Annuler le blanchiment de sortie
        R = [R[i] ^ self._K[i + 4] for i in range(4)]

        # Annuler le dernier échange (rétablit l'état post-round-15)
        R[0], R[1], R[2], R[3] = R[2], R[3], R[0], R[1]

        # 16 tours inverses
        # Après l'échange ci-dessus, les "entrées gauches" de h() sont en [2],[3]
        # et les valeurs modifiées à inverser sont en [0],[1]
        for r in range(15, -1, -1):
            T0 = _h(R[2], self._S)
            T1 = _h(_rol32(R[3], 8), self._S)
            F0 = (T0 + T1 + self._K[2 * r + 8]) & 0xFFFFFFFF
            F1 = (T0 + 2 * T1 + self._K[2 * r + 9]) & 0xFFFFFFFF
            R[0] = _rol32(R[0], 1) ^ F0   # inverse de ROR(x^F0, 1)
            R[1] = _ror32(R[1] ^ F1, 1)   # inverse de ROL(x,1)^F1
            # Annuler l'échange du round r
            R[0], R[1], R[2], R[3] = R[2], R[3], R[0], R[1]

        # Annuler le blanchiment d'entrée
        R = [R[i] ^ self._K[i] for i in range(4)]

        return struct.pack("<4I", *R)


# ---------------------------------------------------------------------------
# Modes opératoires : ECB, CBC, CTR
# ---------------------------------------------------------------------------

def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]


def twofish_ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Chiffrement ECB (avec padding PKCS7)."""
    tf = Twofish(key)
    padded = _pkcs7_pad(plaintext)
    return b"".join(tf.encrypt_block(padded[i:i+16]) for i in range(0, len(padded), 16))


def twofish_ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """Déchiffrement ECB."""
    tf = Twofish(key)
    decrypted = b"".join(tf.decrypt_block(ciphertext[i:i+16]) for i in range(0, len(ciphertext), 16))
    return _pkcs7_unpad(decrypted)


def twofish_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """Chiffrement CBC (avec padding PKCS7)."""
    tf = Twofish(key)
    padded = _pkcs7_pad(plaintext)
    prev = iv
    blocks = []
    for i in range(0, len(padded), 16):
        block = bytes(a ^ b for a, b in zip(padded[i:i+16], prev))
        enc = tf.encrypt_block(block)
        blocks.append(enc)
        prev = enc
    return b"".join(blocks)


def twofish_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Déchiffrement CBC."""
    tf = Twofish(key)
    prev = iv
    blocks = []
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        dec = tf.decrypt_block(block)
        plain = bytes(a ^ b for a, b in zip(dec, prev))
        blocks.append(plain)
        prev = block
    return _pkcs7_unpad(b"".join(blocks))


def twofish_ctr_encrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """Chiffrement/Déchiffrement CTR (symétrique — pas de padding)."""
    tf = Twofish(key)
    out = []
    counter = int.from_bytes(nonce, "big")
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        keystream = tf.encrypt_block(counter.to_bytes(16, "big"))
        out.append(bytes(a ^ b for a, b in zip(block, keystream[:len(block)])))
        counter = (counter + 1) & ((1 << 128) - 1)
    return b"".join(out)


# ---------------------------------------------------------------------------
# Démonstrations / tests
# ---------------------------------------------------------------------------

def demo_basic():
    print("=" * 60)
    print("TWOFISH — Démonstration de base")
    print("=" * 60)

    for key_size in (16, 24, 32):
        key = os.urandom(key_size)
        tf = Twofish(key)
        message = b"Cryptographie !!!"[:16]   # 16 octets exactement

        ciphertext = tf.encrypt_block(message)
        recovered  = tf.decrypt_block(ciphertext)

        print(f"\nClé ({key_size * 8} bits) : {key.hex()}")
        print(f"  Clair      : {message.hex()}  '{message.decode()}'")
        print(f"  Chiffré    : {ciphertext.hex()}")
        print(f"  Déchiffré  : {recovered.hex()}  '{recovered.decode()}'")
        print(f"  Succès     : {message == recovered}")


def demo_modes():
    print("\n" + "=" * 60)
    print("TWOFISH — Modes opératoires (ECB / CBC / CTR)")
    print("=" * 60)

    key  = os.urandom(32)   # 256 bits
    iv   = os.urandom(16)
    nonce = os.urandom(16)
    msg  = b"Message secret pour le TP de cryptographie appliquee !"

    # ECB
    ct_ecb = twofish_ecb_encrypt(key, msg)
    pt_ecb = twofish_ecb_decrypt(key, ct_ecb)
    print(f"\n[ECB] Chiffré  : {ct_ecb.hex()}")
    print(f"[ECB] Déchiffré: {pt_ecb}")

    # CBC
    ct_cbc = twofish_cbc_encrypt(key, iv, msg)
    pt_cbc = twofish_cbc_decrypt(key, iv, ct_cbc)
    print(f"\n[CBC] IV       : {iv.hex()}")
    print(f"[CBC] Chiffré  : {ct_cbc.hex()}")
    print(f"[CBC] Déchiffré: {pt_cbc}")

    # CTR
    ct_ctr = twofish_ctr_encrypt(key, nonce, msg)
    pt_ctr = twofish_ctr_encrypt(key, nonce, ct_ctr)   # symétrique
    print(f"\n[CTR] Nonce    : {nonce.hex()}")
    print(f"[CTR] Chiffré  : {ct_ctr.hex()}")
    print(f"[CTR] Déchiffré: {pt_ctr}")


def demo_avalanche():
    print("\n" + "=" * 60)
    print("TWOFISH — Effet avalanche")
    print("=" * 60)

    key = os.urandom(16)
    tf  = Twofish(key)

    p1 = b'\x00' * 16
    # Inverser le bit 0 du premier octet
    p2 = bytes([p1[0] ^ 0x01]) + p1[1:]

    c1 = tf.encrypt_block(p1)
    c2 = tf.encrypt_block(p2)

    diff_bits = sum(bin(a ^ b).count('1') for a, b in zip(c1, c2))
    total_bits = 128
    print(f"\nClair 1   : {p1.hex()}")
    print(f"Clair 2   : {p2.hex()}  (1 bit différent)")
    print(f"Chiffré 1 : {c1.hex()}")
    print(f"Chiffré 2 : {c2.hex()}")
    print(f"Bits différents : {diff_bits}/{total_bits} ({100*diff_bits/total_bits:.1f} %)")


def demo_benchmark():
    print("\n" + "=" * 60)
    print("TWOFISH — Benchmark (1 Mo)")
    print("=" * 60)

    data = os.urandom(1024 * 1024)   # 1 Mo

    for key_size in (16, 24, 32):
        key = os.urandom(key_size)
        iv  = os.urandom(16)

        t0 = time.perf_counter()
        ct = twofish_cbc_encrypt(key, iv, data)
        t1 = time.perf_counter()

        elapsed = t1 - t0
        throughput = len(data) / elapsed / 1e6
        print(f"  AES-{key_size*8} CBC — {elapsed:.3f} s — {throughput:.2f} Mo/s")


def demo_nonce_reuse_ctr():
    print("\n" + "=" * 60)
    print("TWOFISH CTR — Vulnérabilité réutilisation de nonce")
    print("=" * 60)

    key   = os.urandom(32)
    nonce = os.urandom(16)   # MÊME nonce pour M1 et M2 !

    M1 = b"Message secret A"
    M2 = b"Message public B"

    C1 = twofish_ctr_encrypt(key, nonce, M1)
    C2 = twofish_ctr_encrypt(key, nonce, M2)

    xor_cc = bytes(a ^ b for a, b in zip(C1, C2))
    xor_mm = bytes(a ^ b for a, b in zip(M1, M2))

    print(f"C1 XOR C2 : {xor_cc.hex()}")
    print(f"M1 XOR M2 : {xor_mm.hex()}")
    print(f"Égaux     : {xor_cc == xor_mm}  ← attaquant retrouve M1 XOR M2 sans la clé !")


# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    demo_basic()
    demo_modes()
    demo_avalanche()
    demo_nonce_reuse_ctr()
    demo_benchmark()
