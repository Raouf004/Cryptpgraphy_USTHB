from flask import Flask, request, jsonify, send_from_directory
import numpy as np
import os
import struct
import base64

# --- DES Implementation ---
IP = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
      62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
      57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
      61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]
IP_INV = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
          38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
          36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
          34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25]
E = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,
     16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]
P = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
     2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]
S_BOXES = [
    [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],[0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],[4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],[15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
    [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],[3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],[0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],[13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
    [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],[13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],[13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],[1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
    [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],[13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],[10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],[3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
    [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],[14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],[4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],[11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
    [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],[10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],[9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],[4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
    [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],[13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],[1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],[6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
    [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],[1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],[7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],[2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
]
PC1 = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,
       63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4]
PC2 = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,
       41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]
SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

def permute(block, table):
    return [block[i-1] for i in table]

def xor(a, b):
    return [x ^ y for x, y in zip(a, b)]

def des_generate_keys(key_64bit):
    key_permuted = permute(key_64bit, PC1)
    C, D = key_permuted[:28], key_permuted[28:]
    subkeys = []
    for shift in SHIFTS:
        C = C[shift:] + C[:shift]
        D = D[shift:] + D[:shift]
        subkeys.append(permute(C + D, PC2))
    return subkeys

def des_f(R, subkey):
    expanded = permute(R, E)
    xored = xor(expanded, subkey)
    output = []
    for i in range(8):
        block = xored[i*6:(i+1)*6]
        row = (block[0] << 1) | block[5]
        col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4]
        output += [int(b) for b in f'{S_BOXES[i][row][col]:04b}']
    return permute(output, P)

def des_block(block_64bit, subkeys):
    permuted = permute(block_64bit, IP)
    L, R = permuted[:32], permuted[32:]
    for sk in subkeys:
        L, R = R, xor(L, des_f(R, sk))
    combined = R + L
    return permute(combined, IP_INV)

def bytes_to_bits(b):
    bits = []
    for byte in b:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits

def bits_to_bytes(bits):
    result = []
    for i in range(0, len(bits), 8):
        byte = 0
        for b in bits[i:i+8]:
            byte = (byte << 1) | b
        result.append(byte)
    return bytes(result)

def des_encrypt(plaintext: str, key: str) -> str:
    key_bytes = key.encode('utf-8')[:8].ljust(8, b'\x00')
    data = plaintext.encode('utf-8')
    pad = 8 - len(data) % 8
    data += bytes([pad] * pad)
    key_bits = bytes_to_bits(key_bytes)
    subkeys = des_generate_keys(key_bits)
    result = b''
    for i in range(0, len(data), 8):
        block = bytes_to_bits(data[i:i+8])
        enc = des_block(block, subkeys)
        result += bits_to_bytes(enc)
    return base64.b64encode(result).decode()

def des_decrypt(ciphertext: str, key: str) -> str:
    key_bytes = key.encode('utf-8')[:8].ljust(8, b'\x00')
    data = base64.b64decode(ciphertext)
    key_bits = bytes_to_bits(key_bytes)
    subkeys = des_generate_keys(key_bits)[::-1]
    result = b''
    for i in range(0, len(data), 8):
        block = bytes_to_bits(data[i:i+8])
        dec = des_block(block, subkeys)
        result += bits_to_bytes(dec)
    pad = result[-1]
    return result[:-pad].decode('utf-8', errors='replace')

# --- Hill Cipher ---
def mod_inverse_matrix(matrix, mod):
    det = int(round(np.linalg.det(matrix))) % mod
    det_inv = pow(det, -1, mod)
    size = matrix.shape[0]
    if size == 2:
        adj = np.array([[matrix[1,1], -matrix[0,1]],
                        [-matrix[1,0], matrix[0,0]]], dtype=int)
    else:
        adj = np.array([[int(round((-1)**(i+j) * np.linalg.det(np.delete(np.delete(matrix, i, axis=0), j, axis=1))))
                         for j in range(size)] for i in range(size)], dtype=int).T
    return (det_inv * adj) % mod

def hill_encrypt(plaintext: str, key: str) -> str:
    plaintext = ''.join(filter(str.isalpha, plaintext)).upper()
    size = int(len(key)**0.5)
    if size * size != len(key):
        raise ValueError("Key length must be a perfect square (e.g. 4 for 2x2, 9 for 3x3)")
    key_matrix = np.array([ord(c) - 65 for c in key.upper() if c.isalpha()]).reshape(size, size)
    while len(plaintext) % size != 0:
        plaintext += 'X'
    result = ''
    for i in range(0, len(plaintext), size):
        block = np.array([ord(c) - 65 for c in plaintext[i:i+size]])
        enc = np.dot(key_matrix, block) % 26
        result += ''.join(chr(int(c) + 65) for c in enc)
    return result

def hill_decrypt(ciphertext: str, key: str) -> str:
    ciphertext = ''.join(filter(str.isalpha, ciphertext)).upper()
    size = int(len(key)**0.5)
    key_matrix = np.array([ord(c) - 65 for c in key.upper() if c.isalpha()]).reshape(size, size)
    inv_key = mod_inverse_matrix(key_matrix, 26)
    result = ''
    for i in range(0, len(ciphertext), size):
        block = np.array([ord(c) - 65 for c in ciphertext[i:i+size]])
        dec = np.dot(inv_key, block) % 26
        result += ''.join(chr(int(c) + 65) for c in dec)
    return result

# --- Caesar Cipher ---
def caesar_encrypt(plaintext: str, key: str) -> str:
    shift = int(key) % 26
    result = ''
    for c in plaintext:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result += chr((ord(c) - base + shift) % 26 + base)
        else:
            result += c
    return result

def caesar_decrypt(ciphertext: str, key: str) -> str:
    shift = int(key) % 26
    return caesar_encrypt(ciphertext, str(26 - shift))

# --- Vigenere Cipher ---
def vigenere_encrypt(plaintext: str, key: str) -> str:
    key = ''.join(filter(str.isalpha, key)).upper()
    if not key:
        raise ValueError("Key must contain alphabetic characters")
    result = ''
    ki = 0
    for c in plaintext:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            shift = ord(key[ki % len(key)]) - 65
            result += chr((ord(c) - base + shift) % 26 + base)
            ki += 1
        else:
            result += c
    return result

def vigenere_decrypt(ciphertext: str, key: str) -> str:
    key = ''.join(filter(str.isalpha, key)).upper()
    result = ''
    ki = 0
    for c in ciphertext:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            shift = ord(key[ki % len(key)]) - 65
            result += chr((ord(c) - base - shift) % 26 + base)
            ki += 1
        else:
            result += c
    return result

# --- Playfair Cipher ---
def playfair_matrix(key: str):
    key = ''.join(dict.fromkeys((key + 'ABCDEFGHIKLMNOPQRSTUVWXYZ').upper().replace('J','I')))
    key = ''.join(filter(str.isalpha, key))
    return [key[i*5:(i+1)*5] for i in range(5)]

def playfair_pos(matrix, c):
    c = 'I' if c == 'J' else c
    for r, row in enumerate(matrix):
        if c in row:
            return r, row.index(c)

def playfair_encrypt(plaintext: str, key: str) -> str:
    matrix = playfair_matrix(key)
    text = ''.join(filter(str.isalpha, plaintext)).upper().replace('J','I')
    digraphs = []
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i+1] if i+1 < len(text) else 'X'
        if a == b:
            digraphs.append((a, 'X'))
            i += 1
        else:
            digraphs.append((a, b))
            i += 2
    result = ''
    for a, b in digraphs:
        ra, ca = playfair_pos(matrix, a)
        rb, cb = playfair_pos(matrix, b)
        if ra == rb:
            result += matrix[ra][(ca+1)%5] + matrix[rb][(cb+1)%5]
        elif ca == cb:
            result += matrix[(ra+1)%5][ca] + matrix[(rb+1)%5][cb]
        else:
            result += matrix[ra][cb] + matrix[rb][ca]
    return result

def playfair_decrypt(ciphertext: str, key: str) -> str:
    matrix = playfair_matrix(key)
    text = ''.join(filter(str.isalpha, ciphertext)).upper()
    result = ''
    for i in range(0, len(text), 2):
        a, b = text[i], text[i+1] if i+1 < len(text) else 'X'
        ra, ca = playfair_pos(matrix, a)
        rb, cb = playfair_pos(matrix, b)
        if ra == rb:
            result += matrix[ra][(ca-1)%5] + matrix[rb][(cb-1)%5]
        elif ca == cb:
            result += matrix[(ra-1)%5][ca] + matrix[(rb-1)%5][cb]
        else:
            result += matrix[ra][cb] + matrix[rb][ca]
    return result

# --- Rail Fence ---
def railfence_encrypt(plaintext: str, key: str) -> str:
    rails = int(key)
    fence = [[] for _ in range(rails)]
    rail, direction = 0, 1
    for c in plaintext:
        fence[rail].append(c)
        if rail == 0: direction = 1
        elif rail == rails - 1: direction = -1
        rail += direction
    return ''.join(''.join(r) for r in fence)

def railfence_decrypt(ciphertext: str, key: str) -> str:
    rails = int(key)
    n = len(ciphertext)
    pattern = []
    rail, direction = 0, 1
    for i in range(n):
        pattern.append(rail)
        if rail == 0: direction = 1
        elif rail == rails - 1: direction = -1
        rail += direction
    counts = [pattern.count(r) for r in range(rails)]
    indices = []
    idx = 0
    for r in range(rails):
        indices.append(list(range(idx, idx + counts[r])))
        idx += counts[r]
    result = [''] * n
    for i, r in enumerate(pattern):
        result[i] = ciphertext[indices[r].pop(0)]
    return ''.join(result)

# --- AES (pure python, simplified ECB mode) ---
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]
SBOX_INV = [0]*256
for i,v in enumerate(SBOX): SBOX_INV[v]=i

RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

def xtime(a): return ((a<<1)^0x1b)&0xff if a&0x80 else (a<<1)&0xff

def gmul(a,b):
    p=0
    for _ in range(8):
        if b&1: p^=a
        hi=a&0x80; a=(a<<1)&0xff
        if hi: a^=0x1b
        b>>=1
    return p

def aes_key_expansion(key):
    w=[list(key[i:i+4]) for i in range(0,len(key),4)]
    nk=len(w); nr=nk+6
    for i in range(nk, 4*(nr+1)):
        temp=w[i-1][:]
        if i%nk==0:
            temp=temp[1:]+temp[:1]
            temp=[SBOX[b] for b in temp]
            temp[0]^=RCON[i//nk-1]
        elif nk>6 and i%nk==4:
            temp=[SBOX[b] for b in temp]
        w.append([a^b for a,b in zip(w[i-nk],temp)])
    return [w[i:i+4] for i in range(0,len(w),4)]

def add_round_key(state,rk):
    return [[state[r][c]^rk[c][r] for c in range(4)] for r in range(4)]

def sub_bytes(state,box):
    return [[box[state[r][c]] for c in range(4)] for r in range(4)]

def shift_rows(state):
    return [state[r][r:]+state[r][:r] for r in range(4)]

def inv_shift_rows(state):
    return [state[r][-r:]+state[r][:-r] if r else state[r] for r in range(4)]

def mix_col(col):
    return [gmul(2,col[0])^gmul(3,col[1])^col[2]^col[3],
            col[0]^gmul(2,col[1])^gmul(3,col[2])^col[3],
            col[0]^col[1]^gmul(2,col[2])^gmul(3,col[3]),
            gmul(3,col[0])^col[1]^col[2]^gmul(2,col[3])]

def inv_mix_col(col):
    return [gmul(14,col[0])^gmul(11,col[1])^gmul(13,col[2])^gmul(9,col[3]),
            gmul(9,col[0])^gmul(14,col[1])^gmul(11,col[2])^gmul(13,col[3]),
            gmul(13,col[0])^gmul(9,col[1])^gmul(14,col[2])^gmul(11,col[3]),
            gmul(11,col[0])^gmul(13,col[1])^gmul(9,col[2])^gmul(14,col[3])]

def mix_columns(state):
    cols=[[state[r][c] for r in range(4)] for c in range(4)]
    mixed=[mix_col(col) for col in cols]
    return [[mixed[c][r] for c in range(4)] for r in range(4)]

def inv_mix_columns(state):
    cols=[[state[r][c] for r in range(4)] for c in range(4)]
    mixed=[inv_mix_col(col) for col in cols]
    return [[mixed[c][r] for c in range(4)] for r in range(4)]

def bytes_to_state(b):
    return [[b[c*4+r] for c in range(4)] for r in range(4)]

def state_to_bytes(s):
    return bytes([s[r][c] for c in range(4) for r in range(4)])

def aes_encrypt_block(block, round_keys):
    nr=len(round_keys)-1
    state=bytes_to_state(block)
    state=add_round_key(state,round_keys[0])
    for rnd in range(1,nr):
        state=sub_bytes(state,SBOX)
        state=shift_rows(state)
        state=mix_columns(state)
        state=add_round_key(state,round_keys[rnd])
    state=sub_bytes(state,SBOX)
    state=shift_rows(state)
    state=add_round_key(state,round_keys[nr])
    return state_to_bytes(state)

def aes_decrypt_block(block, round_keys):
    nr=len(round_keys)-1
    state=bytes_to_state(block)
    state=add_round_key(state,round_keys[nr])
    for rnd in range(nr-1,0,-1):
        state=inv_shift_rows(state)
        state=sub_bytes(state,SBOX_INV)
        state=add_round_key(state,round_keys[rnd])
        state=inv_mix_columns(state)
    state=inv_shift_rows(state)
    state=sub_bytes(state,SBOX_INV)
    state=add_round_key(state,round_keys[0])
    return state_to_bytes(state)

def aes_encrypt(plaintext: str, key: str) -> str:
    key_bytes = key.encode()[:16].ljust(16, b'\x00')
    data = plaintext.encode()
    pad = 16 - len(data)%16
    data += bytes([pad]*pad)
    rk = aes_key_expansion(key_bytes)
    result = b''
    for i in range(0,len(data),16):
        result += aes_encrypt_block(data[i:i+16], rk)
    return base64.b64encode(result).decode()

def aes_decrypt(ciphertext: str, key: str) -> str:
    key_bytes = key.encode()[:16].ljust(16, b'\x00')
    data = base64.b64decode(ciphertext)
    rk = aes_key_expansion(key_bytes)
    result = b''
    for i in range(0,len(data),16):
        result += aes_decrypt_block(data[i:i+16], rk)
    pad = result[-1]
    return result[:-pad].decode('utf-8', errors='replace')

# --- Flask App ---
app = Flask(__name__, static_folder='static')

@app.after_request
def add_cors(r):
    r.headers['Access-Control-Allow-Origin'] = '*'
    r.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    r.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
    return r

CIPHERS = {
    'caesar':   (caesar_encrypt,   caesar_decrypt,   'Shift (1-25)', 'number'),
    'vigenere': (vigenere_encrypt,  vigenere_decrypt,  'Keyword (letters only)', 'text'),
    'playfair': (playfair_encrypt,  playfair_decrypt,  'Keyword (letters only)', 'text'),
    'hill':     (hill_encrypt,      hill_decrypt,      '2×2: 4 letters with invertible matrix (e.g. CDFE) or 3×3: 9 letters', 'text'),
    'railfence':(railfence_encrypt, railfence_decrypt, 'Number of rails (2+)', 'number'),
    'des':      (des_encrypt,       des_decrypt,       'Up to 8-char key', 'text'),
    'aes':      (aes_encrypt,       aes_decrypt,       'Up to 16-char key', 'text'),
}

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/cipher', methods=['POST'])
def cipher():
    data = request.json
    name = data.get('cipher','').lower()
    mode = data.get('mode','encrypt')
    text = data.get('text','')
    key  = data.get('key','')
    if name not in CIPHERS:
        return jsonify({'error': f'Unknown cipher: {name}'}), 400
    enc_fn, dec_fn, _, _ = CIPHERS[name]
    try:
        fn = enc_fn if mode == 'encrypt' else dec_fn
        result = fn(text, key)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/ciphers')
def list_ciphers():
    return jsonify([{
        'id': k,
        'name': k.upper(),
        'key_hint': v[2],
        'key_type': v[3]
    } for k, v in CIPHERS.items()])

if __name__ == '__main__':
    os.makedirs('static', exist_ok=True)
    app.run(debug=True, port=5000)
