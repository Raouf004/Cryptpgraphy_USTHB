from flask import Flask, request, jsonify, send_from_directory
import numpy as np
import os
import struct
import base64
import hashlib
import hmac
import secrets
import math
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# --- Existing implementations (DES, Hill, Caesar, Vigenere, Playfair, RailFence, AES) ---
# [Keep all your existing implementations here...]

# ============ NEW IMPLEMENTATIONS ============

# 1. Affine Cipher
def affine_encrypt(plaintext: str, key: str) -> str:
    """Affine cipher: key format 'a,b' where a and b are integers, gcd(a,26)=1"""
    try:
        a, b = map(int, key.split(','))
        if math.gcd(a, 26) != 1:
            raise ValueError("a must be coprime with 26")
    except:
        raise ValueError("Key must be 'a,b' with integers, and gcd(a,26)=1")
    
    result = ''
    for c in plaintext:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            x = ord(c) - base
            encrypted = (a * x + b) % 26
            result += chr(encrypted + base)
        else:
            result += c
    return result

def mod_inverse(a, m):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None

def affine_decrypt(ciphertext: str, key: str) -> str:
    try:
        a, b = map(int, key.split(','))
        a_inv = mod_inverse(a % 26, 26)
        if a_inv is None:
            raise ValueError("No modular inverse for a")
    except:
        raise ValueError("Invalid key")
    
    result = ''
    for c in ciphertext:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            y = ord(c) - base
            decrypted = (a_inv * (y - b)) % 26
            result += chr(decrypted + base)
        else:
            result += c
    return result

# 2. Frequency Analysis
def frequency_analysis(text: str) -> dict:
    """Analyse frequency of letters in text"""
    text = ''.join(filter(str.isalpha, text.upper()))
    if not text:
        return {'error': 'No alphabetic characters found'}
    
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    
    total = len(text)
    for c in freq:
        freq[c] = round(freq[c] / total * 100, 2)
    
    # Sort by frequency descending
    sorted_freq = dict(sorted(freq.items(), key=lambda x: x[1], reverse=True))
    
    # Compare with English frequencies
    english_freq = {
        'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7, 'S': 6.3,
        'H': 6.1, 'R': 6.0, 'D': 4.3, 'L': 4.0, 'C': 2.8, 'U': 2.8, 'M': 2.4,
        'W': 2.4, 'F': 2.2, 'G': 2.0, 'Y': 2.0, 'P': 1.9, 'B': 1.5, 'V': 1.0,
        'K': 0.8, 'J': 0.2, 'X': 0.2, 'Q': 0.1, 'Z': 0.1
    }
    
    return {
        'frequencies': sorted_freq,
        'english_comparison': english_freq,
        'total_characters': total
    }

# 3. One-Time Pad (OTP)
def otp_encrypt(plaintext: str, key: str) -> str:
    """One-Time Pad: key must be same length as plaintext"""
    if len(key) < len(plaintext):
        raise ValueError(f"Key length ({len(key)}) must be >= plaintext length ({len(plaintext)})")
    
    plain_bytes = plaintext.encode()
    key_bytes = key.encode()[:len(plain_bytes)]
    
    encrypted = bytes([p ^ k for p, k in zip(plain_bytes, key_bytes)])
    return base64.b64encode(encrypted).decode()

def otp_decrypt(ciphertext: str, key: str) -> str:
    data = base64.b64decode(ciphertext)
    key_bytes = key.encode()[:len(data)]
    
    decrypted = bytes([d ^ k for d, k in zip(data, key_bytes)])
    return decrypted.decode('utf-8', errors='replace')

def otp_generate_key(length: int) -> str:
    """Generate a random OTP key of specified length"""
    return secrets.token_hex(length // 2 + 1)[:length]

# 4. Index of Coincidence
def index_of_coincidence(text: str) -> dict:
    """Calculate Index of Coincidence for text analysis"""
    text = ''.join(filter(str.isalpha, text.upper()))
    if not text:
        return {'error': 'No alphabetic characters found'}
    
    n = len(text)
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    
    ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1)) if n > 1 else 0
    
    # Estimate key length based on IC
    english_ic = 0.0667
    random_ic = 0.0385
    
    estimated_key_length = None
    if ic > 0:
        # Rough estimation formula
        if abs(ic - english_ic) < abs(ic - random_ic):
            estimated_key_length = "Likely monoalphabetic or short key"
        else:
            estimated_key_length = "Likely polyalphabetic or long key"
    
    return {
        'index_of_coincidence': round(ic, 6),
        'expected_english': english_ic,
        'expected_random': random_ic,
        'estimated_key_length': estimated_key_length,
        'total_characters': n
    }

# 5. RC4
def rc4_encrypt(plaintext: str, key: str) -> str:
    """RC4 stream cipher"""
    key_bytes = key.encode()
    plain_bytes = plaintext.encode()
    
    # Key Scheduling Algorithm (KSA)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
        S[i], S[j] = S[j], S[i]
    
    # Pseudo-Random Generation Algorithm (PRGA)
    i = j = 0
    result = bytearray()
    for byte in plain_bytes:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        result.append(byte ^ k)
    
    return base64.b64encode(result).decode()

def rc4_decrypt(ciphertext: str, key: str) -> str:
    # RC4 is symmetric
    data = base64.b64decode(ciphertext)
    decrypted = rc4_encrypt(data.decode('latin1'), key)
    return decrypted

# 6. RSA
def rsa_generate_keys(key_size: int = 2048) -> dict:
    """Generate RSA key pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    return {
        'private_key_pem': private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode(),
        'public_key_pem': public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    }

def rsa_encrypt(plaintext: str, public_key_pem: str) -> str:
    """RSA encryption with public key"""
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode(),
        backend=default_backend()
    )
    
    ciphertext = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode()

def rsa_decrypt(ciphertext: str, private_key_pem: str) -> str:
    """RSA decryption with private key"""
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None,
        backend=default_backend()
    )
    
    decrypted = private_key.decrypt(
        base64.b64decode(ciphertext),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

# 7. Diffie-Hellman (simplified for demo)
def diffie_hellman_generate_keys() -> dict:
    """Generate Diffie-Hellman key pair using standard parameters"""
    # Using standard prime (RFC 3526 - 2048-bit MODP Group)
    p = int('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF', 16)
    g = 2
    
    private_key = random.randint(2, p-1)
    public_key = pow(g, private_key, p)
    
    return {
        'prime': hex(p),
        'generator': g,
        'private_key': hex(private_key),
        'public_key': hex(public_key)
    }

def diffie_hellman_compute_shared(their_public: str, my_private: str, prime: str) -> str:
    """Compute shared secret"""
    their_pub = int(their_public, 16)
    my_priv = int(my_private, 16)
    p = int(prime, 16)
    
    shared_secret = pow(their_pub, my_priv, p)
    return hex(shared_secret)

# 8. El Gamal (simplified)
def elgamal_generate_keys() -> dict:
    """Generate El Gamal key pair"""
    # Using a smaller prime for demonstration
    p = 2357  # Small prime for demo
    g = 2
    
    private_key = random.randint(2, p-2)
    public_key = pow(g, private_key, p)
    
    return {
        'prime': p,
        'generator': g,
        'private_key': private_key,
        'public_key': public_key
    }

def elgamal_encrypt(plaintext: str, public_key: int, prime: int, generator: int) -> dict:
    """El Gamal encryption"""
    message = int.from_bytes(plaintext.encode(), 'big')
    if message >= prime:
        raise ValueError("Message too large for prime size")
    
    k = random.randint(2, prime-2)
    c1 = pow(generator, k, prime)
    c2 = (message * pow(public_key, k, prime)) % prime
    
    return {
        'c1': c1,
        'c2': c2,
        'prime': prime
    }

def elgamal_decrypt(c1: int, c2: int, private_key: int, prime: int) -> str:
    """El Gamal decryption"""
    s = pow(c1, private_key, prime)
    s_inv = pow(s, -1, prime)
    message = (c2 * s_inv) % prime
    
    # Convert back to string
    try:
        return message.to_bytes((message.bit_length() + 7) // 8, 'big').decode()
    except:
        return str(message)

# 9. Hashing
def hash_text(text: str, algorithm: str = 'sha256') -> dict:
    """Compute hash of text using various algorithms"""
    algorithms_available = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha384': hashlib.sha384,
        'sha512': hashlib.sha512,
        'blake2b': hashlib.blake2b,
        'blake2s': hashlib.blake2s,
        'sha3_256': hashlib.sha3_256,
        'sha3_512': hashlib.sha3_512
    }
    
    if algorithm not in algorithms_available:
        raise ValueError(f"Unsupported algorithm. Choose from: {list(algorithms_available.keys())}")
    
    hash_obj = algorithms_available[algorithm]()
    hash_obj.update(text.encode())
    
    return {
        'algorithm': algorithm,
        'hash': hash_obj.hexdigest(),
        'hash_bytes': len(hash_obj.digest()),
        'input_length': len(text)
    }

# 10. Digital Signatures
def sign_message(message: str, private_key_pem: str) -> str:
    """Sign a message using RSA private key"""
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None,
        backend=default_backend()
    )
    
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return base64.b64encode(signature).decode()

def verify_signature(message: str, signature: str, public_key_pem: str) -> bool:
    """Verify RSA signature"""
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode(),
        backend=default_backend()
    )
    
    try:
        public_key.verify(
            base64.b64decode(signature),
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

# 11. Protocols (Simple demonstration)
class ProtocolSimulator:
    @staticmethod
    def secure_channel():
        """Simulate a secure channel using session key exchange"""
        # Generate session key
        session_key = secrets.token_hex(16)
        return {
            'session_key': session_key,
            'status': 'Channel established',
            'protocol': 'TLS-like'
        }
    
    @staticmethod
    def authenticate_user(username: str, password: str) -> dict:
        """Simple authentication protocol"""
        # In real implementation, use proper password hashing
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), username.encode(), 100000)
        
        return {
            'authenticated': True,
            'protocol': 'Challenge-Response',
            'session_token': secrets.token_hex(32)
        }

# 12. Homomorphic Encryption (Simplified - Paillier-like)
class HomomorphicEncryption:
    def __init__(self):
        # Simplified multiplicative homomorphic encryption
        # In real implementation, use proper Paillier cryptosystem
        self.p = 101  # Small prime for demo
        self.q = 103  # Small prime for demo
        self.n = self.p * self.q
        self.g = 2
    
    def encrypt(self, plaintext: int) -> int:
        """Simplified homomorphic encryption"""
        r = random.randint(2, self.n-1)
        ciphertext = (pow(self.g, plaintext, self.n) * pow(r, self.n, self.n)) % (self.n * self.n)
        return ciphertext
    
    def decrypt(self, ciphertext: int) -> int:
        """Simplified homomorphic decryption"""
        # This is highly simplified - real Paillier is more complex
        lambda_val = (self.p - 1) * (self.q - 1)
        mu = pow(lambda_val, -1, self.n)
        plaintext = ((pow(ciphertext, lambda_val, self.n * self.n) - 1) // self.n * mu) % self.n
        return plaintext
    
    def add(self, ciphertext1: int, ciphertext2: int) -> int:
        """Homomorphic addition"""
        return (ciphertext1 * ciphertext2) % (self.n * self.n)

# 13. Shamir's Secret Sharing
def shamir_share_secret(secret: int, n: int, k: int) -> list:
    """Split secret into n shares, requiring k to reconstruct"""
    if k > n:
        raise ValueError("k cannot be greater than n")
    
    prime = 2**127 - 1  # Mersenne prime
    
    # Generate random coefficients
    coefficients = [secret] + [random.randint(1, prime-1) for _ in range(k-1)]
    
    # Generate shares
    shares = []
    for i in range(1, n+1):
        x = i
        y = sum(coef * pow(x, j, prime) for j, coef in enumerate(coefficients)) % prime
        shares.append((x, y))
    
    return {
        'shares': shares,
        'prime': prime,
        'threshold': k,
        'total_shares': n
    }

def shamir_reconstruct_secret(shares: list, prime: int) -> int:
    """Reconstruct secret from k shares using Lagrange interpolation"""
    secret = 0
    k = len(shares)
    
    for i in range(k):
        xi, yi = shares[i]
        
        # Calculate Lagrange basis
        numerator = 1
        denominator = 1
        for j in range(k):
            if i != j:
                xj = shares[j][0]
                numerator = (numerator * (-xj)) % prime
                denominator = (denominator * (xi - xj)) % prime
        
        lagrange = (yi * numerator * pow(denominator, -1, prime)) % prime
        secret = (secret + lagrange) % prime
    
    return secret

# ============ Flask App - Updated ============
app = Flask(__name__, static_folder='static')

@app.after_request
def add_cors(r):
    r.headers['Access-Control-Allow-Origin'] = '*'
    r.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    r.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
    return r

# Updated CIPHERS dictionary
CIPHERS = {
    'affine': (affine_encrypt, affine_decrypt, 'a,b (e.g., 5,8 where gcd(a,26)=1)', 'text'),
    'caesar': (caesar_encrypt, caesar_decrypt, 'Shift (1-25)', 'number'),
    'vigenere': (vigenere_encrypt, vigenere_decrypt, 'Keyword (letters only)', 'text'),
    'playfair': (playfair_encrypt, playfair_decrypt, 'Keyword (letters only)', 'text'),
    'hill': (hill_encrypt, hill_decrypt, '2×2: 4 letters or 3×3: 9 letters', 'text'),
    'railfence': (railfence_encrypt, railfence_decrypt, 'Number of rails (2+)', 'number'),
    'des': (des_encrypt, des_decrypt, 'Up to 8-char key', 'text'),
    'aes': (aes_encrypt, aes_decrypt, 'Up to 16-char key', 'text'),
    'otp': (otp_encrypt, otp_decrypt, 'Key length >= message length', 'text'),
    'rc4': (rc4_encrypt, rc4_decrypt, 'Any length key', 'text'),
}

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/cipher', methods=['POST'])
def cipher():
    data = request.json
    name = data.get('cipher', '').lower()
    mode = data.get('mode', 'encrypt')
    text = data.get('text', '')
    key = data.get('key', '')
    
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

# New routes for additional features
@app.route('/frequency', methods=['POST'])
def analyze_frequency():
    data = request.json
    text = data.get('text', '')
    return jsonify(frequency_analysis(text))

@app.route('/coincidence', methods=['POST'])
def analyze_coincidence():
    data = request.json
    text = data.get('text', '')
    return jsonify(index_of_coincidence(text))

@app.route('/otp/generate', methods=['POST'])
def generate_otp_key():
    data = request.json
    length = data.get('length', 32)
    return jsonify({'key': otp_generate_key(length)})

@app.route('/rsa/keys', methods=['POST'])
def rsa_keys():
    data = request.json
    size = data.get('size', 2048)
    return jsonify(rsa_generate_keys(size))

@app.route('/rsa/encrypt', methods=['POST'])
def rsa_encrypt_route():
    data = request.json
    return jsonify({'ciphertext': rsa_encrypt(data['text'], data['public_key'])})

@app.route('/rsa/decrypt', methods=['POST'])
def rsa_decrypt_route():
    data = request.json
    return jsonify({'plaintext': rsa_decrypt(data['ciphertext'], data['private_key'])})

@app.route('/dh/keys', methods=['GET'])
def dh_keys():
    return jsonify(diffie_hellman_generate_keys())

@app.route('/dh/shared', methods=['POST'])
def dh_shared():
    data = request.json
    shared = diffie_hellman_compute_shared(data['their_public'], data['my_private'], data['prime'])
    return jsonify({'shared_secret': shared})

@app.route('/elgamal/keys', methods=['GET'])
def elgamal_keys():
    return jsonify(elgamal_generate_keys())

@app.route('/hash', methods=['POST'])
def hash_route():
    data = request.json
    text = data.get('text', '')
    algorithm = data.get('algorithm', 'sha256')
    return jsonify(hash_text(text, algorithm))

@app.route('/sign', methods=['POST'])
def sign_route():
    data = request.json
    signature = sign_message(data['message'], data['private_key'])
    return jsonify({'signature': signature})

@app.route('/verify', methods=['POST'])
def verify_route():
    data = request.json
    valid = verify_signature(data['message'], data['signature'], data['public_key'])
    return jsonify({'valid': valid})

@app.route('/protocol/channel', methods=['GET'])
def protocol_channel():
    return jsonify(ProtocolSimulator.secure_channel())

@app.route('/protocol/auth', methods=['POST'])
def protocol_auth():
    data = request.json
    return jsonify(ProtocolSimulator.authenticate_user(data['username'], data['password']))

@app.route('/homomorphic/encrypt', methods=['POST'])
def homomorphic_encrypt():
    data = request.json
    he = HomomorphicEncryption()
    ciphertext = he.encrypt(int(data['plaintext']))
    return jsonify({'ciphertext': ciphertext, 'n': he.n * he.n})

@app.route('/shamir/share', methods=['POST'])
def shamir_share():
    data = request.json
    result = shamir_share_secret(data['secret'], data['n'], data['k'])
    # Convert shares to serializable format
    result['shares'] = [(x, y) for x, y in result['shares']]
    return jsonify(result)

@app.route('/shamir/reconstruct', methods=['POST'])
def shamir_reconstruct():
    data = request.json
    shares = [(x, y) for x, y in data['shares']]
    secret = shamir_reconstruct_secret(shares, data['prime'])
    return jsonify({'secret': secret})

if __name__ == '__main__':
    os.makedirs('static', exist_ok=True)
    app.run(debug=True, port=5000)