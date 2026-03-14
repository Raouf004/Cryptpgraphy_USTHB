# CipherLab — Cryptography Toolkit

A full-stack web app for encrypting and decrypting text using classic and modern ciphers.

## Project Structure

```
cipherlab/
├── app.py          # Flask backend with all cipher implementations
├── requirements.txt
├── static/
│   └── index.html  # Frontend (HTML + CSS + JS)
└── README.md
```

## Ciphers Implemented (pure Python)

| Cipher      | Type                       | Key Format                    |
|-------------|----------------------------|-------------------------------|
| Caesar      | Substitution               | Number 1–25                   |
| Vigenère    | Polyalphabetic             | Keyword (letters)             |
| Playfair    | Digraph substitution       | Keyword (letters)             |
| Hill        | Matrix substitution        | 4 letters (2×2) or 9 (3×3)   |
| Rail Fence  | Transposition              | Number of rails (2+)          |
| DES         | Symmetric block cipher     | Up to 8-char string           |
| AES-128     | Symmetric block cipher     | Up to 16-char string          |

## Setup & Run

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the Flask server
```bash
python app.py
```

### 3. Open in browser
Navigate to: **http://localhost:5000**

## API Endpoints

- `GET /ciphers` — List available ciphers with key hints
- `POST /cipher` — Encrypt or decrypt

### POST /cipher request body
```json
{
  "cipher": "aes",
  "mode": "encrypt",
  "text": "Hello World",
  "key": "mysecretkey"
}
```

### Response
```json
{
  "result": "base64encodedciphertext..."
}
```
