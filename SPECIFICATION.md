# DNK-2 Encryption Algorithm Specification

**Version 2.0**  
**Date:** 22.02.2026  
**Author:** Alexey Kazakevich  

---

## 1. Purpose

The DNK-2 algorithm is designed to transform confidential data into a sequence of nucleotides (A, T, C, G) with the possibility of full recovery.  
Application areas:

- Encoding data for synthesis and storage in artificial DNA carriers
- Steganographic information transmission
- Long-term data archiving in biological environments

---

## 2. Main parameters

| Parameter | Value |
|-----------|-------|
| Input data | Binary data (text, files, etc.) |
| Output data | String of {A, T, C, G} characters |
| Expansion ratio | 1 byte → 4 nucleotides |
| Operation mode | Stream (XOR with key stream) |
| Key length | 256 bits (fixed) |

---

## 3. Key and key stream generation

### 3.1. Key requirements

The key K is a random binary sequence of 256 bits. Using meaningful phrases as a key is prohibited.

> **Important:** If the key is entered by the user as a password, it must be converted to a 256-bit key using a key derivation function:
> - Argon2id (recommended)
> - or PBKDF2 with at least 600,000 iterations

### 3.2. Nonce

Nonce (Number used ONCE) is a unique 128-bit (16 bytes) number generated anew for each message.

**Nonce purpose:**
- Ensures that even two identical messages encrypted with the same key look different
- Nonce is transmitted openly with the encrypted message

**Critical rule:** It is forbidden to use the same (Key + Nonce) pair for encrypting two different messages.

### 3.3. Key stream generator

ChaCha20 (recommended) or AES-256 in CTR mode is used as a pseudorandom sequence generator.

**Generator input:**
- Key K (256 bits)
- Nonce N (128 bits)

**Generator output:**
- Key stream P with length equal to the data being encrypted (in bytes)

### 3.4. XOR operation

Encryption and decryption are performed by XOR operation between the original data and the key stream:

    C = M ⊕ P
    M = C ⊕ P

Where:
- M — original data (plaintext)
- P — key stream
- C — encrypted data (ciphertext)

---

## 4. Encryption algorithm

### Step 1. Nonce generation
A random 128-bit number N is generated using a cryptographically secure random number generator.

### Step 2. Key stream generation
Based on key K and Nonce N, the generator (ChaCha20) produces a key stream P with length equal to the original message.

### Step 3. Key application
Each byte of the original message is XORed with the corresponding byte of the key stream. The result is the encrypted binary sequence C.

### Step 4. DNA encoding
The encrypted sequence C is bytewise converted to nucleotides. Each byte is split into 4 bit pairs, which are replaced according to the table:

| Bits | Nucleotide |
|------|------------|
| 00   | A |
| 01   | C |
| 10   | G |
| 11   | T |

Thus, 1 byte (8 bits) → 4 nucleotides.

### Step 5. Nonce encoding
The Nonce N (16 bytes) is also converted to nucleotides using the same table:
16 bytes = 128 bits = 64 bit pairs → 32 nucleotides.

### Step 6. Output packet formation

The output packet has a strict structure:

[Nonce in nucleotides (32 chars)]
[AAAA] (start marker)
[Encrypted data in nucleotides]
[TTTT] (stop marker)

**Example:**

AGCTAGCTAGCTAGCTAGCTAGCTAGCTAGCTAAAACGGTTACGGATCCTAGCTA...TTTT
|<-------------- Nonce ------------>|^marker^|<--- Data --->|^marker^|

## 5. Decryption algorithm

### Step 1. Nonce extraction
The first 32 characters are read from the beginning of the sequence. They are decoded into 16 bytes using the reverse table:

| Nucleotide | Bits |
|------------|------|
| A | 00 |
| C | 01 |
| G | 10 |
| T | 11 |

The original Nonce N is restored.

### Step 2. Marker verification
It is verified that the next 4 characters after Nonce are `AAAA`, and the last 4 characters of the entire sequence are `TTTT`. If markers don't match — an error is raised.

### Step 3. Encrypted data extraction
The start marker (`AAAA`) and stop marker (`TTTT`) are removed. The remaining nucleotide sequence is the encrypted data.

### Step 4. Nucleotide to bits decoding
The nucleotide sequence is split into groups of 4. Each nucleotide is converted to a bit pair using the reverse table. The encrypted binary sequence C is restored.

### Step 5. Key stream generation
Based on the original key K and extracted Nonce N, the same generator (ChaCha20) is started, producing a key stream P identical to the one used during encryption.

### Step 6. Key removal
The encrypted sequence C is XORed with the key stream P. The original message M is restored:

    M = C ⊕ P

### Step 7. Conversion to original format
The restored binary sequence is interpreted according to the original data format (text, file, etc.).

---

## 6. Integrity control (recommended)

To detect accidental errors or intentional modifications, it is recommended to add an authentication code to the end of the original data (before encryption):

- BLAKE3 (recommended, high speed)
- SHA-256 (classic version)
- HMAC-SHA256 (if keyed authentication is required)

**Procedure:**
1. Calculate hash of original data
2. Append hash to original data
3. Encrypt the entire block
4. During decryption, verify hash match

---

## 7. Cryptographic strength parameters

| Characteristic | Value |
|----------------|-------|
| Key brute-force complexity | 2²⁵⁶ operations (physically impossible) |
| Ciphertext uniqueness | Provided by 128-bit Nonce |
| Frequency analysis protection | Complete masking of statistics |
| Encoding redundancy | 4× (1 byte → 4 nucleotides) |
| Maximum message size | Practically unlimited (up to 2⁶⁴ bytes) |

---

## 8. Implementation requirements

### 8.1. Mandatory requirements
- Nonce must be generated by a cryptographically secure RNG for each message
- It is forbidden to use the same Nonce with one key more than once
- Keys must be stored in secure storage and transmitted only over secure channels

### 8.2. Recommendations
- Use ChaCha20 instead of AES-CTR on platforms without hardware AES acceleration
- Add integrity control (BLAKE3 or SHA-256) to detect modifications
- When synthesizing DNA, consider limitations on homopolymers (repeating nucleotides) — add post-processing if necessary

### 8.3. Error handling
- Start or stop marker mismatch → error, decryption stops
- Checksum mismatch → error, data considered corrupted
- Invalid character in input sequence (not A,T,C,G) → error

---

## 9. Example

**Original data:** `"Hi"` (ASCII: 72, 105)

Binary: `01001000 01101001`

**Key K:** (256 bits, truncated for example) `10101010...`

**Nonce N:** (128 bits, for example) `11001100...`

**Stream generation P:** (first 16 bits) `10010110 00111010`

**XOR (encryption):**

    01001000 ⊕ 10010110 = 11011110
    01101001 ⊕ 00111010 = 01010011

**Encrypted data C:** `11011110 01010011`

**DNA encoding:**

    1101 1110 0101 0011 (bit pairs)
    11=T, 01=C, 11=T, 10=G, 01=C, 01=C, 00=A, 11=T


**Result:** `TCTGC CAT`

**Nonce encoding:** (gives 32 nucleotides, e.g.) `AGCTAGCTAGCTAGCTAGCTAGCTAGCTAGCT`

**Final packet:**

    AGCTAGCTAGCTAGCTAGCTAGCTAGCTAGCTAAAATC TGCCATTTTT
    (where AGCT...AGCT = Nonce, AAAA = marker, TCTGCCAT = data, TTTT = marker)

## 10. Conclusion

The DNK-2 algorithm version 2.0 is a complete cryptographic solution combining:

- Modern stream cryptography (ChaCha20) with 256-bit key
- Uniqueness mechanism (128-bit Nonce)
- Specialized encoding for compatibility with DNA carriers

When all implementation requirements are followed, the algorithm provides a security level sufficient for protecting confidential information.

---

**© Alexey Kazakevich**  
**Document version: 2.0 (22.02.2026)**
