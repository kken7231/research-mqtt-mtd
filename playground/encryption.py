from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Encryption function
def encrypt_aes_gcm(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, tag

# Decryption function
def decrypt_aes_gcm(ciphertext, key, iv, tag):
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        print("Decryption successful!")
        return plaintext
    except ValueError:
        print("Decryption failed: MAC check failed")
        return None

# Provided values
key = bytes.fromhex("3974BC08993A24BFED9F24D189936095")  # 128-bit key (16 bytes)
iv = bytes.fromhex("000000000001e24000000000")  # 12-byte IV for GCM

# Example plaintext (message to encrypt)
plaintext = b"hello, world"

print("Key (hex):", key.hex())
print("IV (hex):", iv.hex())
print("Plaintext (hex):", plaintext.hex())

# Encrypt the plaintext
ciphertext, tag = encrypt_aes_gcm(plaintext, key, iv)
print("Ciphertext (hex):", ciphertext.hex())
print("Tag (hex):", tag.hex())

# Decrypt the ciphertext
decrypted_text = decrypt_aes_gcm(ciphertext, key, iv, tag)
if decrypted_text:
    print("Decrypted Text:", decrypted_text.decode('utf-8'))