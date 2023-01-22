from Crypto.Cipher import AES
from Crypto.Cipher import ARC4
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

key_AES = bytes([255] * 16) # 1's
iv_AES = get_random_bytes(16)
key_ARC4 = bytes([255] * 5) # 1's

# Encrypt the plaintext using AES in CBC mode with the given key and iv
def encrypt_AES(plaintext: bytes) -> bytes:
  paddedPlainText: bytes = pad(plaintext, 16)
  cipher = AES.new(key_AES, AES.MODE_CBC, iv_AES)
  return cipher.encrypt(paddedPlainText)

# Decrypt the ciphertext using AES in CBC mode with the given key and iv
def decrypt_AES(ciphertext: bytes) -> bytes:
  cipher = AES.new(key_AES, AES.MODE_CBC, iv_AES)
  return unpad(cipher.decrypt(ciphertext), 16)

# Encrypt the plaintext using ARC4 with the given key
def encrypt_ARC4(plaintext: bytes) -> bytes:
  cipher = ARC4.new(key_ARC4)
  return cipher.encrypt(plaintext)

# Decrypt the ciphertext using ARC4 with the given key
def decrypt_ARC4(ciphertext: bytes) -> bytes:
  cipher = ARC4.new(key_ARC4)
  return cipher.decrypt(ciphertext)


def main():
  plaintext = b'this is the wireless security lab'
  print("Plaintext: ", plaintext)
  print("=====================AES=====================")
  ciphertext = encrypt_AES(plaintext)
  print("Cipher text: ", ciphertext)
  print("Decrypted plaintext: ", decrypt_AES(ciphertext))

  print("=====================ARC4=====================")
  ciphertext = encrypt_ARC4(plaintext)
  print("Cipher text: ",ciphertext)
  print("Decrypted plaintext: ", decrypt_ARC4(ciphertext))


main()