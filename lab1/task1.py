from Crypto.Cipher import AES
from Crypto.Cipher import ARC4
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

key_AES = bytes([255] * 16)
iv_AES = get_random_bytes(16)
key_ARC4 = bytes([255] * 5)

def encrypt_AES(plaintext: bytes) -> bytes:
  paddedPlainText: bytes = pad(plaintext, 16)
  cipher = AES.new(key_AES, AES.MODE_CBC, iv_AES)
  return cipher.encrypt(paddedPlainText)

def decrypt_AES(ciphertext: bytes) -> bytes:
  cipher = AES.new(key_AES, AES.MODE_CBC, iv_AES)
  return unpad(cipher.decrypt(ciphertext), 16)

def encrypt_ARC4(plaintext: bytes) -> bytes:
  cipher = ARC4.new(key_ARC4)
  return cipher.encrypt(plaintext)

def decrypt_ARC4(ciphertext: bytes) -> bytes:
  cipher = ARC4.new(key_ARC4)
  return cipher.decrypt(ciphertext)


def main():
  plaintext = b'this is the wireless security lab'
  
  print("AES=====================")
  ciphertext = encrypt_AES(plaintext)
  print(ciphertext)
  print(decrypt_AES(ciphertext))

  print("ARC4=====================")
  ciphertext = encrypt_ARC4(plaintext)
  print(ciphertext)
  print(decrypt_ARC4(ciphertext))


main()