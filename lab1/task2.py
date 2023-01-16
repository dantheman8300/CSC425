from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

key_AES = get_random_bytes(16)
iv_AES = get_random_bytes(16)

def encrypt_AES_CBC(): 
  # Read input file
  fileIn = open("cp-logo.bmp", "rb")
  header = fileIn.read(54) # Store header info
  pictureData = fileIn.read() # Store picture data

  # Create output file 
  fileOut = open("CBC_encrypted.bmp", "wb")
  fileOut.write(header) # Write header info

  # Create cipher
  cipher = AES.new(key_AES, AES.MODE_CBC, iv_AES)

  # Encrypt and write to output file
  ciphterData = cipher.encrypt(pad(pictureData, 16))

  # Write to output file
  fileOut.write(ciphterData)

  # Close files
  fileIn.close()
  fileOut.close()

def encrypt_AES_ECB():
  # Read input file
  fileIn = open("cp-logo.bmp", "rb")
  header = fileIn.read(54) # Store header info
  pictureData = fileIn.read() # Store picture data

  # Create output file 
  fileOut = open("ECB_encrypted.bmp", "wb")
  fileOut.write(header) # Write header info

  # Create cipher
  cipher = AES.new(key_AES, AES.MODE_ECB)

  # Encrypt and write to output file
  ciphterData = cipher.encrypt(pad(pictureData, 16))

  # Write to output file
  fileOut.write(ciphterData)

  # Close files
  fileIn.close()
  fileOut.close()

def encrypt_AES_CFB():
  # Read input file
  fileIn = open("cp-logo.bmp", "rb")
  header = fileIn.read(54) # Store header info
  pictureData = fileIn.read() # Store picture data

  # Create output file 
  fileOut = open("CFB_encrypted.bmp", "wb")
  fileOut.write(header) # Write header info

  # Create cipher
  cipher = AES.new(key_AES, AES.MODE_CFB)

  # Encrypt and write to output file
  ciphterData = cipher.encrypt(pad(pictureData, 16))

  # Write to output file
  fileOut.write(ciphterData)

  # Close files
  fileIn.close()
  fileOut.close()

def encrypt_AES_OFB():
  # Read input file
  fileIn = open("cp-logo.bmp", "rb")
  header = fileIn.read(54) # Store header info
  pictureData = fileIn.read() # Store picture data

  # Create output file 
  fileOut = open("OFB_encrypted.bmp", "wb")
  fileOut.write(header) # Write header info

  # Create cipher
  cipher = AES.new(key_AES, AES.MODE_OFB)

  # Encrypt and write to output file
  ciphterData = cipher.encrypt(pad(pictureData, 16))

  # Write to output file
  fileOut.write(ciphterData)

  # Close files
  fileIn.close()
  fileOut.close()

def encrypt_AES_CTR():
  # Read input file
  fileIn = open("cp-logo.bmp", "rb")
  header = fileIn.read(54) # Store header info
  pictureData = fileIn.read() # Store picture data

  # Create output file 
  fileOut = open("CTR_encrypted.bmp", "wb")
  fileOut.write(header) # Write header info

  # Create cipher
  cipher = AES.new(key_AES, AES.MODE_CTR)

  # Encrypt and write to output file
  ciphterData = cipher.encrypt(pad(pictureData, 16))

  # Write to output file
  fileOut.write(ciphterData)

  # Close files
  fileIn.close()
  fileOut.close()

def decrypt_AES_CBC(): 
  # Read input file
  fileIn = open("CBC_encrypted.bmp", "rb")
  header = fileIn.read(54) # Store header info
  pictureData = fileIn.read() # Store picture data

  # Change the first byte of the picture data to test error propagation
  mutablePictureData = list(pictureData)
  mutablePictureData[0] = mutablePictureData[0] - 1
  pictureData = bytes(mutablePictureData)

  # Create output file 
  fileOut = open("CBC_decrypted.bmp", "wb")
  fileOut.write(header) # Write header info

  # Create cipher
  cipher = AES.new(key_AES, AES.MODE_CBC, iv_AES)

  # Encrypt and write to output file
  decryptedData = cipher.decrypt(pictureData)

  # Write to output file
  fileOut.write(decryptedData)

  # Close files
  fileIn.close()
  fileOut.close()

def decrypt_AES_ECB():
  # Read input file
  fileIn = open("ECB_encrypted.bmp", "rb")
  header = fileIn.read(54) # Store header info
  pictureData = fileIn.read() # Store picture data

  # Change the first byte of the picture data to test error propagation
  mutablePictureData = list(pictureData)
  mutablePictureData[0] = mutablePictureData[0] - 1
  pictureData = bytes(mutablePictureData)

  # Create output file 
  fileOut = open("ECB_decrypted.bmp", "wb")
  fileOut.write(header) # Write header info

  # Create cipher
  cipher = AES.new(key_AES, AES.MODE_ECB)

  # Encrypt and write to output file
  decryptedData = cipher.decrypt(pictureData)

  # Write to output file
  fileOut.write(decryptedData)

  # Close files
  fileIn.close()
  fileOut.close()

def decrypt_AES_CFB():
  # Read input file
  fileIn = open("CFB_encrypted.bmp", "rb")
  header = fileIn.read(54) # Store header info
  pictureData = fileIn.read() # Store picture data

  # Change the first byte of the picture data to test error propagation
  mutablePictureData = list(pictureData)
  mutablePictureData[0] = mutablePictureData[0] - 1
  pictureData = bytes(mutablePictureData)

  # Create output file 
  fileOut = open("CFB_decrypted.bmp", "wb")
  fileOut.write(header) # Write header info

  # Create cipher
  cipher = AES.new(key_AES, AES.MODE_CFB)

  # Encrypt and write to output file
  decryptedData = cipher.decrypt(pictureData)

  # Write to output file
  fileOut.write(decryptedData)

  # Close files
  fileIn.close()
  fileOut.close()

def decrypt_AES_OFB():
  # Read input file
  fileIn = open("OFB_encrypted.bmp", "rb")
  header = fileIn.read(54) # Store header info
  pictureData = fileIn.read() # Store picture data

  # Change the first byte of the picture data to test error propagation
  mutablePictureData = list(pictureData)
  mutablePictureData[0] = mutablePictureData[0] - 1
  pictureData = bytes(mutablePictureData)

  # Create output file 
  fileOut = open("OFB_decrypted.bmp", "wb")
  fileOut.write(header) # Write header info

  # Create cipher
  cipher = AES.new(key_AES, AES.MODE_OFB)

  # Encrypt and write to output file
  decryptedData = cipher.decrypt(pictureData)

  # Write to output file
  fileOut.write(decryptedData)

  # Close files
  fileIn.close()
  fileOut.close()

def decrypt_AES_CTR():
  # Read input file
  fileIn = open("CTR_encrypted.bmp", "rb")
  header = fileIn.read(54) # Store header info
  pictureData = fileIn.read() # Store picture data

  # Change the first byte of the picture data to test error propagation
  mutablePictureData = list(pictureData)
  mutablePictureData[0] = mutablePictureData[0] - 1
  pictureData = bytes(mutablePictureData)

  # Create output file 
  fileOut = open("CTR_decrypted.bmp", "wb")
  fileOut.write(header) # Write header info

  # Create cipher
  cipher = AES.new(key_AES, AES.MODE_CTR)

  # Encrypt and write to output file
  decryptedData = cipher.decrypt(pictureData)

  # Write to output file
  fileOut.write(decryptedData)

  # Close files
  fileIn.close()
  fileOut.close()
  

def main():
  encrypt_AES_CBC()
  encrypt_AES_ECB()
  encrypt_AES_CFB()
  encrypt_AES_OFB()
  encrypt_AES_CTR()

  decrypt_AES_CBC()
  decrypt_AES_ECB()
  decrypt_AES_CFB()
  decrypt_AES_OFB()
  decrypt_AES_CTR()

main()