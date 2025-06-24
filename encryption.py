from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def encrypt_file(data, key):
    key = key.ljust(32, b'\0')[:32]  # AES-256 requires 32-byte key
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + ct_bytes

def decrypt_file(data, key):
    key = key.ljust(32, b'\0')[:32]
    iv = data[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(data[16:]), AES.block_size)
    return pt
