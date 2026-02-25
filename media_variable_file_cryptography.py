# Copyright (C) 2022 Christopher Panayi, MWR CyberSec
#
# This file is part of PXEThief (https://github.com/MWR-CyberSec/PXEThief).
# 
# PXEThief is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.
# 
# PXEThief is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License along with PXEThief. If not, see <https://www.gnu.org/licenses/>.

import sys
import base64
from Crypto.Cipher import AES,DES3
from hashlib import *
import binascii

def read_media_variable_file(filename):
    media_file = open(filename,'rb')
    media_file.seek(24)
    media_data = media_file.read()
    return media_data[:-8]

def aes_des_key_derivation(password):
    
    key_sha1 = sha1(password).digest()
    
    b0 = b""
    for x in key_sha1:
        b0 += bytes((x ^ 0x36,))
        
    b1 = b""
    for x in key_sha1:
        b1 += bytes((x ^ 0x5c,))

    # pad remaining bytes with the appropriate value
    b0 += b"\x36"*(64 - len(b0))
    b1 += b"\x5c"*(64 - len(b1))
         
    b0_sha1 = sha1(b0).digest()
    b1_sha1 = sha1(b1).digest()
    
    return b0_sha1 + b1_sha1

def aes128_decrypt(data,key,iv=b"\x00"*16):

    aes128 = AES.new(key, AES.MODE_CBC, iv)
    decrypted = aes128.decrypt(data)
    return decrypted.decode("utf-16-le")

def aes128_decrypt_raw(data,key,iv=b"\x00"*16):

    aes128 = AES.new(key, AES.MODE_CBC, iv)
    decrypted = aes128.decrypt(data)
    return decrypted

def aes256_decrypt(data,key,iv=b"\x00"*16):

    aes256 = AES.new(key, AES.MODE_CBC, iv)
    decrypted = aes256.decrypt(data)
    return decrypted.decode("utf-16-le")

def aes256_decrypt_raw(data,key,iv=b"\x00"*16):

    aes256 = AES.new(key, AES.MODE_CBC, iv)
    decrypted = aes256.decrypt(data)
    return decrypted

def _3des_decrypt(data,key,iv=b"\x00"*8):

    _3des = DES3.new(key, DES3.MODE_CBC, iv)
    decrypted = _3des.decrypt(data)
    return decrypted.decode("utf-16-le")

def _3des_decrypt_raw(data,key,iv=b"\x00"*8):

    _3des = DES3.new(key, DES3.MODE_CBC, iv)
    decrypted = _3des.decrypt(data)
    return decrypted

def read_media_variable_file_header(filename):
    media_file = open(filename,'rb')
    media_data = media_file.read(40).hex()
    hash_type = ""
    if media_data[32:36] == "0e66":
        hash_type = "aes128$"
    if media_data[32:36] == "1066":
        hash_type = "aes256$"
    if media_data[32:36] == "0366":
        hash_type = "3des..$"
    return hash_type + media_data
