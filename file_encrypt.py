#!/usr/bin/python

import os
import sys
from simplecrypt import encrypt, decrypt
from binascii import hexlify

DECRYPT_MODE = 'DECRYPT'
ENCRYPT_MODE = 'ENCRYPT'

def parse_commandline():
    mode = sys.argv[1].upper()
    file_name = sys.argv[2]
    return mode, file_name

def file_decrypt(file_name, password):
    with open(file_name, 'r') as f:
        for line in f:
            print(decrypt(password, line))
    return

def file_encrypt(file_name, password):
    with open(file_name, 'r') as f:
        for line in f:
            encrypted_line = encrypt(line, password)
            print("Encrypted line is : %s", hexlify(encrypted_line))
            print("Decrypted line is : %s", decrypt(password, encrypted_line))
    f.close()
    return


def main():
    ##prompt password
    ## TODO
    password = "input"
    mode, file_name = parse_commandline()
    if mode == DECRYPT_MODE:
        file_decrypt(file_name, password)
    elif mode == ENCRYPT_MODE:
        file_encrypt(file_name, password)
    else:
        print("mode {} is not supported".format(mode))


if __name__ == "__main__":
    main()
