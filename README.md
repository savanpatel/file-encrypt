# file-encrypt

### What it is?
file-encrypt is simple file encryption-decryption python script.
### Required installations.
open ssl c library
on mac 

`brew install openssl` 

`brew install openssl-dev`
#### Usage
Build the executable with `make`

Encrypt file:
 `./file-crypt ENCRYPT test.c test.enc`

Decrypt file:
 `./file-crypt DECRYPT test.enc decrypted.c`
