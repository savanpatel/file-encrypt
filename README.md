# file-crypt

### What it is?
file-crypt is simple password protected file encryption-decryption tool written in c.
### Required installations.
open ssl c library
on mac 

`brew install openssl` 

`brew install openssl-dev`
#### Usage
Build the executable with `make`

Encrypt file:
 `./file-crypt -e test.c -o test.enc`

Decrypt file:
 `./file-crypt -d test.enc -o decrypted.c`
