# file-crypt

file-encrypt is simple file command line tool that can:
  * encrypt a single file with given password
  * decrypt a previously encrypted file.

## Building file-encrypt
  1. setup openssl libraries.
     `brew install openssl`
     `brew install openssl-dev`
  2. Build the executable with `make`

## Usage
Encrypt a file:
 `./file-crypt ENCRYPT test.txt test.enc`

Decrypt file:
 `./file-crypt DECRYPT test.enc decrypted.txt`


## TODO
  * Use getopt(3) to improve cmdline options to be like
    ./file-crypt -e <inputfile> <outputfile>
    ./file-crypt -d <enfile> <decryptedfile>
  * Use exit codes to specify status of operation such as
    - 0 for success
    - 1 for failure like mismatch password
    - 2 inputfile not found or is not encrypted file.
    - 3 for failure to create/write outputfile
  * Create testassets directory and move test.c into it.
  * Add more test cases for things like
    - missing files
    - bad files
    - inaccessible file
    - zero size file
    - empty password
    - case-sensitive check for passwords.
  * Add repeatability tests to make sure sameinput and same password generates same encrypted file.
  * Add performance tests
    - encrypt a fixed size file multiple (100) times. Measure time, memory usage.
    - decrypt a fixed size file  multiple (100) times. Measure time, memory usage.
    - start with small file and keep doubling size and measure time taken for encrypt/decrypt operations
