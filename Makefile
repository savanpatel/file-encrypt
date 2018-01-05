all: build-encrypt test

test:

build-encrypt:
	gcc file-crypt.c -g -o file-crypt -lcrypto
	./file-crypt
