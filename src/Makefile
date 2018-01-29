all: clean build-encrypt

clean:
	rm -rf test.enc file-crypt test.out file-crypt.dSYM

test: build-encrypt
	./file-crypt ENCRYPT test.c test.enc && ./file-crypt DECRYPT test.enc test.out
build-encrypt:
	gcc file-crypt.c -o file-crypt -lcrypto
