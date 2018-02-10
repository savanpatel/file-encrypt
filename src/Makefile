all: clean build-encrypt

clean:
	rm -rf test.enc file-crypt test.out file-crypt.dSYM

test: build-encrypt
	./file-crypt -e test.c -o test.enc && ./file-crypt -d test.enc -o test.c
build-encrypt:
	gcc file-crypt.c -o file-crypt -lcrypto
