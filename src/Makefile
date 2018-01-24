all: clean build-encrypt

clean:
	rm -rf test.enc file-crypt

test: build-encrypt
	./file-crypt ENCRYPT test.c test.enc
build-encrypt:
	gcc file-crypt.c -g -o file-crypt -lcrypto
