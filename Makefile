all: clean build-encrypt test

clean:
	rm -rf test.enc file-crypt
test:

build-encrypt:
	gcc file-crypt.c -g -o file-crypt -lcrypto
	./file-crypt ENCRYPT test.c test.enc
