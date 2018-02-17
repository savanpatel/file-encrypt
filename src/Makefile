OUTDIR=$(PWD)/BUILD/product
SYMDIR=$(PWD)/BUILD/symbols
SRCDIR=$(PWD)


LDFLAGS=-L/usr/local/opt/openssl/lib
CFLAGS=-I/usr/local/opt/openssl/include

$(OUTDIR)/file-crypt: $(SRCDIR)/file-crypt.c | $(OUTDIR) $(SYMDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -g -o $(SYMDIR)/file-crypt -lcrypto $(SRCDIR)/file-crypt.c
	cp $(SYMDIR)/file-crypt $(OUTDIR)/

$(OUTDIR) $(SYMDIR):
	mkdir -p $@

.PHONY: clean

clean:
	rm -fr $(OUTDIR) $(SYMDIR)

test: $(OUTDIR)/file-crypt
	$(echo Doing encrypt)
	$(OUTDIR)/file-crypt ENCRYPT test.c $(SYMDIR)/test.enc
	$(echo Doing decrypt)
	$(OUTDIR)/file-crypt DECRYPT $(SYMDIR)/test.enc $(SYMDIR)/decrypted.c
