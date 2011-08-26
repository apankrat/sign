INSTALL=/usr

all:
	$(MAKE) -C src
	cp src/sign .

install:
	cp src/sign $(INSTALL)/bin/
	cp man/sign.1 $(INSTALL)/man/man1/
	ln -s $(INSTALL)/bin/sign $(INSTALL)/bin/unsign

clean:
	$(MAKE) -C src clean
	rm -f sign

