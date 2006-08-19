PACKAGE_NAME=Cache-Static
TARBALL_DEST=../
TARBALL_NAME=$(PACKAGE_NAME).tgz

all: rebuild

rebuild:
	-make distclean
	perl <Makefile.PL
	make

install: rebuild
	sudo make install

clean:
	-make distclean #if there is a Makefile...
	find . -name \*~ -exec rm -f '{}' \;
	rm -f scache/mod_so/functions
	rm -f scache/mod_so/*.o
	rm -f scache/mod_so/*.so
	rm -f Makefile.old
	rm -rf blib

tarball: tar
tgz: tar

tar: clean
	cd $(TARBALL_DEST) && \
	rm -f $(TARBALL_NAME) && \
	tar cvz --exclude='.svn' -f ${TARBALL_NAME} $(PACKAGE_NAME)
