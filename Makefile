#
# american fuzzy lop - make wrapper
# ---------------------------------
#
# Written and maintained by Michal Zalewski <lcamtuf@google.com>
# 
# Copyright 2013, 2014 Google Inc. All rights reserved.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
# 
#   http://www.apache.org/licenses/LICENSE-2.0
#

PROGNAME    = afl
VERSION     = 0.43b

BIN_PATH    = /usr/local/bin
HELPER_PATH = /usr/local/lib/afl

PROGS       = afl-gcc afl-as afl-fuzz afl-showmap

CFLAGS     += -O3 -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign \
	      -DAFL_PATH=\"$(HELPER_PATH)\" -DVERSION=\"$(VERSION)\"

GCC48PLUS  := $(shell expr `$(CC) -dumpversion | cut -f-2 -d.` \>= 4.8)
CONF_64BIT := $(shell grep -E '^[ 	]*\#define USE_64BIT' config.h)

ifeq "$(GCC48PLUS)" "1"
  CFLAGS   += -DUSE_ASAN=1
endif

ifeq "$(CONF_64BIT)" ""
  CK_TARGET = test_32
  CFLAGS   += -m32
else
  CK_TARGET = test_64
  CFLAGS   += -m64 -Wno-format
endif

COMM_HDR    = alloc-inl.h config.h debug.h types.h

all: test_gcc test_x86 $(CK_TARGET) $(PROGS) all_done

test_gcc:
	@echo "[*] Checking for an installation of GCC..."
	@$(CC) -v >.test 2>&1; grep -q '^gcc version' .test || ( echo; echo "Oops, looks like you don't have GCC installed (or you need to specify \$CC)."; echo; rm -f .test; exit 1 )
	@rm -f .test

test_x86:
	@echo "[*] Checking for the ability to compile x86 code..."
	@echo 'main() { __asm__("xorb %al, %al"); }' | $(CC) -w -x c - -o .test || ( echo; echo "Oops, looks like your compiler can't generate x86 code."; echo; echo "(If you are looking for ARM, see experimental/arm_support/README.)"; echo; exit 1 )
	@rm -f .test

test_32:
	@echo "[*] Checking for 32-bit mode support..."
	@echo 'main() { }' | $(CC) -w -x c - -m32 -o .test || ( echo; echo "Oops, looks like your compiler can't generate 32-bit code!"; echo; echo "You can still build AFL, but you need to edit config.h and uncomment USE_64BIT."; echo; exit 1 )
	@rm -f .test

test_64:
	@echo "[*] Checking for 64-bit mode support..."
	@echo 'main() { }' | $(CC) -w -x c - -m64 -o .test || ( echo; echo "Oops, looks like your compiler can't generate 64-bit code!"; echo; echo "You can still build AFL, but you need to edit config.h and comment out USE_64BIT."; echo; exit 1 )
	@rm -f .test

afl-gcc: afl-gcc.c $(COMM_HDR)
	$(CC) $(CFLAGS) $(LDFLAGS) $@.c -o $@
	ln -s afl-gcc afl-g++ 2>/dev/null || true

afl-as: afl-as.c afl-as.h $(COMM_HDR)
	$(CC) $(CFLAGS) $(LDFLAGS) $@.c -o $@
	ln -s afl-as as  2>/dev/null || true

afl-fuzz: afl-fuzz.c $(COMM_HDR)
	$(CC) $(CFLAGS) $(LDFLAGS) $@.c -o $@

afl-showmap: afl-showmap.c $(COMM_HDR)
	$(CC) $(CFLAGS) $(LDFLAGS) $@.c -o $@

all_done:
	@echo -e "[+] All done! Be sure to review README - it's pretty short and useful."

clean:
	rm -f $(PROGS) as afl-g++ *.o *~ a.out core core.[1-9][0-9]* *.stackdump test .test
	rm -rf out_dir

install: all
	install afl-gcc afl-g++ afl-fuzz afl-showmap $(BIN_PATH)
	mkdir -p -m 755 $(HELPER_PATH) 2>/dev/null
	install afl-as as $(HELPER_PATH)

publish: clean
	test "`basename $$PWD`" = "afl" || exit 1
	cd ..; rm -rf $(PROGNAME)-$(VERSION); cp -pr $(PROGNAME) $(PROGNAME)-$(VERSION); \
	  tar cfvz ~/www/$(PROGNAME).tgz $(PROGNAME)-$(VERSION)
	chmod 644 ~/www/$(PROGNAME).tgz

