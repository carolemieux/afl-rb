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
VERSION     = 0.39b

BIN_PATH    = /usr/local/bin
HELPER_PATH = /usr/local/lib/afl

PROGS       = afl-gcc afl-as afl-fuzz afl-showmap

# On some embedded platforms (e.g., hosted GCC on Intel Edison), stack
# protector may not be supported; remove the option if compilation fails.

CFLAGS     += -O3 -Wall -fstack-protector-all -m32 \
	      -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign \
	      -DAFL_PATH=\"$(HELPER_PATH)\" \
	      -DVERSION=\"$(VERSION)\"

GCC48PLUS  := $(shell expr `gcc -dumpversion | cut -f-2 -d.` \>= 4.8)

ifeq "$(GCC48PLUS)" "1"
  CFLAGS   += -DUSE_ASAN=1
endif

COMM_HDR    = alloc-inl.h config.h debug.h types.h

all: $(PROGS)

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

clean:
	rm -f $(PROGS) as afl-g++ *.o *~ a.out core core.[1-9][0-9]* *.stackdump test
	rm -rf out_dir

install: all
	install afl-gcc afl-g++ afl-fuzz afl-showmap $(BIN_PATH)
	mkdir -m 755 $(HELPER_PATH) 2>/dev/null || continue
	install afl-as as $(HELPER_PATH)

publish: clean
	test "`basename $$PWD`" = "afl" || exit 1
	cd ..; rm -rf $(PROGNAME)-$(VERSION); cp -pr $(PROGNAME) $(PROGNAME)-$(VERSION); \
	  tar cfvz ~/www/$(PROGNAME).tgz $(PROGNAME)-$(VERSION)
	chmod 644 ~/www/$(PROGNAME).tgz

