# Copyright (c) The slhdsa-c project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT

.PHONY: test

CSRC	=	$(wildcard *.c)
OBJS	= 	$(CSRC:.c=.o)

XTEST	?=	xfips205
XTESTC	?=	test/xfips205.c

CC      ?= gcc
CFLAGS  :=	-Wall \
		-Wextra \
		-Werror=unused-result \
		-Wpedantic \
		-Werror \
		-Wmissing-prototypes \
		-Wshadow \
		-Wpointer-arith \
		-Wredundant-decls \
		-Wno-long-long \
		-Wno-unknown-pragmas \
		-O3 \
		-fomit-frame-pointer \
		-std=c99 \
		-pedantic \
		$(CFLAGS)

LDLIBS	+=

$(XTEST):	$(OBJS)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(OBJS) $(XTESTC) $(LDLIBS)

%.o:	%.[cS]
	$(CC) $(CFLAGS) -c $^ -o $@

test: $(XTEST)
	python3 test/acvp_client.py

clean:
	$(RM) -rf $(XTEST) $(OBJS) *.rsp *.req *.log
	cd test && $(MAKE) clean
